use alloy::{
    network::{EthereumWallet, Network, ReceiptResponse},
    primitives::{Address, B256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
    transports::Transport,
};
use anyhow::Result;
use sp1_blobstream_primitives::get_header_update_verdict;
use sp1_blobstream_script::util::{
    fetch_input_for_blobstream_proof, find_block_to_request, get_latest_block_height,
};
use sp1_blobstream_script::TendermintRPCClient;
use sp1_blobstream_script::{relay, TENDERMINT_ELF};
use sp1_sdk::{
    network::FulfillmentStrategy, HashableKey, Prover, ProverClient, SP1ProofWithPublicValues,
    SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};
use std::{env, sync::Arc};
use std::{marker::PhantomData, time::Duration};
use tendermint_light_client_verifier::Verdict;
use tracing::{error, info, Instrument};
use tracing_subscriber::EnvFilter;

use sp1_blobstream_script::util::signer::MaybeWallet;

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract SP1Blobstream {
        bool public frozen;
        uint64 public latestBlock;
        uint256 public state_proofNonce;
        mapping(uint64 => bytes32) public blockHeightToHeaderHash;
        mapping(uint256 => bytes32) public state_dataCommitments;
        uint64 public constant DATA_COMMITMENT_MAX = 10000;
        bytes32 public blobstreamProgramVkey;
        address public verifier;

        function commitHeaderRange(bytes calldata proof, bytes calldata publicValues) external;
    }
}

struct SP1BlobstreamOperator<P, T, N> {
    pk: Arc<SP1ProvingKey>,
    vk: SP1VerifyingKey,
    contract_address: Address,
    provider: P,
    chain_id: u64,
    use_kms_relayer: bool,
    _phantom: PhantomData<(T, N)>,
}

// Timeout for the proof in seconds.
const PROOF_TIMEOUT_SECONDS: u64 = 60 * 30;

/// The number of times to retry the relay.
const NUM_RELAY_RETRIES: u32 = 3;

/// The timeout for the operator to run.
const LOOP_TIMEOUT_MINS: u64 = 20;

impl<P: Provider<T, N>, T: Transport + Clone, N: Network> SP1BlobstreamOperator<P, T, N> {
    /// Create a new SP1BlobstreamOperator.
    ///
    /// If `use_kms_relayer` is true, the operator will use the KMS relayer to relay the transaction.
    /// Otherwise, it will try to use `Provider`
    ///
    /// # Panics
    /// - If the chain id cannot be retrieved from the provider.
    pub async fn new(
        provider: P,
        contract_address: Address,
        pk: Arc<SP1ProvingKey>,
        vk: SP1VerifyingKey,
        use_kms_relayer: bool,
    ) -> Self {
        let chain_id = provider
            .get_chain_id()
            .await
            .expect("Failed to get chain id");

        Self {
            pk,
            vk,
            contract_address,
            provider,
            chain_id,
            use_kms_relayer,
            _phantom: PhantomData,
        }
    }

    /// Check the verifying key in the contract matches the verifying key in the prover.
    async fn check_vkey(&self) -> Result<()> {
        let contract = SP1Blobstream::new(self.contract_address, &self.provider);
        let verifying_key = contract
            .blobstreamProgramVkey()
            .call()
            .await?
            .blobstreamProgramVkey;

        if verifying_key.0.to_vec()
            != hex::decode(self.vk.bytes32().strip_prefix("0x").unwrap()).unwrap()
        {
            return Err(anyhow::anyhow!(
                    "The verifying key in the operator does not match the verifying key in the contract!"
                ));
        }

        Ok(())
    }

    async fn request_header_range(
        &self,
        trusted_block: u64,
        target_block: u64,
    ) -> Result<SP1ProofWithPublicValues> {
        let rpc_client = TendermintRPCClient::default();
        let mut stdin = SP1Stdin::new();

        info!("Fetching inputs for proof.");
        let inputs =
            fetch_input_for_blobstream_proof(&rpc_client, trusted_block, target_block).await?;
        info!("Inputs fetched for proof.");

        // Simulate the step from the trusted block to the target block.
        let verdict =
            get_header_update_verdict(&inputs.trusted_light_block, &inputs.target_light_block);
        assert_eq!(verdict, Verdict::Success);

        let encoded_proof_inputs = serde_cbor::to_vec(&inputs)?;
        stdin.write_vec(encoded_proof_inputs);

        // If the SP1_PROVER environment variable is set to "cpu", use the CPU prover.
        if let Ok(prover_type) = env::var("SP1_PROVER") {
            if prover_type == "cpu" {
                let prover_client = ProverClient::builder().cpu().build();
                let proof = prover_client.prove(&self.pk, &stdin).plonk().run()?;
                return Ok(proof);
            }
        }

        let prover_client = ProverClient::builder().network().build();
        prover_client
            .prove(&self.pk, &stdin)
            .strategy(FulfillmentStrategy::Reserved)
            .skip_simulation(true)
            .plonk()
            .timeout(Duration::from_secs(PROOF_TIMEOUT_SECONDS))
            .run()
    }

    /// Relay a header range proof to the SP1 Blobstream contract.
    async fn relay_header_range(&self, proof: SP1ProofWithPublicValues) -> Result<B256> {
        if self.use_kms_relayer {
            let proof_bytes = proof.bytes().into();
            let public_values = proof.public_values.to_vec().into();
            let contract = SP1Blobstream::new(self.contract_address, &self.provider);
            let commit_header_range = contract.commitHeaderRange(proof_bytes, public_values);

            relay::relay_with_kms(
                &relay::KMSRelayRequest {
                    chain_id: self.chain_id,
                    address: self.contract_address.to_checksum(None),
                    calldata: commit_header_range.calldata().to_string(),
                    platform_request: false,
                },
                NUM_RELAY_RETRIES,
            )
            .await
        } else {
            let public_values_bytes = proof.public_values.to_vec();

            // Wait for 3 required confirmations with a timeout of 60 seconds.
            const NUM_CONFIRMATIONS: u64 = 3;
            const TIMEOUT_SECONDS: u64 = 60;

            let contract = SP1Blobstream::new(self.contract_address, &self.provider);
            let receipt = contract
                .commitHeaderRange(proof.bytes().into(), public_values_bytes.into())
                .send()
                .await?
                .with_required_confirmations(NUM_CONFIRMATIONS)
                .with_timeout(Some(Duration::from_secs(TIMEOUT_SECONDS)))
                .get_receipt()
                .await?;

            // If status is false, it reverted.
            if !receipt.status() {
                error!("Transaction reverted!");
            }

            Ok(receipt.transaction_hash())
        }
    }

    async fn run(&self) -> Result<()> {
        self.check_vkey().await?;
        tracing::info!("Vkey check passed");

        let client = TendermintRPCClient::default();
        let block_update_interval = get_block_update_interval();
        let contract = SP1Blobstream::new(self.contract_address, &self.provider);

        // Read the data commitment max from the contract.
        let data_commitment_max = contract
            .DATA_COMMITMENT_MAX()
            .call()
            .await?
            .DATA_COMMITMENT_MAX;
        tracing::debug!("Data commitment max: {}", data_commitment_max);

        // Get the latest block from the contract.
        let current_block = contract.latestBlock().call().await?.latestBlock;
        tracing::debug!("Current block: {}", current_block);

        // Get the head of the chain.
        let latest_tendermint_block_nb = get_latest_block_height(&client).await?;
        tracing::debug!("Latest tendermint block: {}", latest_tendermint_block_nb);

        // Subtract 1 block to ensure the block is stable.
        let latest_stable_tendermint_block = latest_tendermint_block_nb - 1;

        // block_to_request is the closest interval of block_interval less than min(latest_stable_tendermint_block, data_commitment_max + current_block)
        let max_block = std::cmp::min(
            latest_stable_tendermint_block,
            data_commitment_max + current_block,
        );
        let block_to_request = max_block - (max_block % block_update_interval);

        // If block_to_request is greater than the current block in the contract, attempt to request.
        if block_to_request > current_block {
            // The next block the operator should request.
            let max_end_block = block_to_request;

            let target_block = find_block_to_request(&client, current_block, max_end_block).await?;

            info!("Current block: {}", current_block);
            info!("Attempting to step to block {}", target_block);

            // Request a header range if the target block is not the next block.
            match self.request_header_range(current_block, target_block).await {
                Ok(proof) => {
                    let tx_hash = self.relay_header_range(proof).await?;
                    info!(
                        "Posted data commitment from block {} to block {}",
                        current_block, target_block
                    );
                    info!("Transaction hash: {}", tx_hash);
                }
                Err(e) => {
                    error!("Header range request failed: {}", e);
                    return Err(e);
                }
            };
        } else {
            info!("Next block to request is {} which is > the head of the Tendermint chain which is {}. Sleeping.", block_to_request + block_update_interval, latest_stable_tendermint_block);
        }
        Ok(())
    }
}

fn get_loop_interval_mins() -> u64 {
    let loop_interval_mins_env = env::var("LOOP_INTERVAL_MINS");
    let mut loop_interval_mins = 60;
    if loop_interval_mins_env.is_ok() {
        loop_interval_mins = loop_interval_mins_env
            .unwrap()
            .parse::<u64>()
            .expect("invalid LOOP_INTERVAL_MINS");
    }
    loop_interval_mins
}

fn get_block_update_interval() -> u64 {
    env::var("BLOCK_UPDATE_INTERVAL")
        .map(|i| i.parse().expect("Couldnt parse BLOCK_UPDATE_INTERVAL"))
        .unwrap_or(360)
}

#[derive(Debug, serde::Deserialize)]
struct ChainConfig {
    name: String,
    rpc_url: String,
    blobstream_address: Address,
}

impl ChainConfig {
    /// Tries to read from the `CHAINS_PATH` environment variable, then the default path (`../chains.json`).
    ///
    /// If neither are set, it will try to use [`Self::from_env`].
    fn fetch() -> Result<Vec<Self>> {
        const DEFAULT_PATH: &str = "chains.json";

        let path = env::var("CHAINS_PATH").unwrap_or(DEFAULT_PATH.to_string());

        Self::from_file(&path).or_else(|_| {
            tracing::info!("No chains file found, trying env.");
            Self::from_env()
        })
    }

    /// Tries to read from the `CHAINS` environment variable.
    fn from_env() -> Result<Vec<Self>> {
        let chains = env::var("CHAINS")?;

        Ok(serde_json::from_str(&chains)?)
    }

    fn from_file(path: &str) -> Result<Vec<Self>> {
        tracing::debug!("Reading chains from file: {}", path);

        let file = std::fs::read_to_string(path)?;

        Ok(serde_json::from_str(&file)?)
    }
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    // Setup tracing.
    tracing_subscriber::fmt::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Succinct deployments use the `CHAINS` environment variable.
    let config = ChainConfig::fetch().expect("Failed to fetch chain config");
    let maybe_private_key: Option<PrivateKeySigner> = env::var("PRIVATE_KEY")
        .ok()
        .map(|s| s.parse().expect("Failed to parse PRIVATE_KEY"));

    // Setup the KMS relayer config.
    let use_kms_relayer: bool = env::var("USE_KMS_RELAYER")
        .map(|s| s.parse().expect("USE_KMS_RELAYER failed to parse"))
        .expect("USE_KMS_RELAYER not set");

    // Ensure we have a signer if we're not using the KMS relayer.
    if !use_kms_relayer && maybe_private_key.is_none() {
        panic!("PRIVATE_KEY is not set but USE_KMS_RELAYER is false.");
    }

    // Setup our signer.
    let signer = MaybeWallet::new(maybe_private_key.map(EthereumWallet::new));

    // Setup the prover and program keys.
    let prover = ProverClient::builder().cpu().build();
    let (pk, vk) = prover.setup(TENDERMINT_ELF);
    let pk = Arc::new(pk);

    // Setup all the tasks.
    // These futures should never resolve, so we just await them in the main thread.
    let handles = config.into_iter().map(
        |c| {
            let provider = ProviderBuilder::new()
                .wallet(signer.clone())
                .on_http(c.rpc_url.parse().expect("Failed to parse RPC URL"));

            let pk = pk.clone();
            let vk = vk.clone();

            tokio::task::spawn(async move {
                tracing::info!("Starting operator for chain {}", c.name);

                let operator = SP1BlobstreamOperator::new(
                    provider,
                    c.blobstream_address,
                    pk,
                    vk,
                    use_kms_relayer,
                )
                .await;

                loop {
                    let request_interval_mins = get_loop_interval_mins();

                    tokio::select! {
                        _ = tokio::time::sleep(tokio::time::Duration::from_secs(60 * LOOP_TIMEOUT_MINS)) => {
                            tracing::error!("Operator took longer than {} minutes to run.", LOOP_TIMEOUT_MINS);
                            continue;
                        }
                        e = operator.run().instrument(tracing::span!(tracing::Level::INFO, "operator", chain = c.name)) => {
                            if let Err(e) = e {
                                // Sleep for less time on errors.
                                error!("Error running operator: {:?}", e);

                                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                                continue;
                            }
                        }
                    }

                    tokio::time::sleep(tokio::time::Duration::from_secs(60 * request_interval_mins)).await;
                }
            })
    });

    // Run all the tasks.
    futures::future::try_join_all(handles).await.unwrap();

    info!("All operators finished.");
}
