use alloy::{
    network::{EthereumWallet, Network, ReceiptResponse},
    primitives::{Address, B256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
    transports::Transport,
};
use anyhow::{Context, Result};
use sp1_blobstream_primitives::get_header_update_verdict;
use sp1_blobstream_script::util::{
    fetch_input_for_blobstream_proof, find_block_to_request, get_latest_block_height,
};
use sp1_blobstream_script::TendermintRPCClient;
use sp1_blobstream_script::{relay, TENDERMINT_ELF};
use sp1_sdk::{
    network::FulfillmentStrategy, HashableKey, NetworkProver, Prover, ProverClient,
    SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};
use std::{collections::HashMap, env, sync::Arc};
use std::{marker::PhantomData, time::Duration};
use tendermint_light_client_verifier::Verdict;
use tracing::{error, info, Instrument};
use tracing_subscriber::EnvFilter;

use sp1_blobstream_script::util::signer::MaybeWallet;

use futures::{stream::FuturesUnordered, StreamExt};

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

use SP1Blobstream::SP1BlobstreamInstance as SP1BlobstreamContract;

// Timeout for the proof in seconds.
const PROOF_TIMEOUT_SECONDS: u64 = 60 * 30;

/// The number of times to retry the relay.
const NUM_RELAY_RETRIES: u32 = 3;

/// The timeout for the operator to run.
const LOOP_TIMEOUT_MINS: u64 = 20;

struct SP1BlobstreamOperator<P, T, N> {
    pk: Arc<SP1ProvingKey>,
    vk: SP1VerifyingKey,
    contracts: HashMap<u64, SP1BlobstreamContract<T, P, N>>,
    network_prover: NetworkProver,

    use_kms_relayer: bool,
    _phantom: PhantomData<(T, N)>,
}

impl<P, T, N> SP1BlobstreamOperator<P, T, N>
where
    P: Provider<T, N> + 'static,
    T: Transport + Clone,
    N: Network,
{
    pub fn new(pk: SP1ProvingKey, vk: SP1VerifyingKey, use_kms_relayer: bool) -> Self {
        Self {
            pk: Arc::new(pk),
            vk,
            contracts: HashMap::new(),
            network_prover: ProverClient::builder().network().build(),
            use_kms_relayer,
            _phantom: PhantomData,
        }
    }

    /// Add a chain to the operator.
    ///
    /// # Panics
    /// - If the chain id cannot be retrieved from the provider.
    pub async fn with_chain(mut self, provider: P, address: Address) -> Self {
        let chain_id = provider
            .get_chain_id()
            .await
            .expect("Failed to get chain id");

        let contract = SP1Blobstream::new(address, provider);

        self.contracts.insert(chain_id, contract);
        self
    }

    /// Check the verifying key in the contract matches the verifying key in the prover.
    async fn check_vkey(&self, chain_id: u64) -> Result<()> {
        let contract = self.contracts.get(&chain_id).unwrap();
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

    async fn create_proof(
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

        self.network_prover
            .prove(&self.pk, &stdin)
            .strategy(FulfillmentStrategy::Reserved)
            .skip_simulation(true)
            .plonk()
            .timeout(Duration::from_secs(PROOF_TIMEOUT_SECONDS))
            .run()
    }

    /// Relay a header range proof to the SP1 Blobstream contract.
    ///
    /// # Errors
    /// - If any errors occur while relaying the proof.
    async fn relay_header_range(
        &self,
        proof: &SP1ProofWithPublicValues,
        chain_id: u64,
    ) -> Result<B256> {
        let contract = self.contracts.get(&chain_id).unwrap();

        if self.use_kms_relayer {
            let proof_bytes = proof.bytes().into();
            let public_values = proof.public_values.to_vec().into();
            let commit_header_range = contract.commitHeaderRange(proof_bytes, public_values);

            relay::relay_with_kms(
                &relay::KMSRelayRequest {
                    chain_id,
                    address: contract.address().to_checksum(None),
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

    /// Compute a proof of the light client protocol,
    /// updating from `current_block` to `next_block` for the given chains.
    ///
    /// Note: Assumes that the `current_block` is valid for each chain.
    ///
    /// # Errors
    /// - If any errors occur while checking the vkey.
    /// - If any errors occur while creating the proof.
    /// - If any errors occur while relaying the proof.
    async fn compute_batch_proof(
        self: Arc<Self>,
        client: &TendermintRPCClient,
        chains: &[u64],
        current_block: u64,
        next_block: u64,
    ) -> Result<()> {
        // Check the vkey is correct for each chain just in case.
        futures::future::try_join_all(chains.iter().map(|chain_id| self.check_vkey(*chain_id)))
            .await?;

        // If block_to_request is greater than the current block in the contract, attempt to request.
        if next_block > current_block {
            // The next block the operator should request.
            let max_end_block = next_block;

            let target_block = find_block_to_request(client, current_block, max_end_block).await?;

            info!("Current block: {}", current_block);
            info!("Attempting to step to block {}", target_block);

            let proof = self
                .create_proof(current_block, target_block)
                .await
                .context(format!(
                    "Failed to create proof for block {} to block {}",
                    current_block, target_block
                ))?;

            // Put the proof in an Arc to avoid cloning it for each chain.
            let proof = Arc::new(proof);

            // Relay to all the chains concurrently.
            let handles = chains.iter().copied().map(|id| {
                let proof = proof.clone();
                let this = self.clone();

                async move {
                    match this.relay_header_range(&proof, id).await {
                        Ok(tx_hash) => {
                            info!(
                                "Posted data commitment from block {} to block {}",
                                current_block, target_block
                            );
                            info!("Transaction hash: {}", tx_hash);
                            Ok(())
                        }
                        Err(e) => {
                            error!("Relaying proof failed: {}", e);

                            Err(e.context(format!(
                                "Failed to relay proof for block {} to block {}",
                                current_block, target_block
                            )))
                        }
                    }
                }
            });

            // We dont want `try_join_all` because we dont want to early exit on any error.
            let results = futures::future::join_all(handles).await;

            // Print any errors that occurred, and return a placeholder error to indicate an error occurred.
            if results
                .iter()
                .filter(|res| res.is_err())
                .inspect(|res| {
                    tracing::error!("Error relaying: {:?}", res);
                })
                .count()
                > 0
            {
                // Return an empty error, any errors wouldve been logged already.
                return Err(anyhow::anyhow!(""));
            }
        } else {
            info!("Next block to request is {} which is > the head of the Tendermint chain which is {}. Sleeping.", next_block, current_block);
        }

        Ok(())
    }

    /// Run the operator logic for the given chains.
    ///
    /// Internally this function will:
    /// - Get the data commitment max for each chain.
    /// - Get the latest block for each chain.
    /// - Find all the chains that have the same last known block.
    /// - For each last known block,
    ///   - Spawn a task to compute only one proof and relay the proof to all chains that have the same last known block.
    ///
    /// # Errors
    /// - If any errors occur while making the batch proof.
    async fn run_inner(self: Arc<Self>) -> Result<()> {
        let client = TendermintRPCClient::default();
        let block_update_interval = get_block_update_interval();

        // Note: Early exits on any error.
        let max_commits =
            futures::future::try_join_all(self.contracts.iter().map(|(id, contract)| async move {
                match contract.DATA_COMMITMENT_MAX().call().await {
                    Ok(data_commitment_max) => {
                        anyhow::Result::Ok(data_commitment_max.DATA_COMMITMENT_MAX)
                    }
                    Err(e) => {
                        error!("Failed to get data commitment max for chain {}: {}", id, e);
                        anyhow::Result::Err(e)
                    }
                }
            }))
            .await?;

        // All the chains should have the same data commitment max.
        assert!(max_commits.iter().all(|&max| max == max_commits[0]));
        let data_commitment_max = max_commits[0];

        // We want to find all the chains that have the same last knwon block.
        let mut blocks_to_chain_id: HashMap<u64, Vec<u64>> = HashMap::new();

        // Get the latest blocks from all the contracts.
        // Note: Early exits on any error.
        let latest_blocks =
            futures::future::try_join_all(self.contracts.iter().map(|(id, contract)| async move {
                match contract.latestBlock().call().await {
                    Ok(latest_block) => anyhow::Result::Ok((id, latest_block.latestBlock)),
                    Err(e) => {
                        error!("Failed to get latest block for chain {}: {}", id, e);
                        anyhow::Result::Err(e)
                    }
                }
            }))
            .await?;

        for (id, block) in latest_blocks {
            blocks_to_chain_id.entry(block).or_default().push(*id);
        }

        // Get the head of the chain.
        let latest_tendermint_block_nb = get_latest_block_height(&client).await?;
        tracing::debug!("Latest tendermint block: {}", latest_tendermint_block_nb);

        // Subtract 1 block to ensure the block is stable.
        let latest_stable_tendermint_block = latest_tendermint_block_nb - 1;

        let mut handles = Vec::new();
        for (last_known_block, ids) in blocks_to_chain_id {
            // block_to_request is the closest interval of block_interval less than min(latest_stable_tendermint_block, data_commitment_max + current_block)
            let max_block = std::cmp::min(
                latest_stable_tendermint_block,
                data_commitment_max + last_known_block,
            );

            let block_to_request = max_block - (max_block % block_update_interval);

            let id_display_str = ids
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<String>>()
                .join(", ");

            // Spawn a task for each starting block, so we compute any proofs concurrently.
            handles.push(tokio::spawn({
                let this = self.clone();
                let client = client.clone();

                async move {
                    let this = this.clone();
                    this.compute_batch_proof(&client, &ids, last_known_block, block_to_request)
                        .await
                }
                .instrument(tracing::span!(
                    tracing::Level::INFO,
                    "compute_batch_proof",
                    chains = id_display_str
                ))
            }));
        }

        let results = futures::future::join_all(handles).await;
        if results
            .iter()
            .filter(|res| res.is_err())
            .inspect(|res| {
                tracing::error!("Error running operator: {:?}", res);
            })
            .count()
            > 0
        {
            // Return an empty error, any errors wouldve been logged already.
            return Err(anyhow::anyhow!(""));
        }

        Ok(())
    }

    /// Run the operator, indefinitely.
    async fn run(self) {
        let this = Arc::new(self);

        loop {
            let request_interval_mins = get_loop_interval_mins();

            tokio::select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(60 * LOOP_TIMEOUT_MINS)) => {
                    tracing::error!("Operator took longer than {} minutes to run.", LOOP_TIMEOUT_MINS);
                    continue;
                }
                res = this.clone().run_inner().instrument(tracing::span!(tracing::Level::INFO, "operator")) => {
                    if let Err(e) = res {
                        tracing::error!("Error running operator: {:?}", e);

                        // Sleep for less time on errors.
                        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                        continue;
                    }
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(60 * request_interval_mins)).await;
        }
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

    let mut operator = SP1BlobstreamOperator::new(pk, vk, use_kms_relayer);

    for c in config {
        let provider = ProviderBuilder::new()
            .wallet(signer.clone())
            .on_http(c.rpc_url.parse().expect("Failed to parse RPC URL"));

        operator = operator.with_chain(provider, c.blobstream_address).await;
    }

    operator.run().await;
}
