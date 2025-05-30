use alloy::{
    network::{Network, ReceiptResponse},
    primitives::{Address, B256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use anyhow::{Context, Result};
use reqwest::Url;
use sp1_blobstream_primitives::get_header_update_verdict;
use sp1_blobstream_script::util::{fetch_input_for_blobstream_proof, find_block_to_request};
use sp1_blobstream_script::TendermintRPCClient;
use sp1_blobstream_script::{relay, TENDERMINT_ELF};
use sp1_sdk::{
    network::FulfillmentStrategy, HashableKey, NetworkProver, Prover, ProverClient,
    SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};
use std::time::Duration;
use std::{collections::HashMap, env, sync::Arc};
use tendermint_light_client_verifier::Verdict;
use tracing::{error, info, Instrument};
use tracing_subscriber::EnvFilter;

/////// Contract ///////

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

/////// Constants ///////

// Timeout for the proof in seconds.
const PROOF_TIMEOUT_SECONDS: u64 = 60 * 30;

/// The number of times to retry the relay.
const NUM_RELAY_RETRIES: u32 = 3;

/// The timeout for the operator to run.
const LOOP_TIMEOUT_MINS: u64 = PROOF_TIMEOUT_SECONDS * 2;

/// The number of confirmations to wait for.
const NUM_CONFIRMATIONS: u64 = 3;

/// The timeout for the transaction in seconds.
const TRANSACTION_TIMEOUT_SECONDS: u64 = 60;

/////// Signer Mode ///////

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignerMode {
    Kms,
    Local,
}

impl std::str::FromStr for SignerMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "kms" => Self::Kms,
            "local" => Self::Local,
            _ => return Err(anyhow::anyhow!("Invalid signer mode: {}", s)),
        })
    }
}

/////// Operator ///////

struct SP1BlobstreamOperator<P, N> {
    pk: Arc<SP1ProvingKey>,
    vk: SP1VerifyingKey,
    client: TendermintRPCClient,
    contracts: HashMap<u64, SP1BlobstreamContract<P, N>>,
    network_prover: Arc<NetworkProver>,
    signer_mode: SignerMode,
}

/////// Constructor ///////

impl<P, N> SP1BlobstreamOperator<P, N>
where
    P: Provider<N> + 'static,
    N: Network,
{
    /// Create a new SP1 Blobstream operator.
    ///
    /// - `pk`: the SP1 Proving key of the blobstream program.
    /// - `vk`: the SP1 Verifying key of the blobstream program.
    /// - `use_kms_relayer`: whether to use the KMS relayer to relay the proof.
    pub fn new(
        pk: SP1ProvingKey,
        vk: SP1VerifyingKey,
        client: TendermintRPCClient,
        signer_mode: SignerMode,
        network_prover: Arc<NetworkProver>,
    ) -> Self {
        Self {
            pk: Arc::new(pk),
            vk,
            client,
            contracts: HashMap::new(),
            network_prover,
            signer_mode,
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
}

/////// Control Flow ///////

impl<P, N> SP1BlobstreamOperator<P, N>
where
    P: Provider<N> + 'static,
    N: Network,
{
    /// Create and relay a block range proof to multiple chains.
    /// Creates a single proof for the block range from current_block to target_block,
    /// then relays that proof to all the specified chains concurrently.
    ///
    /// # Returns
    /// A vector of results, one for each chain indicating success or a transaction error.
    ///
    /// # Errors
    /// - If creating the block range proof fails.
    /// - If relaying the proof to any chain fails.
    async fn create_and_relay_proof(
        &self,
        chains: Vec<u64>,
        current_block: u64,
        target_block: u64,
    ) -> Result<Vec<Result<()>>> {
        debug_assert!(
            target_block > current_block,
            "Target block must be greater than current block"
        );

        info!("Current block: {}", current_block);
        info!("Attempting to step to block {}", target_block);

        let proof = self
            .create_proof(current_block, target_block)
            .await
            .context(format!(
                "Failed to create proof for block {} to block {}",
                current_block, target_block
            ))?;

        // Relay to all the chains concurrently.
        let handles = chains.into_iter().map(|id| {
            let proof = &proof;

            async move {
                match self.relay_header_range(proof, id).await {
                    Ok(tx_hash) => {
                        info!(
                            "Posted data commitment from block {} to block {}",
                            current_block, target_block
                        );
                        info!("Transaction hash for chain {}: {}", id, tx_hash);
                        Ok(())
                    }
                    Err(e) => {
                        error!("Relaying proof failed to chain {}: {}", id, e);

                        Err(e.context(format!(
                            "Failed to relay proof for block {} to block {}",
                            current_block, target_block
                        )))
                    }
                }
            }
            .instrument(tracing::span!(
                tracing::Level::INFO,
                "relay_header_range",
                chain_id = id
            ))
        });

        Ok(futures::future::join_all(handles).await)
    }

    /// Run the operator logic for the given chains.
    ///
    /// Internally this function will:
    /// - Get the data commitment max for each chain.
    /// - Get the latest block for each chain.
    /// - Find all the chains that have the same last known block.
    /// - For each last known block,
    ///   - Find the block to request based on the last known block and the block update interval.
    ///   - Spawn a task to compute only one proof and relay the proof to all chains that have the same last known block.
    ///
    /// # Errors
    /// - If any errors occur while making the batch proof.
    async fn run_operator_iteration(self: Arc<Self>) -> Result<()> {
        tracing::info!("Running operator iteration");

        let data_commitment_max = self.validate_contracts().await?;

        // How often new tendermint blocks are created.
        let block_update_interval = get_block_update_interval();

        // Store a mapping of all the chains that share the same last known block.
        let mut blocks_to_chain_id: HashMap<u64, Vec<u64>> = HashMap::new();

        // Get the latest blocks from all the contracts.
        //
        // Note: Early exits on any error.
        let latest_blocks =
            futures::future::try_join_all(self.contracts.iter().map(|(id, contract)| async move {
                match contract.latestBlock().call().await {
                    Ok(latest_block) => anyhow::Result::Ok((id, latest_block)),
                    Err(e) => {
                        error!("Failed to get latest block for chain {}: {}", id, e);
                        anyhow::Result::Err(e)
                    }
                }
            }))
            .await?;

        // Group the chains by the last known block.
        latest_blocks.into_iter().for_each(|(id, block)| {
            blocks_to_chain_id.entry(block).or_default().push(*id);
        });

        let mut handles = Vec::new();
        for (last_known_block, ids) in blocks_to_chain_id {
            // If the consensus threshold is not met, the first block to match the threshold
            // will be used as the block to request.
            let block_to_request = find_block_to_request(
                &self.client,
                last_known_block,
                block_update_interval,
                data_commitment_max,
            )
            .await?;

            if let Some(block_to_request) = block_to_request {
                // To display in the instrumented span.
                let id_display_str = ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<String>>()
                    .join(", ");

                // Spawn a task for each starting block, to compute the proofs concurrently.
                let fut = tokio::spawn({
                    let operator_clone = self.clone();
                    async move {
                        operator_clone
                            .create_and_relay_proof(ids, last_known_block, block_to_request)
                            .await
                    }
                    .instrument(tracing::span!(
                        tracing::Level::INFO,
                        "compute_batch_proof",
                        chains = id_display_str
                    ))
                });

                handles.push(fut);
            } else {
                tracing::info!(
                    "Next block to request is <= the last known block of {}. Sleeping.",
                    last_known_block
                );
                continue;
            }
        }

        // Individually check each task for errors.
        let results = futures::future::join_all(handles).await;

        // Errors either occur when creating proofs or when relaying proofs.
        //
        // In either case, return an error. In `run`, the operator will not "sleep" for the loop
        // interval if there was an error and will retry invoking `run_operator_iteration`
        // immediately.
        let mut has_err = false;
        for batch_result in results {
            match batch_result {
                Ok(Ok(relay_results)) => {
                    for relay_result in relay_results {
                        if let Err(e) = relay_result {
                            tracing::error!("Error relaying proof: {:?}", e);
                            has_err = true;
                        }
                    }
                }
                Ok(Err(e)) => {
                    tracing::error!("Error running batch: {:?}", e);
                    has_err = true;
                }
                Err(e) => {
                    tracing::error!("Join error: {:?}", e);
                    has_err = true;
                }
            }
        }

        if has_err {
            // Any errors would have been logged already.
            //
            // Return an indicator to retry sooner.
            return Err(anyhow::anyhow!(""));
        }

        Ok(())
    }

    /// Run the operator, indefinitely.
    async fn run(self) {
        let this = Arc::new(self);

        tracing::info!("Operator running with chains {:?}", this.contracts.keys());

        loop {
            let request_interval_mins = get_loop_interval_mins();

            // Use timeout instead of select for cleaner timeout handling
            match tokio::time::timeout(
                tokio::time::Duration::from_secs(LOOP_TIMEOUT_MINS),
                this.clone()
                    .run_operator_iteration()
                    .instrument(tracing::span!(tracing::Level::INFO, "operator")),
            )
            .await
            {
                Ok(Ok(())) => {
                    tracing::info!("Successfully ran operator iteration.");
                    // Sleep for the request interval
                    tokio::time::sleep(tokio::time::Duration::from_secs(
                        60 * request_interval_mins,
                    ))
                    .await;
                }
                Ok(Err(e)) => {
                    tracing::error!("Error running operator iteration: {:?}", e);
                    // If there's an error, sleep for only 10 seconds
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                }
                Err(_) => {
                    tracing::error!(
                        "Operator iteration took longer than {} minutes to run.",
                        LOOP_TIMEOUT_MINS
                    );
                    // Sleep for a short time before retrying
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                }
            }
        }
    }
}

///// Methods ///////

impl<P, N> SP1BlobstreamOperator<P, N>
where
    P: Provider<N> + 'static,
    N: Network,
{
    /// Check the verifying key in the contract matches the verifying key in the prover.
    ///
    /// # Errors
    /// - If the verifying key in the operator does not match the verifying key in the contract.
    async fn check_vkey(&self, chain_id: u64) -> Result<()> {
        let contract = self.contracts.get(&chain_id).unwrap();
        let verifying_key = contract.blobstreamProgramVkey().call().await?;

        if verifying_key.to_vec()
            != hex::decode(self.vk.bytes32().strip_prefix("0x").unwrap()).unwrap()
        {
            return Err(anyhow::anyhow!(
                    "The verifying key in the operator does not match the verifying key in the contract!"
                ));
        }

        Ok(())
    }

    /// Check the operator has the same data commitment max and verifying key for all chains.
    ///
    /// # Returns
    /// The data commitment max for all chains.
    async fn validate_contracts(&self) -> Result<u64> {
        // Check the verification key is correct for each chain
        // to ensure that the operator's program key matches the one the contract expects.
        //
        // Note: Early exits on any error.
        futures::future::try_join_all(self.contracts.keys().map(|id| async move {
            self.check_vkey(*id)
                .await
                .map_err(|e| e.context(format!("Failed to check verifying key for chain {}", id)))
        }))
        .await
        .context("Failed to check verifying key for all chains")?;

        // Get the data commitment max for each chain, they should be all be the same.
        //
        // Note: Early exits on any error.
        let max_commits =
            futures::future::try_join_all(self.contracts.iter().map(|(id, contract)| async move {
                match contract.DATA_COMMITMENT_MAX().call().await {
                    Ok(data_commitment_max) => anyhow::Result::Ok(data_commitment_max),
                    Err(e) => {
                        error!("Failed to get data commitment max for chain {}: {}", id, e);
                        anyhow::Result::Err(e)
                    }
                }
            }))
            .await
            .context("Failed to get data commitment max for all chains")?;

        // All the chains should have the same data commitment max.
        assert!(
            max_commits.iter().all(|&max| max == max_commits[0]),
            "Data commitment max values are not the same for all chains"
        );

        Ok(max_commits[0])
    }

    /// Create a proof of the light client protocol,
    /// updating from `current_block` to `next_block` for the given chains.
    ///
    /// # Errors
    /// - If any errors occur while creating the proof.
    async fn create_proof(
        &self,
        trusted_block: u64,
        target_block: u64,
    ) -> Result<SP1ProofWithPublicValues> {
        let mut stdin = SP1Stdin::new();

        info!("Fetching inputs for proof.");
        let inputs =
            fetch_input_for_blobstream_proof(&self.client, trusted_block, target_block).await?;
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
            .cycle_limit(10_000_000_000)
            .plonk()
            .timeout(Duration::from_secs(PROOF_TIMEOUT_SECONDS))
            .run_async()
            .await
    }

    /// Relay a header range proof to the SP1 Blobstream contract,
    /// depending on the `use_kms_relayer` flag, it will either use the KMS relayer
    /// or attempt to sign with the provider instance.
    ///
    /// # Errors
    /// - If any errors occur while relaying the proof.
    async fn relay_header_range(
        &self,
        proof: &SP1ProofWithPublicValues,
        chain_id: u64,
    ) -> Result<B256> {
        let contract = self.contracts.get(&chain_id).unwrap();

        if matches!(self.signer_mode, SignerMode::Kms) {
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

            let receipt = contract
                .commitHeaderRange(proof.bytes().into(), public_values_bytes.into())
                .send()
                .await?
                .with_required_confirmations(NUM_CONFIRMATIONS)
                .with_timeout(Some(Duration::from_secs(TRANSACTION_TIMEOUT_SECONDS)))
                .get_receipt()
                .await?;

            // If status is false, it reverted.
            if !receipt.status() {
                error!("Transaction reverted!");
            }

            Ok(receipt.transaction_hash())
        }
    }
}

/////// Env Helpers ///////

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

/////// Chain Config ///////

#[derive(Debug, serde::Deserialize)]
struct ChainConfig {
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
            Self::from_env().map(|c| vec![c])
        })
    }

    /// Tries to read from the `CONTRACT_ADDRESS` and `RPC_URL` environment variables.
    fn from_env() -> Result<Self> {
        let address = env::var("CONTRACT_ADDRESS").context("CONTRACT_ADDRESS not set")?;
        let rpc_url = env::var("RPC_URL").context("RPC_URL not set")?;

        Ok(Self {
            rpc_url,
            blobstream_address: address.parse()?,
        })
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

    // Set up tracing.
    tracing_subscriber::fmt::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::from_env("info")),
        )
        .init();

    // Succinct deployments use the `CHAINS` environment variable.
    let config = ChainConfig::fetch().expect("Failed to fetch chain config");

    // Set up the KMS relayer config.
    let signer_mode = env::var("SIGNER_MODE")
        .map(|s| s.parse().expect("SIGNER_MODE failed to parse"))
        .unwrap_or(SignerMode::Kms);

    match signer_mode {
        SignerMode::Local => run_with_wallet(config).await,
        SignerMode::Kms => run_with_kms_relayer(config).await,
    }
}

async fn run_with_wallet(config: Vec<ChainConfig>) {
    let key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY not set");
    let signer: PrivateKeySigner = key.parse().expect("Failed to parse PRIVATE_KEY");

    let prover = ProverClient::builder().network().build();
    let (pk, vk) = prover.setup(TENDERMINT_ELF);

    let client = TendermintRPCClient::default();

    let mut operator =
        SP1BlobstreamOperator::new(pk, vk, client, SignerMode::Local, Arc::new(prover));
    for (i, c) in config.iter().enumerate() {
        let url: Url = c.rpc_url.parse().expect("Failed to parse RPC URL");
        tracing::info!("Adding chain {:?} to operator", url.domain());
        tracing::info!("Chain {} of {}", i + 1, config.len());

        let provider = ProviderBuilder::new()
            .wallet(signer.clone())
            .connect_http(url);

        operator = operator.with_chain(provider, c.blobstream_address).await;
    }

    operator.run().await;
}

async fn run_with_kms_relayer(config: Vec<ChainConfig>) {
    let prover = ProverClient::builder().network().build();
    let (pk, vk) = prover.setup(TENDERMINT_ELF);

    let client = TendermintRPCClient::default();

    let mut operator =
        SP1BlobstreamOperator::new(pk, vk, client, SignerMode::Kms, Arc::new(prover));

    for (i, c) in config.iter().enumerate() {
        let url: Url = c.rpc_url.parse().expect("Failed to parse RPC URL");
        tracing::info!("Adding chain {:?} to operator", url.domain());
        tracing::info!("Chain {} of {}", i + 1, config.len());

        let provider = ProviderBuilder::new().connect_http(url);

        operator = operator.with_chain(provider, c.blobstream_address).await;
    }

    operator.run().await;
}
