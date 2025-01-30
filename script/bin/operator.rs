use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
};
use anyhow::Result;
use log::{error, info};
use reqwest::Url;
use sp1_blobstream_primitives::get_header_update_verdict;
use sp1_blobstream_script::util::TendermintRPCClient;
use sp1_blobstream_script::{relay, TENDERMINT_ELF};
use sp1_sdk::{
    network::FulfillmentStrategy, HashableKey, ProverClient, SP1ProofWithPublicValues,
    SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};
use std::env;
use std::time::Duration;
use tendermint_light_client_verifier::Verdict;

struct SP1BlobstreamOperator {
    pk: SP1ProvingKey,
    vk: SP1VerifyingKey,
    contract_address: Address,
    rpc_url: Url,
    chain_id: u64,
    use_kms_relayer: bool,
}

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

// Timeout for the proof in seconds.
const PROOF_TIMEOUT_SECONDS: u64 = 60 * 30;

const NUM_RELAY_RETRIES: u32 = 3;

impl SP1BlobstreamOperator {
    pub async fn new() -> Self {
        dotenv::dotenv().ok();

        let prover_client = ProverClient::from_env();
        let (pk, vk) = prover_client.setup(TENDERMINT_ELF);
        let use_kms_relayer: bool = env::var("USE_KMS_RELAYER")
            .unwrap_or("false".to_string())
            .parse()
            .unwrap();
        let chain_id: u64 = env::var("CHAIN_ID")
            .expect("CHAIN_ID not set")
            .parse()
            .unwrap();
        let rpc_url = env::var("RPC_URL")
            .expect("RPC_URL not set")
            .parse()
            .unwrap();

        let contract_address = env::var("CONTRACT_ADDRESS")
            .expect("CONTRACT_ADDRESS not set")
            .parse()
            .unwrap();

        Self {
            pk,
            vk,
            chain_id,
            rpc_url,
            contract_address,
            use_kms_relayer,
        }
    }

    /// Check the verifying key in the contract matches the verifying key in the prover.
    async fn check_vkey(&self) -> Result<()> {
        let provider = ProviderBuilder::new().on_http(self.rpc_url.clone());
        let contract = SP1Blobstream::new(self.contract_address, provider);
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
        let inputs = rpc_client
            .fetch_input_for_blobstream_proof(trusted_block, target_block)
            .await;
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
            let provider = ProviderBuilder::new().on_http(self.rpc_url.clone());
            let contract = SP1Blobstream::new(self.contract_address, provider);
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
            let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY not set");
            let signer: PrivateKeySigner =
                private_key.parse().expect("Failed to parse private key");
            let wallet = EthereumWallet::from(signer);
            let provider = ProviderBuilder::new()
                .with_recommended_fillers()
                .wallet(wallet)
                .on_http(self.rpc_url.clone());
            let contract = SP1Blobstream::new(self.contract_address, provider);
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

            Ok(receipt.transaction_hash)
        }
    }

    async fn run(&self) -> Result<()> {
        self.check_vkey().await?;

        let fetcher = TendermintRPCClient::default();
        let block_update_interval = get_block_update_interval();

        let provider = ProviderBuilder::new().on_http(self.rpc_url.clone());
        let contract = SP1Blobstream::new(self.contract_address, provider);

        // Read the data commitment max from the contract.
        let data_commitment_max = contract
            .DATA_COMMITMENT_MAX()
            .call()
            .await?
            .DATA_COMMITMENT_MAX;

        // Get the latest block from the contract.
        let current_block = contract.latestBlock().call().await?.latestBlock;

        // Get the head of the chain.
        let latest_tendermint_block_nb = fetcher.get_latest_block_height().await;

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

            let target_block = fetcher
                .find_block_to_request(current_block, max_end_block)
                .await;

            info!("Current block: {}", current_block);
            info!("Attempting to step to block {}", target_block);

            // Request a header range if the target block is not the next block.
            match self.request_header_range(current_block, target_block).await {
                Ok(proof) => {
                    let tx_hash = self.relay_header_range(proof).await?;
                    info!(
                        "Posted data commitment from block {} to block {}\nTransaction hash: {}",
                        current_block, target_block, tx_hash
                    );
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Header range request failed: {}", e));
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
    let block_update_interval_env = env::var("BLOCK_UPDATE_INTERVAL");
    let mut block_update_interval = 360;
    if block_update_interval_env.is_ok() {
        block_update_interval = block_update_interval_env
            .unwrap()
            .parse::<u64>()
            .expect("invalid BLOCK_UPDATE_INTERVAL");
    }
    block_update_interval
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    env_logger::init();

    let operator = SP1BlobstreamOperator::new().await;

    info!("Starting SP1 Blobstream operator");
    const LOOP_TIMEOUT_MINS: u64 = 20;
    loop {
        let request_interval_mins = get_loop_interval_mins();
        // If the operator takes longer than LOOP_TIMEOUT_MINS for a single invocation, or there's
        // an error, sleep for the loop interval and try again.
        tokio::select! {
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(60 * LOOP_TIMEOUT_MINS)) => {
                continue;
            }
            e = operator.run() => {
                if let Err(e) = e {
                    error!("Error running operator: {}", e);
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(60 * request_interval_mins)).await;
    }
}
