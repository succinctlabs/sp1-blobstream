use alloy::providers::Provider;
use alloy::sol;
use alloy::{
    network::EthereumWallet, providers::ProviderBuilder, signers::local::PrivateKeySigner,
};
use anyhow::Result;
use blobstream_script::util::TendermintRPCClient;
use blobstream_script::TendermintProver;
use log::{error, info};
use reqwest::Url;
use sp1_sdk::{ProverClient, SP1PlonkBn254Proof, SP1ProvingKey, SP1Stdin};
use std::env;

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

struct BlobstreamXOperator {
    client: ProverClient,
    pk: SP1ProvingKey,
    chain_id: u64,
    rpc_url: Url,
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract BlobstreamX {
        bool public frozen;
        uint64 public latestBlock;
        uint256 public state_proofNonce;
        mapping(uint64 => bytes32) public blockHeightToHeaderHash;
        mapping(uint256 => bytes32) public state_dataCommitments;
        uint64 public constant DATA_COMMITMENT_MAX = 10000;
        bytes32 public blobstreamXProgramVkey;
        address public verifier;

        function commitHeaderRange(bytes calldata proof, bytes calldata publicValues) external;
    }
}

impl BlobstreamXOperator {
    pub async fn new() -> Self {
        dotenv::dotenv().ok();

        let client = ProverClient::new();
        let (pk, _) = client.setup(ELF);
        let chain_id = env::var("CHAIN_ID")
            .expect("CHAIN_ID not set")
            .parse()
            .unwrap();
        let rpc_url = env::var("RPC_URL")
            .expect("RPC_URL not set")
            .parse()
            .unwrap();

        Self {
            client,
            pk,
            chain_id,
            rpc_url,
        }
    }

    /// Get the gas limit.
    fn get_gas_limit(&self) -> u128 {
        if self.chain_id == 42161 || self.chain_id == 421614 {
            15_000_000
        } else {
            1_500_000
        }
    }

    /// Get the gas fee cap.
    async fn get_fee_cap(&self) -> u128 {
        // Base percentage multiplier for the gas fee.
        let mut multiplier = 20;

        // Double the estimated gas fee cap for the testnets.
        if self.chain_id == 17000
            || self.chain_id == 421614
            || self.chain_id == 11155111
            || self.chain_id == 84532
        {
            multiplier = 100
        }

        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .on_http(self.rpc_url.clone());

        // Get the gas price.
        let gas_price = provider.get_gas_price().await.unwrap();

        // Calculate the fee cap.
        (gas_price * (100 + multiplier)) / 100
    }

    async fn request_header_range(
        &self,
        trusted_block: u64,
        target_block: u64,
    ) -> Result<SP1PlonkBn254Proof> {
        let prover = TendermintProver::new();
        let mut stdin = SP1Stdin::new();

        let inputs = prover
            .fetch_input_for_blobstream_proof(trusted_block, target_block)
            .await;

        let encoded_proof_inputs = serde_cbor::to_vec(&inputs).unwrap();
        stdin.write_vec(encoded_proof_inputs);

        self.client.prove_plonk(&self.pk, stdin)
    }

    /// Relay a header range proof to the SP1 BlobstreamX contract.
    async fn relay_header_range(&self, proof: SP1PlonkBn254Proof) {
        let proof_as_bytes = hex::decode(&proof.proof.encoded_proof).unwrap();
        let public_values_bytes = proof.public_values.to_vec();

        let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY not set");
        let rpc_url = env::var("RPC_URL")
            .expect("RPC_URL not set")
            .parse()
            .unwrap();
        let contract_address = env::var("CONTRACT_ADDRESS")
            .expect("CONTRACT_ADDRESS not set")
            .parse()
            .unwrap();
        let signer: PrivateKeySigner = private_key.parse().expect("Failed to parse private key");
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new().wallet(wallet).on_http(rpc_url);

        let contract = BlobstreamX::new(contract_address, provider);

        let gas_limit = self.get_gas_limit();
        let max_fee_per_gas = self.get_fee_cap().await;

        let tx_hash = contract
            .commitHeaderRange(proof_as_bytes.into(), public_values_bytes.into())
            .gas_price(max_fee_per_gas)
            .gas(gas_limit)
            .send()
            .await
            .unwrap()
            .watch()
            .await
            .unwrap();

        println!("Transaction hash: {:?}", tx_hash);
    }

    async fn run(&mut self, loop_delay_mins: u64, block_interval: u64, data_commitment_max: u64) {
        info!("Starting BlobstreamX operator");
        let mut fetcher = TendermintRPCClient::default();

        loop {
            let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY not set");
            let rpc_url = env::var("RPC_URL")
                .expect("RPC_URL not set")
                .parse()
                .unwrap();
            let contract_address = env::var("CONTRACT_ADDRESS")
                .expect("CONTRACT_ADDRESS not set")
                .parse()
                .unwrap();
            let signer: PrivateKeySigner =
                private_key.parse().expect("Failed to parse private key");
            let wallet = EthereumWallet::from(signer);
            let provider = ProviderBuilder::new().wallet(wallet).on_http(rpc_url);

            let contract = BlobstreamX::new(contract_address, provider);

            // Get the latest block from the contract.
            let current_block = contract.latestBlock().call().await.unwrap();
            let current_block: u64 = current_block.latestBlock;

            // Get the head of the chain.
            let latest_tendermint_block_nb = fetcher.get_latest_block_height().await;

            // Subtract 1 block to ensure the block is stable.
            let latest_stable_tendermint_block = latest_tendermint_block_nb - 1;

            // block_to_request is the closest interval of block_interval less than min(latest_stable_tendermint_block, data_commitment_max + current_block)
            let max_block = std::cmp::min(
                latest_stable_tendermint_block,
                data_commitment_max + current_block,
            );
            let block_to_request = max_block - (max_block % block_interval);

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
                        self.relay_header_range(proof).await;
                    }
                    Err(e) => {
                        error!("Header range request failed: {}", e);
                        continue;
                    }
                };
            } else {
                info!("Next block to request is {} which is > the head of the Tendermint chain which is {}. Sleeping.", block_to_request + block_interval, latest_stable_tendermint_block);
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(60 * loop_delay_mins)).await;
        }
    }
}

#[tokio::main]
async fn main() {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    env_logger::init();

    let loop_delay_mins_env = env::var("LOOP_DELAY_MINS");
    let mut loop_delay_mins = 5;
    if loop_delay_mins_env.is_ok() {
        loop_delay_mins = loop_delay_mins_env
            .unwrap()
            .parse::<u64>()
            .expect("invalid LOOP_DELAY_MINS");
    }

    let update_delay_blocks_env = env::var("UPDATE_DELAY_BLOCKS");
    let mut update_delay_blocks = 300;
    if update_delay_blocks_env.is_ok() {
        update_delay_blocks = update_delay_blocks_env
            .unwrap()
            .parse::<u64>()
            .expect("invalid UPDATE_DELAY_BLOCKS");
    }

    let data_commitment_max_env = env::var("DATA_COMMITMENT_MAX");
    // Note: This default value reflects the max data commitment size that can be rquested from the
    // Celestia node.
    let mut data_commitment_max = 1000;
    if data_commitment_max_env.is_ok() {
        data_commitment_max = data_commitment_max_env
            .unwrap()
            .parse::<u64>()
            .expect("invalid DATA_COMMITMENT_MAX");
    }

    let mut operator = BlobstreamXOperator::new().await;
    operator
        .run(loop_delay_mins, update_delay_blocks, data_commitment_max)
        .await;
}
