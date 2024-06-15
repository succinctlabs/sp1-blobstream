use alloy_primitives::U256;
use alloy_sol_types::{sol, SolCall, SolType, SolValue};
use anyhow::Result;
use blobstream_script::util::TendermintRPCClient;
use blobstream_script::{contract::ContractClient, TendermintProver};
use log::{error, info};
use primitives::types::ProofOutputs;
use sp1_sdk::{ProverClient, SP1PlonkBn254Proof, SP1ProvingKey, SP1Stdin};
use std::env;
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

struct BlobstreamXOperator {
    contract: ContractClient,
    client: ProverClient,
    pk: SP1ProvingKey,
}

sol! {
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

        let contract = ContractClient::default();
        let client = ProverClient::new();
        let (pk, _) = client.setup(ELF);

        Self {
            contract,
            client,
            pk,
        }
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

    fn log_proof_outputs(&self, proof: &mut SP1PlonkBn254Proof) {
        // Read output values.
        let public_values = proof.public_values.as_ref();
        let outputs = ProofOutputs::abi_decode(public_values, true).unwrap();

        println!("Proof Outputs: {:?}", outputs);
    }

    /// Relay a header range proof to the SP1 VectorX contract.
    async fn relay_header_range(&self, mut proof: SP1PlonkBn254Proof) {
        self.log_proof_outputs(&mut proof);

        let proof_as_bytes = hex::decode(&proof.proof.encoded_proof).unwrap();
        let verify_vectorx_proof_call_data = BlobstreamX::commitHeaderRangeCall {
            publicValues: proof.public_values.to_vec().into(),
            proof: proof_as_bytes.into(),
        }
        .abi_encode();

        let receipt = self
            .contract
            .send(verify_vectorx_proof_call_data)
            .await
            .expect("Failed to post/verify header range proof onchain.");

        if let Some(receipt) = receipt {
            println!("Transaction hash: {:?}", receipt.transaction_hash);
        }
    }

    async fn run(&mut self, loop_delay_mins: u64, block_interval: u64, data_commitment_max: u64) {
        info!("Starting BlobstreamX operator");
        let mut fetcher = TendermintRPCClient::default();

        loop {
            // Get the latest block from the contract.
            let current_block_call_data = BlobstreamX::latestBlockCall {}.abi_encode();
            let current_block = self.contract.read(current_block_call_data).await.unwrap();
            let current_block = U256::abi_decode(&current_block, true).unwrap();
            let current_block: u64 = current_block.try_into().unwrap();

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
