use crate::util::TendermintRPCClient;

use primitives::types::ProofInputs;
use sp1_sdk::{ProverClient, SP1ProvingKey, SP1VerifyingKey};
pub mod relay;
mod types;
pub mod util;

// The path to the ELF file for the Succinct zkVM program.
pub const TENDERMINT_ELF: &[u8] = include_bytes!("../../elf/blobstream-elf");

pub struct TendermintProver {
    pub prover_client: ProverClient,
    pub pkey: SP1ProvingKey,
    pub vkey: SP1VerifyingKey,
}

impl Default for TendermintProver {
    fn default() -> Self {
        Self::new()
    }
}

impl TendermintProver {
    pub fn new() -> Self {
        log::info!("Initializing SP1 ProverClient...");
        let prover_client = ProverClient::new();
        let (pkey, vkey) = prover_client.setup(TENDERMINT_ELF);
        log::info!("SP1 ProverClient initialized");
        Self {
            prover_client,
            pkey,
            vkey,
        }
    }

    // Fetch the inputs for a Blobstream proof.
    pub async fn fetch_input_for_blobstream_proof(
        &self,
        trusted_block_height: u64,
        target_block_height: u64,
    ) -> ProofInputs {
        let tendermint_client = TendermintRPCClient::default();
        let light_blocks = tendermint_client
            .fetch_light_blocks_in_range(trusted_block_height, target_block_height)
            .await;

        let mut headers = Vec::new();
        for light_block in &light_blocks[1..light_blocks.len() - 1] {
            headers.push(light_block.signed_header.header.clone());
        }

        ProofInputs {
            trusted_light_block: light_blocks[0].clone(),
            target_light_block: light_blocks[light_blocks.len() - 1].clone(),
            headers,
        }
    }
}
