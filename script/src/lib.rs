use crate::util::TendermintRPCClient;
use sp1_sdk::{PlonkBn254Proof, ProverClient, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin, SP1VerifyingKey};
use tendermint_light_client_verifier::types::LightBlock;

mod types;
pub mod util;
pub mod contract;

// The path to the ELF file for the Succinct zkVM program.
pub const TENDERMINT_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

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

    /// Fetch the trusted height from the trusted header hash and generate a proof from the trusted
    /// block to the latest block.
    pub async fn generate_header_update_proof_to_latest_block(
        &self,
        trusted_header_hash: &[u8],
    ) -> SP1ProofWithPublicValues<PlonkBn254Proof> {
        let tendermint_client = TendermintRPCClient::default();
        let latest_block_height = tendermint_client.get_latest_block_height().await;

        // Get the block height corresponding to the trusted header hash.
        let trusted_block_height = tendermint_client
            .get_block_height_from_hash(trusted_header_hash)
            .await;
        let (trusted_light_block, target_light_block) = tendermint_client
            .get_light_blocks(trusted_block_height, latest_block_height)
            .await;

        self.generate_header_update_proof(&trusted_light_block, &target_light_block)
            .await
    }

    /// Given a trusted block height and a target block height, generate a proof of the update.
    pub async fn generate_header_update_proof_between_blocks(
        &self,
        trusted_block_height: u64,
        target_block_height: u64,
    ) -> SP1ProofWithPublicValues<PlonkBn254Proof> {
        let tendermint_client = TendermintRPCClient::default();
        let (trusted_light_block, target_light_block) = tendermint_client
            .get_light_blocks(trusted_block_height, target_block_height)
            .await;
        self.generate_header_update_proof(&trusted_light_block, &target_light_block)
            .await
    }

    pub async fn fetch_input_for_header_update_proof(
        &self,
        trusted_block_height: u64,
        target_block_height: u64,
    ) -> SP1Stdin {
        let tendermint_client = TendermintRPCClient::default();
        let (trusted_light_block, target_light_block) = tendermint_client
            .get_light_blocks(trusted_block_height, target_block_height)
            .await;
        // Encode the light blocks to be input into our program.
        let encoded_1 = serde_cbor::to_vec(&trusted_light_block).unwrap();
        let encoded_2 = serde_cbor::to_vec(&target_light_block).unwrap();

        // Write the encoded light blocks to stdin.
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(encoded_1);
        stdin.write_vec(encoded_2);

        stdin
    }

    // Fetch the inputs for a Blobstream proof.
    pub async fn fetch_input_for_blobstream_proof(
        &self,
        trusted_block_height: u64,
        target_block_height: u64,
    ) -> SP1Stdin {
        let tendermint_client = TendermintRPCClient::default();
        let light_blocks = tendermint_client
            .fetch_light_blocks_in_range(trusted_block_height, target_block_height)
            .await;

        let mut stdin = SP1Stdin::new();

        stdin.write(&trusted_block_height);
        stdin.write(&target_block_height);

        // Encode the light blocks to be input into our program.
        // Write the encoded light blocks to stdin.
        for light_block in light_blocks {
            let encoded = serde_cbor::to_vec(&light_block).unwrap();
            stdin.write_vec(encoded);
        }

        stdin
    }

    /// Generate a proof of an update from trusted_light_block to target_light_block. Returns the
    /// public values and proof of the update.
    pub async fn generate_header_update_proof(
        &self,
        trusted_light_block: &LightBlock,
        target_light_block: &LightBlock,
    ) -> SP1ProofWithPublicValues<PlonkBn254Proof> {
        log::info!(
            "Generating proof for blocks {} to {}",
            trusted_light_block.height(),
            target_light_block.height()
        );
        // Encode the light blocks to be input into our program.
        let encoded_1 = serde_cbor::to_vec(&trusted_light_block).unwrap();
        let encoded_2 = serde_cbor::to_vec(&target_light_block).unwrap();

        // Write the encoded light blocks to stdin.
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(encoded_1);
        stdin.write_vec(encoded_2);

        // Generate the proof. Depending on SP1_PROVER env, this may be a local or network proof.
        let proof = self
            .prover_client
            .prove_plonk(&self.pkey, stdin)
            .expect("proving failed");
        println!("Successfully generated proof!");

        // Verify proof.
        self.prover_client
            .verify_plonk(&proof, &self.vkey)
            .expect("Verification failed");

        // Return the proof.
        proof
    }
}
