use clap::Parser;
use sp1_blobstream_script::util::fetch_input_for_blobstream_proof;
use sp1_blobstream_script::{TendermintRPCClient, TENDERMINT_ELF};
use sp1_sdk::{ProverClient, SP1Stdin};
use tokio::runtime;
use tracing::debug;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct ScriptArgs {
    /// Trusted block.
    #[clap(long)]
    trusted_block: u64,

    /// Target block.
    #[clap(long, env)]
    target_block: u64,
}

/// Generate a proof between the given trusted and target blocks.
/// Example:
/// ```
/// RUST_LOG=info cargo run --bin test --release -- --trusted-block=1 --target-block=5
/// ```
fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    sp1_sdk::utils::setup_logger();

    let args = ScriptArgs::parse();

    let rt = runtime::Runtime::new()?;

    let mut stdin = SP1Stdin::new();
    let tendermint_rpc_client = TendermintRPCClient::default();

    // Fetch the inputs for the proof.
    let inputs = rt.block_on(async {
        fetch_input_for_blobstream_proof(
            &tendermint_rpc_client,
            args.trusted_block,
            args.target_block,
        )
        .await
        .expect("Failed to fetch proof inputs")
    });
    let encoded_proof_inputs = serde_cbor::to_vec(&inputs).unwrap();
    stdin.write_vec(encoded_proof_inputs);

    let prover_client = ProverClient::from_env();
    let (pk, vk) = prover_client.setup(TENDERMINT_ELF);
    let proof = prover_client.prove(&pk, &stdin).groth16().run()?;
    prover_client.verify(&proof, &vk)?;

    Ok(())
}
