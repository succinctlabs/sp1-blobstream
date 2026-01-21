use clap::Parser;
use sp1_blobstream_script::util::fetch_input_for_blobstream_proof;
use sp1_blobstream_script::{TendermintRPCClient, TENDERMINT_ELF};
use sp1_sdk::{include_elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};
use tokio::runtime;

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
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    sp1_sdk::utils::setup_logger();

    let args = ScriptArgs::parse();

    let mut stdin = SP1Stdin::new();
    let tendermint_rpc_client = TendermintRPCClient::default();

    // Fetch the inputs for the proof.
    let inputs = fetch_input_for_blobstream_proof(
        &tendermint_rpc_client,
        args.trusted_block,
        args.target_block,
    )
    .await
    .expect("Failed to fetch proof inputs");
    let encoded_proof_inputs = serde_cbor::to_vec(&inputs).unwrap();
    stdin.write_vec(encoded_proof_inputs);

    let prover_client = ProverClient::from_env().await;
    let new_elf = include_elf!("sp1-blobstream-program").to_vec();
    let pk = prover_client
        .setup(new_elf.into())
        .await
        .expect("Failed to setup prover");
    let vk = pk.verifying_key().clone();
    let proof = prover_client.prove(&pk, stdin).groth16().await?;
    prover_client.verify(&proof, &vk, None)?;

    Ok(())
}
