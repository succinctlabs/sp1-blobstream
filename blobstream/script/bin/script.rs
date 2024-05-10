use clap::Parser;
use tendermint_operator::TendermintProver;
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
/// RUST_LOG=info cargo run --bin script --release -- --trusted-block=1 --target-block=5
/// ```
fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    sp1_sdk::utils::setup_logger();

    let args = ScriptArgs::parse();

    let prover = TendermintProver::new();

    let rt = runtime::Runtime::new()?;

    // Fetch the stdin for the proof.
    let stdin = rt.block_on(async {
        prover
            .fetch_input_for_header_update_proof(args.trusted_block, args.target_block)
            .await
    });

    // Generate the proof. Depending on SP1_PROVER env, this may be a local or network proof.
    let proof = prover
        .prover_client
        .prove_groth16(&prover.pkey, stdin)
        .expect("proving failed");
    println!("Successfully generated proof!");

    // Verify proof.
    prover
        .prover_client
        .verify_groth16(&proof, &prover.vkey)
        .expect("Verification failed");

    Ok(())
}
