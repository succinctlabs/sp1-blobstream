use blobstream_script::TendermintProver;
use clap::Parser;
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

pub async fn get_data_commitment(start_block: u64, end_block: u64) {
    // If start_block == end_block, then return a dummy commitment.
    // This will occur in the context of data commitment's map reduce when leaves that contain blocks beyond the end_block.

    let route = format!(
        "data_commitment?start={}&end={}",
        start_block.to_string().as_str(),
        end_block.to_string().as_str()
    );

    let url = format!(
        "{}/{}",
        "http://consensus-full-mocha-4.celestia-mocha.com:26657", route
    );

    let mut res = reqwest::get(url.clone()).await;

    println!("Data Commitment Response: {:?}", res.unwrap())
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
            .fetch_input_for_blobstream_proof(args.trusted_block, args.target_block)
            .await
    });

    // Generate the proof. Depending on SP1_PROVER env, this may be a local or network proof.
    let proof = prover
        .prover_client
        .prove(&prover.pkey, stdin)
        .expect("proving failed");
    println!("Successfully generated proof!");

    let public_values = proof.public_values.as_ref();
    let data_commitment = public_values[64..96].to_vec();
    println!("Data commitment: {:?}", hex::encode(data_commitment));

    // // // Verify proof.
    // prover
    //     .prover_client
    //     .verify_groth16(&proof, &prover.vkey)
    //     .expect("Verification failed");

    Ok(())
}
