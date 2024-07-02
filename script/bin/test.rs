use blobstream_script::{TendermintProver, TENDERMINT_ELF};
use clap::Parser;
use log::debug;
use sp1_sdk::SP1Stdin;
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

    let url = format!("{}/{}", "https://rpc.lunaroasis.net/", route);

    let res = reqwest::get(url.clone()).await;

    debug!("Data Commitment Response: {:?}", res.unwrap())
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

    let prover = TendermintProver::new();

    let rt = runtime::Runtime::new()?;

    let mut stdin = SP1Stdin::new();

    // Fetch the inputs for the proof.
    let inputs = rt.block_on(async {
        prover
            .fetch_input_for_blobstream_proof(args.trusted_block, args.target_block)
            .await
    });
    let encoded_proof_inputs = serde_cbor::to_vec(&inputs).unwrap();
    stdin.write_vec(encoded_proof_inputs);

    let (_, report) = prover.prover_client.execute(TENDERMINT_ELF, stdin).unwrap();
    println!("Report: {:?}", report);

    Ok(())
}
