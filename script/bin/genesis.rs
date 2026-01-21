//! To build the binary:
//!
//!     `cargo build --release --bin genesis`
//!
//!
//!
//!
//!

use clap::Parser;
use sp1_blobstream_script::util::*;
use sp1_blobstream_script::TendermintRPCClient;
use sp1_sdk::{HashableKey, MockProver, Prover, ProvingKey};
use std::env;
use tracing::info;
use tracing_subscriber::EnvFilter;
const BLOBSTREAMX_ELF: &[u8] = include_bytes!("../../elf/blobstream-elf");

#[derive(Parser, Debug, Clone)]
#[command(about = "Get the genesis parameters from a block.")]
pub struct GenesisArgs {
    #[arg(long)]
    pub block: Option<u64>,
}

#[tokio::main]
pub async fn main() {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();

    // Set up tracing.
    tracing_subscriber::fmt::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let data_fetcher = TendermintRPCClient::default();
    let args = GenesisArgs::parse();

    let client = MockProver::new().await;
    let pk = client
        .setup(sp1_sdk::Elf::Static(BLOBSTREAMX_ELF))
        .await
        .expect("Failed to setup prover");
    let vk = pk.verifying_key().clone();

    if let Some(block) = args.block {
        let header_hash = fetch_header_hash(&data_fetcher, block)
            .await
            .expect("Failed to fetch genesis header hash");

        info!(
            "\nGENESIS_HEIGHT={:?}\nGENESIS_HEADER={}\nSP1_BLOBSTREAM_PROGRAM_VKEY={}\n",
            block,
            header_hash.to_string(),
            vk.bytes32(),
        );
    } else {
        let latest_block_height = get_latest_block_height(&data_fetcher)
            .await
            .expect("Can get latest block hash");

        let header_hash = fetch_header_hash(&data_fetcher, latest_block_height)
            .await
            .expect("Failed to fetch latest block header hash");

        info!(
            "\nGENESIS_HEIGHT={:?}\nGENESIS_HEADER={}\nSP1_BLOBSTREAM_PROGRAM_VKEY={}\n",
            latest_block_height,
            header_hash.to_string(),
            vk.bytes32(),
        );
    }
}
