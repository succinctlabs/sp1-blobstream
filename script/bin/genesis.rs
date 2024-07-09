//! To build the binary:
//!
//!     `cargo build --release --bin genesis`
//!
//!
//!
//!
//!

use std::env;

use blobstream_script::util::TendermintRPCClient;
use clap::Parser;
use log::info;
use sp1_sdk::{HashableKey, ProverClient};
const BLOBSTREAMX_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

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
    env_logger::init();
    let data_fetcher = TendermintRPCClient::default();
    let args = GenesisArgs::parse();

    let client = ProverClient::new();
    let (_pk, vk) = client.setup(BLOBSTREAMX_ELF);

    if let Some(block) = args.block {
        let header_hash = data_fetcher.fetch_header_hash(block).await;
        info!(
            "\nGENESIS_HEIGHT={:?}\nGENESIS_HEADER={}\nSP1_BLOBSTREAM_PROGRAM_VKEY={}\n",
            block,
            header_hash.to_string(),
            vk.bytes32(),
        );
    } else {
        let latest_block_height = data_fetcher.get_latest_block_height().await;
        let header_hash = data_fetcher.fetch_header_hash(latest_block_height).await;

        info!(
            "\nGENESIS_HEIGHT={:?}\nGENESIS_HEADER={}\nSP1_BLOBSTREAM_PROGRAM_VKEY={}\n",
            latest_block_height,
            header_hash.to_string(),
            vk.bytes32(),
        );
    }
}
