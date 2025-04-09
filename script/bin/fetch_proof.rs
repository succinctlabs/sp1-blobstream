use std::str::FromStr;

use alloy::primitives::{Bytes, B256};
use alloy::sol;
use alloy::sol_types::{SolCall, SolType};
use clap::Parser;
use sp1_blobstream_primitives::types::ProofOutputs;
use sp1_blobstream_script::util::fetch_input_for_blobstream_proof;
use sp1_blobstream_script::{relay, TendermintRPCClient, TENDERMINT_ELF};
use sp1_sdk::{ProverClient, SP1Stdin};
use tokio::runtime;
use tracing::info;
use SP1Blobstream::commitHeaderRangeCall;

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract SP1Blobstream {
        bool public frozen;
        uint64 public latestBlock;
        uint256 public state_proofNonce;
        mapping(uint64 => bytes32) public blockHeightToHeaderHash;
        mapping(uint256 => bytes32) public state_dataCommitments;
        uint64 public constant DATA_COMMITMENT_MAX = 10000;
        bytes32 public blobstreamProgramVkey;
        address public verifier;

        function commitHeaderRange(bytes calldata proof, bytes calldata publicValues) external;
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct ScriptArgs {
    /// Proof ID.
    #[clap(long)]
    proof_id: B256,
}

/// Fetch a proof from the prover.
/// Example:
/// ```
/// RUST_LOG=info cargo run --bin fetch_proof --release -- --proof-id=0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
/// ```
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    sp1_sdk::utils::setup_logger();

    let args = ScriptArgs::parse();

    let prover_client = ProverClient::builder().network().build();

    let (status, maybe_proof) = prover_client.get_proof_status(args.proof_id).await?;

    if let Some(proof) = maybe_proof {
        let proof_bytes = proof.bytes();
        let mut pv = proof.public_values;

        let commit_header_range = commitHeaderRangeCall {
            proof: proof_bytes.into(),
            publicValues: pv.to_vec().into(),
        };

        let mut buf = [0u8; 32 * 6];
        pv.read_slice(&mut buf);

        // info!("Proof outputs bytes: {:?}", Bytes::from(buf));
        // let proof_outputs = ProofOutputs::abi_decode(&buf, true).unwrap();

        // info!("Proof outputs: {:?}", proof_outputs);
        // info!("Proof: {:?}", Bytes::from(proof_bytes));

        let calldata = commit_header_range.abi_encode();

        let chain_id = 17000;

        relay::relay_with_kms(
            &relay::KMSRelayRequest {
                chain_id,
                address: "0x315A044cb95e4d44bBf6253585FbEbcdB6fb41ef".to_string(),
                calldata: hex::encode(calldata),
                platform_request: false,
            },
            1,
        )
        .await?;
    }

    Ok(())
}
