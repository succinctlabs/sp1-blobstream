use alloy::sol;
use serde::{Deserialize, Serialize};
use tendermint::block::Header;
use tendermint_light_client_verifier::types::LightBlock;

/// bytes32 trusted_header_hash;
/// bytes32 target_header_hash;
/// bytes32 data_commitment;
/// uint64 trusted_block;
/// uint64 target_block;
/// uint256 validator_bitmap;
pub type ProofOutputs = sol! {
    tuple(bytes32, bytes32, bytes32, uint64, uint64, uint256)
};

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofInputs {
    pub trusted_light_block: LightBlock,
    pub target_light_block: LightBlock,
    /// Exclusive of trusted_light_block and target_light_block's headers
    pub headers: Vec<Header>,
}
