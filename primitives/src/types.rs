use alloy_sol_types::sol;

// bytes32 trusted_header_hash;
// bytes32 target_header_hash;
// bytes32 data_commitment;
// uint64 trusted_block;
// uint64 target_block;
pub type ProofOutputs = sol! {
    tuple(bytes32, bytes32, bytes32, uint64, uint64)
};