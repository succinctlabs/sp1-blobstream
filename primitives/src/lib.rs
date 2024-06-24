use std::{ops::Add, time::Duration};

use alloy::primitives::U256;
use tendermint_light_client_verifier::{
    options::Options, types::LightBlock, ProdVerifier, Verdict, Verifier,
};

pub mod types;

/// Get the verdict for the header update from trusted_block to target_block.
pub fn get_header_update_verdict(trusted_block: &LightBlock, target_block: &LightBlock) -> Verdict {
    let opt = Options {
        // TODO: Should we set a custom threshold?
        trust_threshold: Default::default(),
        // 2 week trusting period.
        trusting_period: Duration::from_secs(14 * 24 * 60 * 60),
        clock_drift: Default::default(),
    };

    let vp = ProdVerifier::default();
    // TODO: What should we set the verify time to? This prevents outdated headers from being used.
    let verify_time = target_block.time() + Duration::from_secs(20);
    vp.verify_update_header(
        target_block.as_untrusted_state(),
        trusted_block.as_trusted_state(),
        &opt,
        verify_time.unwrap(),
    )
}

// Convert a boolean array to a uint256. This is useful for committing to the validator bitmap.
pub fn bool_array_to_uint256(arr: [bool; 256]) -> U256 {
    let mut res = U256::from(0);
    for (index, &value) in arr.iter().enumerate() {
        if value {
            res = res.add(U256::from(1) << index)
        }
    }
    res
}
