use std::{ops::Add, time::Duration};

use alloy::primitives::U256;
use tendermint_light_client_verifier::{
    options::Options, types::LightBlock, ProdVerifier, Verdict, Verifier,
};

pub mod types;

/// Get the verdict for the header update from trusted_block to target_block.
pub fn get_header_update_verdict(trusted_block: &LightBlock, target_block: &LightBlock) -> Verdict {
    let opt = Options {
        // Note: For additionaly security, the trust threshold can be increased. By default, set to
        // 1/3.
        trust_threshold: Default::default(),
        // 2 week trusting period is valid for chains with 21 day unbonding period.
        trusting_period: Duration::from_secs(14 * 24 * 60 * 60),
        clock_drift: Default::default(),
    };

    let vp = ProdVerifier::default();
    // Note: The zkVM has no notion of time. This means that no header will be rejected for being too
    // far in the past, which is a potential issue. Deployers must ensure that the target block is not
    // too far in the past, i.e. the light client must be relatively synchronized with the chain (i.e.)
    // within the trusting period.
    let verify_time = target_block.time();
    vp.verify_update_header(
        target_block.as_untrusted_state(),
        trusted_block.as_trusted_state(),
        &opt,
        verify_time,
    )
}

// Convert a boolean array to a U256. Used to commit to the validator bitmap.
pub fn convert_bitmap_to_u256(arr: [bool; 256]) -> U256 {
    let mut res = U256::from(0);
    for (index, &value) in arr.iter().enumerate() {
        if value {
            res = res.add(U256::from(1) << index)
        }
    }
    res
}
