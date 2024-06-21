use alloy::primitives::U256;

pub mod types;

// Convert a boolean array to a uint256. This is useful for committing to the validator bitmap.
pub fn bool_array_to_uint256(arr: [bool; 256]) -> U256 {
    let mut result = [0u64; 4];
    for (index, &value) in arr.iter().enumerate() {
        if value {
            let word_index = index / 64;
            let bit_index = index % 64;
            if word_index < 4 {
                result[word_index] |= 1 << bit_index;
            }
        }
    }
    U256::from_limbs(result)
}
