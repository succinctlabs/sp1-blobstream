#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy::primitives::B256;
use alloy::primitives::U256;
use alloy::sol;
use alloy::sol_types::SolType;
use primitives::get_header_update_verdict;
use primitives::types::ProofInputs;
use primitives::types::ProofOutputs;
use sha2::Sha256;
use std::collections::HashSet;
use std::ops::Add;
use tendermint::{block::Header, merkle::simple_hash_from_byte_vectors};
use tendermint_light_client_verifier::types::LightBlock;
use tendermint_light_client_verifier::Verdict;
type DataRootTuple = sol! {
    tuple(uint64, bytes32)
};

/// Compute the data commitment for the supplied headers. Each leaf in the Tendermint Merkle tree
/// is the SHA256 hash of the concatenation of the block height and the header's last `Commit`.
/// Excludes the last header's data hash from the commitment to avoid overlapping headers between
/// commits.
fn compute_data_commitment(headers: &[Header]) -> [u8; 32] {
    let mut encoded_data_root_tuples: Vec<Vec<u8>> = Vec::new();
    // Loop over all headers except the last one.
    for i in 0..headers.len() - 1 {
        let curr_header = &headers[i];
        let next_header = &headers[i + 1];

        // Verify the chain of headers is connected.
        if curr_header.hash() != next_header.last_block_id.unwrap().hash {
            panic!("invalid header");
        }

        let data_hash: [u8; 32] = curr_header
            .data_hash
            .expect("Header has no data hash.")
            .as_bytes()
            .try_into()
            .unwrap();

        // ABI-encode the leaf corresponding to this header, which is a DataRootTuple.
        let data_root_tuple = DataRootTuple::abi_encode(&(curr_header.height.value(), data_hash));
        encoded_data_root_tuples.push(data_root_tuple);
    }

    // Return the root of the Tendermint Merkle tree.
    simple_hash_from_byte_vectors::<Sha256>(&encoded_data_root_tuples)
}

// Convert a boolean array to a U256. Used to commit to the validator bitmap.
fn convert_bitmap_to_u256(arr: [bool; 256]) -> U256 {
    let mut res = U256::from(0);
    for (index, &value) in arr.iter().enumerate() {
        if value {
            res = res.add(U256::from(1) << index)
        }
    }
    res
}

/// Construct a bitmap of the intersection of the validators that signed off on the trusted and
/// target header. Use the order of the validators from the trusted header. Equivocates slashing in
/// the case that validators are malicious. 256 is chosen as the maximum number of validators as it
/// is unlikely that Celestia has >256 validators.
fn get_validator_bitmap_commitment(
    trusted_light_block: &LightBlock,
    target_light_block: &LightBlock,
) -> U256 {
    // If a validator has signed off on both headers, add them to the intersection set.
    let mut validator_commit_intersection = HashSet::new();
    for i in 0..trusted_light_block.signed_header.commit.signatures.len() {
        for j in 0..target_light_block.signed_header.commit.signatures.len() {
            let trusted_sig = &trusted_light_block.signed_header.commit.signatures[i];
            let target_sig = &target_light_block.signed_header.commit.signatures[j];

            if trusted_sig.is_commit()
                && target_sig.is_commit()
                && trusted_sig.validator_address() == target_sig.validator_address()
            {
                validator_commit_intersection.insert(trusted_sig.validator_address().unwrap());
            }
        }
    }

    // Construct the validator bitmap.
    let mut validator_bitmap = [false; 256];
    for (i, validator) in trusted_light_block
        .validators
        .validators()
        .iter()
        .enumerate()
    {
        if validator_commit_intersection.contains(&validator.address) {
            validator_bitmap[i] = true;
        }
    }

    // Convert the validator bitmap to a U256.
    convert_bitmap_to_u256(validator_bitmap)
}

fn main() {
    // Read in the proof inputs. Note: Use a slice, as bincode is unable to deserialize protobuf.
    let proof_inputs_vec = sp1_zkvm::io::read_vec();
    let proof_inputs = serde_cbor::from_slice(&proof_inputs_vec).unwrap();

    let ProofInputs {
        trusted_light_block,
        target_light_block,
        headers,
    } = proof_inputs;

    let verdict = get_header_update_verdict(&trusted_light_block, &target_light_block);

    // If the Verdict is not Success, panic.
    match verdict {
        Verdict::Success => (),
        Verdict::NotEnoughTrust(voting_power_tally) => {
            panic!(
                "Not enough trust in the trusted header, voting power tally: {:?}",
                voting_power_tally
            );
        }
        Verdict::Invalid(err) => panic!(
            "Could not verify updating to target_block, error: {:?}",
            err
        ),
    }

    // Compute the data commitment across the range.
    let mut all_headers = Vec::new();
    all_headers.push(trusted_light_block.signed_header.header.clone());
    all_headers.extend(headers);
    all_headers.push(target_light_block.signed_header.header.clone());
    let data_commitment = B256::from_slice(&compute_data_commitment(&all_headers));

    // Get the commitment to the validator bitmap.
    let validator_bitmap_u256 =
        get_validator_bitmap_commitment(&trusted_light_block, &target_light_block);

    // ABI encode the proof outputs to bytes and commit them to the zkVM.
    let trusted_header_hash =
        B256::from_slice(trusted_light_block.signed_header.header.hash().as_bytes());
    let target_header_hash =
        B256::from_slice(target_light_block.signed_header.header.hash().as_bytes());
    let proof_outputs = ProofOutputs::abi_encode(&(
        trusted_header_hash,
        target_header_hash,
        data_commitment,
        trusted_light_block.signed_header.header.height.value(),
        target_light_block.signed_header.header.height.value(),
        validator_bitmap_u256,
    ));
    sp1_zkvm::io::commit_slice(&proof_outputs);
}
