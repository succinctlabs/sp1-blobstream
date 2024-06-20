#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy::primitives::B256;
use alloy::sol;
use alloy::sol_types::SolType;
use core::time::Duration;
use primitives::types::ProofInputs;
use primitives::types::ProofOutputs;
use sha2::Sha256;
use tendermint::{block::Header, merkle::simple_hash_from_byte_vectors};
use tendermint_light_client_verifier::{
    options::Options, types::LightBlock, ProdVerifier, Verdict, Verifier,
};
type DataRootTuple = sol! {
    tuple(uint64, bytes32)
};

/// Get the verdict for the header update from trusted_block to target_block.
fn get_header_update_verdict(trusted_block: &LightBlock, target_block: &LightBlock) -> Verdict {
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

/// Compute the data commitment for the given headers.
fn compute_data_commitment(headers: &[Header]) -> [u8; 32] {
    let mut encoded_data_root_tuples: Vec<Vec<u8>> = Vec::new();
    for i in 1..headers.len() {
        let prev_header = &headers[i - 1];
        let curr_header = &headers[i];
        // Checks that chain of headers is well-formed.
        if prev_header.hash() != curr_header.last_block_id.unwrap().hash {
            panic!("invalid header");
        }

        let data_hash: [u8; 32] = prev_header
            .data_hash
            .unwrap()
            .as_bytes()
            .try_into()
            .unwrap();

        let data_root_tuple = DataRootTuple::abi_encode(&(prev_header.height.value(), data_hash));
        encoded_data_root_tuples.push(data_root_tuple);
    }

    simple_hash_from_byte_vectors::<Sha256>(&encoded_data_root_tuples)
}

fn main() {
    let proof_inputs_vec = sp1_zkvm::io::read_vec();
    let proof_inputs = serde_cbor::from_slice(&proof_inputs_vec).unwrap();

    let ProofInputs {
        trusted_block_height,
        target_block_height,
        trusted_light_block,
        target_light_block,
        headers,
    } = proof_inputs;

    let verdict = get_header_update_verdict(&trusted_light_block, &target_light_block);

    match verdict {
        Verdict::Success => {
            println!("success");
        }
        v => panic!("Could not verify updating to target_block, error: {:?}", v),
    }

    let mut all_headers = Vec::new();
    all_headers.push(trusted_light_block.signed_header.header.clone());
    all_headers.extend(headers);
    all_headers.push(target_light_block.signed_header.header.clone());

    let data_commitment = B256::from_slice(&compute_data_commitment(&all_headers));

    // Now that we have verified our proof, we commit the header hashes to the zkVM to expose
    // them as public values.
    let trusted_header_hash =
        B256::from_slice(trusted_light_block.signed_header.header.hash().as_bytes());
    let target_header_hash =
        B256::from_slice(target_light_block.signed_header.header.hash().as_bytes());

    // ABI-Encode Proof Outputs
    let proof_outputs = ProofOutputs::abi_encode(&(
        trusted_header_hash,
        target_header_hash,
        data_commitment,
        trusted_block_height,
        target_block_height,
    ));
    sp1_zkvm::io::commit_slice(&proof_outputs);
}
