#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::{sol, SolType};
use core::time::Duration;
use tendermint_light_client_verifier::{
    options::Options, types::LightBlock, ProdVerifier, Verdict, Verifier,
};

use sha2::Sha256;
use tendermint::merkle::simple_hash_from_byte_vectors;

type DataRootTuple = sol! {
    tuple(uint64, bytes32)
};

// Cycle Tracker Counts: Naive (5/10 @ 2PM PT) for block 10 -> block 50
// # 95M reading inputs
// # 5M for verify
// # 37k for hash header (could be cheaper by opening merkle commitments) -> 36M
// # 100k for data commitment computation -> 2.5M

/// Get the verdict for the header update from trusted_block to target_block.
fn get_header_update_verdict(trusted_block: &LightBlock, target_block: &LightBlock) -> Verdict {
    let opt = Options {
        trust_threshold: Default::default(),
        // 2 week trusting period.
        trusting_period: Duration::from_secs(14 * 24 * 60 * 60),
        clock_drift: Default::default(),
    };

    let vp = ProdVerifier::default();
    let verify_time = target_block.time() + Duration::from_secs(20);
    vp.verify_update_header(
        target_block.as_untrusted_state(),
        trusted_block.as_trusted_state(),
        &opt,
        verify_time.unwrap(),
    )
}

/// Compute the data commitment for the given light blocks.
fn compute_data_commitment(light_blocks: &[LightBlock]) -> [u8; 32] {
    let mut encoded_data_root_tuples: Vec<Vec<u8>> = Vec::new();
    for i in 1..light_blocks.len() {
        println!("cycle-tracker-start: header_hash");
        let prev_light_block = &light_blocks[i - 1];
        let curr_light_block = &light_blocks[i];
        // Checks that chain of headers is well-formed.
        if prev_light_block.signed_header.header.hash()
            != curr_light_block
                .signed_header
                .header
                .last_block_id
                .unwrap()
                .hash
        {
            panic!("invalid light block");
        }
        println!("cycle-tracker-end: header_hash");

        println!("cycle-tracker-start: data_hash");
        let data_hash: [u8; 32] = prev_light_block
            .signed_header
            .header
            .data_hash
            .unwrap()
            .as_bytes()
            .try_into()
            .unwrap();
        println!("cycle-tracker-end: data_hash");
        let data_root_tuple =
            DataRootTuple::abi_encode(&(prev_light_block.height().value(), data_hash));
        encoded_data_root_tuples.push(data_root_tuple);
    }

    println!("cycle-tracker-start: data_commitment");
    let data_commitment = simple_hash_from_byte_vectors::<Sha256>(&encoded_data_root_tuples);
    println!("cycle-tracker-end: data_commitment");

    data_commitment
}

fn main() {
    println!("cycle-tracker-start: reading inputs");
    let trusted_block_height = sp1_zkvm::io::read::<u64>();
    let target_block_height = sp1_zkvm::io::read::<u64>();
    // TODO: We should probably just read in the LightBlock's for the start and end and the headers
    // in between.
    // TODO: Make this into a struct that we can deserialize easily with serde_cbor.
    let mut encoded_light_blocks: Vec<Vec<u8>> = Vec::new();
    for _ in 0..=(target_block_height - trusted_block_height) {
        let encoded_light_block = sp1_zkvm::io::read_vec();
        encoded_light_blocks.push(encoded_light_block)
    }

    // Decode the light blocks.
    let mut light_blocks: Vec<LightBlock> = Vec::new();
    for header in encoded_light_blocks {
        let light_block: LightBlock = serde_cbor::from_slice(&header).unwrap();
        light_blocks.push(light_block);
    }

    println!("cycle-tracker-end: reading inputs");

    let trusted_block = &light_blocks[0];
    let target_block = &light_blocks[(target_block_height - trusted_block_height) as usize];

    println!("cycle-tracker-start: verify");
    let verdict = get_header_update_verdict(trusted_block, target_block);

    match verdict {
        Verdict::Success => {
            println!("success");
        }
        v => panic!("Could not verify updating to target_block, error: {:?}", v),
    }
    println!("cycle-tracker-end: verify");

    let data_commitment = compute_data_commitment(&light_blocks);

    // Now that we have verified our proof, we commit the header hashes to the zkVM to expose
    // them as public values.
    let trusted_header_hash = trusted_block.signed_header.header.hash();
    let target_header_hash = target_block.signed_header.header.hash();

    sp1_zkvm::io::commit_slice(trusted_header_hash.as_bytes());
    sp1_zkvm::io::commit_slice(target_header_hash.as_bytes());
    sp1_zkvm::io::commit_slice(&data_commitment);
}
