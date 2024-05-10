#![no_main]
sp1_zkvm::entrypoint!(main);

use core::time::Duration;
use tendermint_light_client_verifier::{
    options::Options, types::LightBlock, ProdVerifier, Verdict, Verifier,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataRootTuple {
    pub height: u64,
    pub data_root: Vec<u8>,
}

const MAX_NUM_HEADERS: usize = 32;
fn main() {
    // Read in 32 LightBlocks in the form.
    // TODO: We should probably just read in the LightBlock's for the start and end and the headers
    // in between.
    // TODO: Make this into a struct that we can deserialize easily with serde_cbor.
    let mut encoded_light_blocks: Vec<Vec<u8>> = Vec::new();
    for i in 0..MAX_NUM_HEADERS {
        let encoded_light_block = sp1_zkvm::io::read_vec();
        encoded_light_blocks.push(encoded_light_block)
    }

    // Decode the light blocks.
    let mut light_blocks: Vec<LightBlock>;
    for header in encoded {
        let light_block: LightBlock = serde_cbor::from_slice(&header).unwrap();
        light_blocks.push(light_block);
    }

    let vp = ProdVerifier::default();
    let opt = Options {
        trust_threshold: Default::default(),
        // 2 week trusting period.
        trusting_period: Duration::from_secs(14 * 24 * 60 * 60),
        clock_drift: Default::default(),
    };
    let verify_time = light_blocks[MAX_NUM_HEADERS - 1].time() + Duration::from_secs(20);
    let verdict = vp.verify_update_header(
        light_blocks[MAX_NUM_HEADERS - 1].as_untrusted_state(),
        light_blocks[0].as_trusted_state(),
        &opt,
        verify_time.unwrap(),
    );

    let data_root_tuples: Vec<DataRootTuple>;
    for light_block in light_blocks {
        if !(light_block.signed_header.header.hash()
            == light_block.signed_header.header.last_block_id.unwrap().hash)
        {
            panic("invalid light block");
        }

        data_root_tuples.push(DataRootTuple {
            height: light_block.height().value(),
            data_root: light_block
                .signed_header
                .header
                .data_hash
                .unwrap()
                .as_bytes(),
        });

        // We need to construct dataRootTuples: https://github.com/celestiaorg/celestia-core/blob/6933af1ead0ddf4a8c7516690e3674c6cdfa7bd8/rpc/core/blocks.go#L325-L334

        // light_block.signed_header.header.data_hash
        // light_blocks[i].signed_header.header.data_hash
    }

    // take data root tuples and hash them into dataCommitment
    /*
    func hashDataRootTuples(tuples []DataRootTuple) ([]byte, error) {
        dataRootEncodedTuples := make([][]byte, 0, len(tuples))
        for _, tuple := range tuples {
            encodedTuple, err := EncodeDataRootTuple(
                tuple.height,
                tuple.dataRoot,
            )
            if err != nil {
                return nil, err
            }
            dataRootEncodedTuples = append(dataRootEncodedTuples, encodedTuple)
        }
        root := merkle.HashFromByteSlices(dataRootEncodedTuples)
        return root, nil
    }


    */

    // light_blocks[0].signed_header.header.hash() == light_blocks[0].signed_header.header.last_block_id.unwrap().hash

    match verdict {
        Verdict::Success => {
            println!("success");
        }
        v => panic!("expected success, got: {:?}", v),
    }

    // Now that we have verified our proof, we commit the header hashes to the zkVM to expose
    // them as public values.
    let header_hash_1 = light_block_1.signed_header.header.hash();
    let header_hash_2 = light_block_2.signed_header.header.hash();

    sp1_zkvm::io::commit_slice(header_hash_1.as_bytes());
    sp1_zkvm::io::commit_slice(header_hash_2.as_bytes());
}
