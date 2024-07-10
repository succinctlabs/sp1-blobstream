#![allow(dead_code)]
use crate::types::*;
use alloy::primitives::B256;
use log::debug;
use reqwest::Client;
use std::{collections::HashMap, env, error::Error};
use subtle_encoding::hex;
use tendermint::block::Commit;
use tendermint::validator::Set as TendermintValidatorSet;
use tendermint::{
    block::signed_header::SignedHeader,
    node::Id,
    validator::{Info, Set},
};
use tendermint_light_client_verifier::types::{LightBlock, ValidatorSet};

pub struct TendermintRPCClient {
    url: String,
}

impl Default for TendermintRPCClient {
    fn default() -> Self {
        TendermintRPCClient {
            url: env::var("TENDERMINT_RPC_URL").expect("TENDERMINT_RPC_URL not set"),
        }
    }
}

impl TendermintRPCClient {
    pub fn new(url: String) -> Self {
        TendermintRPCClient { url }
    }

    // Search to find the greatest block number to request.
    pub async fn find_block_to_request(&mut self, start_block: u64, max_end_block: u64) -> u64 {
        let mut curr_end_block = max_end_block;
        loop {
            if curr_end_block - start_block == 1 {
                return curr_end_block;
            }
            let start_block_validators = self.fetch_validators(start_block).await.unwrap();
            let start_validator_set = Set::new(start_block_validators, None);
            let target_block_validators = self.fetch_validators(curr_end_block).await.unwrap();
            let target_validator_set = Set::new(target_block_validators, None);
            let target_block_commit = self.fetch_commit(curr_end_block).await.unwrap();
            if Self::is_valid_skip(
                start_validator_set,
                target_validator_set,
                target_block_commit.result.signed_header.commit,
            ) {
                return curr_end_block;
            }
            let mid_block = (curr_end_block + start_block) / 2;
            curr_end_block = mid_block;
        }
    }

    /// Fetches all light blocks for the given range of block heights. Inclusive of start and end.
    pub async fn fetch_light_blocks_in_range(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> Vec<LightBlock> {
        let peer_id = self.fetch_peer_id().await.unwrap();
        let batch_size = 25;
        let mut blocks = Vec::new();
        debug!(
            "Fetching light blocks in range: {} to {}",
            start_height, end_height
        );

        for batch_start in (start_height..=end_height).step_by(batch_size) {
            let batch_end = std::cmp::min(batch_start + (batch_size as u64) - 1, end_height);
            let mut handles = Vec::new();

            for height in batch_start..=batch_end {
                let fetch_light_block =
                    async move { self.fetch_light_block(height, peer_id).await.unwrap() };
                handles.push(fetch_light_block);
            }

            // Join all the futures in the current batch
            let batch_blocks = futures::future::join_all(handles).await;
            blocks.extend(batch_blocks);
        }

        debug!("Finished fetching light blocks!");
        blocks
    }

    /// Retrieves light blocks for the trusted and target block heights.
    pub async fn get_light_blocks(
        &self,
        trusted_block_height: u64,
        target_block_height: u64,
    ) -> (LightBlock, LightBlock) {
        let peer_id = self.fetch_peer_id().await.unwrap();

        let trusted_light_block = self
            .fetch_light_block(trusted_block_height, peer_id)
            .await
            .expect("Failed to generate light block 1");
        let target_light_block = self
            .fetch_light_block(target_block_height, peer_id)
            .await
            .expect("Failed to generate light block 2");
        (trusted_light_block, target_light_block)
    }

    /// Retrieves the latest block height from the Tendermint node.
    pub async fn get_latest_block_height(&self) -> u64 {
        let latest_commit = self.fetch_latest_commit().await.unwrap();
        latest_commit.result.signed_header.header.height.value()
    }

    /// Retrieves the block height from a given block hash.
    pub async fn get_block_height_from_hash(&self, hash: &[u8]) -> u64 {
        let block = self.fetch_block_by_hash(hash).await.unwrap();
        block.result.block.header.height.value()
    }

    /// Sorts the signatures in the signed header based on the descending order of validators' power.
    fn sort_signatures_by_validators_power_desc(
        &self,
        signed_header: &mut SignedHeader,
        validators_set: &ValidatorSet,
    ) {
        let validator_powers: HashMap<_, _> = validators_set
            .validators()
            .iter()
            .map(|v| (v.address, v.power()))
            .collect();

        signed_header.commit.signatures.sort_by(|a, b| {
            let power_a = a
                .validator_address()
                .and_then(|addr| validator_powers.get(&addr))
                .unwrap_or(&0);
            let power_b = b
                .validator_address()
                .and_then(|addr| validator_powers.get(&addr))
                .unwrap_or(&0);
            power_b.cmp(power_a)
        });
    }

    /// Fetches the peer ID from the Tendermint node.
    async fn fetch_peer_id(&self) -> Result<[u8; 20], Box<dyn Error>> {
        let client = Client::new();
        let fetch_peer_id_url = format!("{}/status", self.url);

        let response: PeerIdResponse = client
            .get(fetch_peer_id_url)
            .send()
            .await?
            .json::<PeerIdResponse>()
            .await?;

        Ok(hex::decode(response.result.node_info.id)
            .unwrap()
            .try_into()
            .unwrap())
    }

    /// Fetches a block by its hash.
    async fn fetch_block_by_hash(&self, hash: &[u8]) -> Result<BlockResponse, Box<dyn Error>> {
        let client = Client::new();
        let block_by_hash_url = format!(
            "{}/block_by_hash?hash=0x{}",
            self.url,
            String::from_utf8(hex::encode(hash)).unwrap()
        );
        let response: BlockResponse = client
            .get(block_by_hash_url)
            .send()
            .await?
            .json::<BlockResponse>()
            .await?;
        Ok(response)
    }

    /// Fetches a light block by its hash.
    async fn get_light_block_by_hash(&self, hash: &[u8]) -> LightBlock {
        let block = self.fetch_block_by_hash(hash).await.unwrap();
        let peer_id = self.fetch_peer_id().await.unwrap();
        self.fetch_light_block(
            block.result.block.header.height.value(),
            hex::decode(peer_id).unwrap().try_into().unwrap(),
        )
        .await
        .unwrap()
    }

    /// Fetches the latest commit from the Tendermint node.
    async fn fetch_latest_commit(&self) -> Result<CommitResponse, Box<dyn Error>> {
        let url = format!("{}/commit", self.url);
        let client = Client::new();

        let response: CommitResponse = client
            .get(url)
            .send()
            .await?
            .json::<CommitResponse>()
            .await?;
        Ok(response)
    }

    /// Fetches a commit for a specific block height.
    async fn fetch_commit(&self, block_height: u64) -> Result<CommitResponse, Box<dyn Error>> {
        let url = format!("{}/{}", self.url, "commit");

        let client = Client::new();

        let response: CommitResponse = client
            .get(url)
            .query(&[
                ("height", block_height.to_string().as_str()),
                ("per_page", "100"), // helpful only when fetching validators
            ])
            .send()
            .await?
            .json::<CommitResponse>()
            .await?;
        Ok(response)
    }

    /// Fetches validators for a specific block height.
    async fn fetch_validators(&self, block_height: u64) -> Result<Vec<Info>, Box<dyn Error>> {
        let url = format!("{}/{}", self.url, "validators");

        let client = Client::new();
        let mut validators = vec![];
        let mut collected_validators = 0;
        let mut page_index = 1;
        loop {
            let response = client
                .get(&url)
                .query(&[
                    ("height", block_height.to_string().as_str()),
                    ("per_page", "100"),
                    ("page", page_index.to_string().as_str()),
                ])
                .send()
                .await?
                .json::<ValidatorSetResponse>()
                .await?;
            let block_validator_set: BlockValidatorSet = response.result;
            validators.extend(block_validator_set.validators);
            collected_validators += block_validator_set.count.parse::<i32>().unwrap();

            if collected_validators >= block_validator_set.total.parse::<i32>().unwrap() {
                break;
            }
            page_index += 1;
        }

        Ok(validators)
    }

    /// Fetches a light block for a specific block height and peer ID.
    async fn fetch_light_block(
        &self,
        block_height: u64,
        peer_id: [u8; 20],
    ) -> Result<LightBlock, Box<dyn Error>> {
        let commit_response = self.fetch_commit(block_height).await?;
        let mut signed_header = commit_response.result.signed_header;

        let validator_response = self.fetch_validators(block_height).await?;

        let validators = Set::new(validator_response, None);

        let next_validator_response = self.fetch_validators(block_height + 1).await?;
        let next_validators = Set::new(next_validator_response, None);

        self.sort_signatures_by_validators_power_desc(&mut signed_header, &validators);
        Ok(LightBlock::new(
            signed_header,
            validators,
            next_validators,
            Id::new(peer_id),
        ))
    }

    /// Determines if a valid skip is possible between start_block and target_block.
    pub fn is_valid_skip(
        start_validator_set: TendermintValidatorSet,
        target_validator_set: TendermintValidatorSet,
        target_block_commit: Commit,
    ) -> bool {
        let threshold = 1_f64 / 3_f64;
        let mut shared_voting_power = 0_u64;
        let target_block_total_voting_power = target_validator_set.total_voting_power().value();
        let start_block_validators = start_validator_set.validators();
        let mut start_block_idx = 0;
        let start_block_num_validators = start_block_validators.len();

        // Exit if we have already reached the threshold
        while (target_block_total_voting_power as f64) * threshold > shared_voting_power as f64
            && start_block_idx < start_block_num_validators
        {
            if let Some(target_block_validator) =
                target_validator_set.validator(start_block_validators[start_block_idx].address)
            {
                // Confirm that the validator has signed on target_block.
                for sig in target_block_commit.signatures.iter() {
                    if let Some(validator_address) = sig.validator_address() {
                        if validator_address == target_block_validator.address {
                            // Add the shared voting power to the validator
                            shared_voting_power += target_block_validator.power.value();
                        }
                    }
                }
            }
            start_block_idx += 1;
        }

        (target_block_total_voting_power as f64) * threshold <= shared_voting_power as f64
    }

    /// Fetches a header hash for a specific block height.
    pub async fn fetch_header_hash(&self, block_height: u64) -> B256 {
        let peer_id = self.fetch_peer_id().await.unwrap();
        let light_block = self.fetch_light_block(block_height, peer_id).await.unwrap();

        B256::from_slice(light_block.signed_header.header.hash().as_bytes())
    }
}
