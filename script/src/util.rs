#![allow(dead_code)]
use crate::types::*;
use alloy::primitives::B256;
use anyhow::Context;
use futures::stream::FuturesOrdered;
use futures::StreamExt;
use reqwest::Client;
use sp1_blobstream_primitives::types::ProofInputs;
use std::sync::Arc;
use std::{collections::HashMap, env};
use subtle_encoding::hex;
use tendermint::block::{Commit, Header};
use tendermint::validator::Set as TendermintValidatorSet;
use tendermint::Block;
use tendermint::{
    block::signed_header::SignedHeader,
    node::Id,
    validator::{Info, Set},
};
use tendermint_light_client_verifier::types::{LightBlock, ValidatorSet};

pub struct TendermintRPCClient {
    url: String,
    client: Arc<Client>,
}

impl Default for TendermintRPCClient {
    fn default() -> Self {
        let url = env::var("TENDERMINT_RPC_URL").expect("TENDERMINT_RPC_URL not set");
        Self::new(url)
    }
}

/// The default timeout for Tendermint RPC requests in seconds.
const DEFAULT_TENDERMINT_RPC_TIMEOUT_SECS: u64 = 20;

/// The default concurrency for Tendermint RPC requests.
const DEFAULT_TENDERMINT_RPC_CONCURRENCY: usize = 50;

/// The default sleep duration for Tendermint RPC requests in milliseconds.
const DEFAULT_TENDERMINT_RPC_SLEEP_MS: u64 = 1250;

/// The maximum number of failures allowed when fetching block headers.
const DEFAULT_TENDERMINT_RPC_MAX_FAILURES: u32 = 5;

impl TendermintRPCClient {
    pub fn new(url: String) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(
                DEFAULT_TENDERMINT_RPC_TIMEOUT_SECS,
            ))
            .build()
            .unwrap();
        TendermintRPCClient {
            url,
            client: Arc::new(client),
        }
    }

    pub async fn fetch_input_for_blobstream_proof(
        &self,
        trusted_block_height: u64,
        target_block_height: u64,
    ) -> anyhow::Result<ProofInputs> {
        let (trusted_light_block, target_light_block) = self
            .get_light_blocks(trusted_block_height, target_block_height)
            .await?;

        let headers = self
            .get_headers_in_range(trusted_block_height + 1, target_block_height - 1)
            .await?;

        Ok(ProofInputs {
            trusted_light_block,
            target_light_block,
            headers,
        })
    }

    // Search to find the greatest block number to request.
    pub async fn find_block_to_request(&self, start_block: u64, max_end_block: u64) -> u64 {
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

    /// Retrieves light blocks for the trusted and target block heights.
    pub async fn get_light_blocks(
        &self,
        trusted_block_height: u64,
        target_block_height: u64,
    ) -> anyhow::Result<(LightBlock, LightBlock)> {
        let peer_id = self.fetch_peer_id().await?;

        let trusted_light_block = self
            .fetch_light_block(trusted_block_height, peer_id)
            .await
            .context("Failed to fetch trusted light block")?;

        let target_light_block = self
            .fetch_light_block(target_block_height, peer_id)
            .await
            .context("Failed to fetch target light block")?;

        Ok((trusted_light_block, target_light_block))
    }

    /// Retrieves the block from the Tendermint node.
    pub async fn get_block(&self, height: u64) -> anyhow::Result<Block> {
        let block = self.fetch_block_by_height(height).await?;
        Ok(block.result.block)
    }

    /// Retrieves the headers for the given range of block heights. Inclusive of start and end.
    pub async fn get_headers_in_range(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> anyhow::Result<Vec<Header>> {
        let mut headers = Vec::with_capacity(((end_height - start_height) + 1) as usize);

        let mut failures: u32 = 0;
        let mut next_batch_start = start_height;

        while next_batch_start <= end_height {
            if failures == DEFAULT_TENDERMINT_RPC_MAX_FAILURES {
                return Err(anyhow::anyhow!(
                    "Got too many failures attempting to fetch block headers."
                ));
            }

            // Top of the range is non-inclusive so max out at `end_height + 1`.
            let batch_end = std::cmp::min(
                next_batch_start + DEFAULT_TENDERMINT_RPC_CONCURRENCY as u64,
                end_height + 1,
            );

            // Chunk the range into batches of DEFAULT_TENDERMINT_RPC_CONCURRENCY.
            let batch_headers: Vec<anyhow::Result<Header>> = (next_batch_start..batch_end)
                .map(|height| async move { Ok(self.get_block(height).await?.header) })
                .collect::<FuturesOrdered<_>>()
                .collect::<Vec<_>>()
                .await;

            // Check if we got any errors.
            let first_err = batch_headers.iter().position(|h| h.is_err());

            if let Some(err) = first_err {
                failures += 1;

                log::error!(
                    "Got error fetching headers, successful header count: {}",
                    err
                );

                // Bump the start of the next batch by the number of successful headers in this batch.
                next_batch_start += err as u64;

                // Extend the headers with the headers that were not err.
                headers.extend(batch_headers.into_iter().take(err).map(Result::unwrap));
            } else {
                // There are no errors, so we reset the failure count to 0.
                failures = 0;

                // The next start should be the (not included) end of this batch.
                next_batch_start = batch_end;

                // Extend the headers with all of the headers in this batch.
                headers.extend(batch_headers.into_iter().map(Result::unwrap));
            }

            // Sleep for 1.25 seconds to avoid rate limiting.
            tokio::time::sleep(std::time::Duration::from_millis(
                DEFAULT_TENDERMINT_RPC_SLEEP_MS * 2_u64.pow(failures),
            ))
            .await;
        }

        Ok(headers)
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
    async fn fetch_peer_id(&self) -> anyhow::Result<[u8; 20]> {
        let fetch_peer_id_url = format!("{}/status", self.url);

        let response: PeerIdResponse = self
            .client
            .get(fetch_peer_id_url)
            .send()
            .await
            .context("Failed to fetch peer ID")?
            .json::<PeerIdResponse>()
            .await
            .context("Failed to parse peer ID response")?;

        Ok(hex::decode(response.result.node_info.id)
            .unwrap()
            .try_into()
            .unwrap())
    }

    /// Fetches a block by its hash.
    async fn fetch_block_by_hash(&self, hash: &[u8]) -> anyhow::Result<BlockResponse> {
        let block_by_hash_url = format!(
            "{}/block_by_hash?hash=0x{}",
            self.url,
            String::from_utf8(hex::encode(hash)).unwrap()
        );

        self.client
            .get(block_by_hash_url)
            .send()
            .await
            .context("Failed to fetch block by hash")?
            .json::<BlockResponse>()
            .await
            .context("Failed to parse block by hash response")
    }

    /// Fetches a light block by its hash.
    async fn get_light_block_by_hash(&self, hash: &[u8]) -> anyhow::Result<LightBlock> {
        log::trace!("Fetching light block by hash: {:?}", hash);

        let block = self.fetch_block_by_hash(hash).await?;
        let peer_id = self.fetch_peer_id().await?;

        self.fetch_light_block(
            block.result.block.header.height.value(),
            hex::decode(peer_id).unwrap().try_into().unwrap(),
        )
        .await
        .context("Failed to fetch light block by hash")
    }

    /// Fetches the block by its height.
    async fn fetch_block_by_height(&self, height: u64) -> anyhow::Result<BlockResponse> {
        let url = format!("{}/block?height={}", self.url, height);

        self.client
            .get(url)
            .send()
            .await
            .context("Failed to fetch block by height")?
            .json::<BlockResponse>()
            .await
            .context("Failed to parse block by height response")
    }

    /// Fetches the latest commit from the Tendermint node.
    async fn fetch_latest_commit(&self) -> anyhow::Result<CommitResponse> {
        let url = format!("{}/commit", self.url);

        Ok(self
            .client
            .get(url)
            .send()
            .await?
            .json::<CommitResponse>()
            .await?)
    }

    /// Fetches a commit for a specific block height.
    async fn fetch_commit(&self, block_height: u64) -> anyhow::Result<CommitResponse> {
        let url = format!("{}/{}", self.url, "commit");

        self.client
            .get(url)
            .query(&[
                ("height", block_height.to_string().as_str()),
                ("per_page", "100"), // helpful only when fetching validators
            ])
            .send()
            .await
            .context("Failed to fetch commit")?
            .json::<CommitResponse>()
            .await
            .context("Failed to parse commit response")
    }

    /// Fetches validators for a specific block height.
    async fn fetch_validators(&self, block_height: u64) -> anyhow::Result<Vec<Info>> {
        let url = format!("{}/{}", self.url, "validators");

        let mut validators = vec![];
        let mut collected_validators = 0;
        let mut page_index = 1;
        loop {
            let response = self
                .client
                .get(&url)
                .query(&[
                    ("height", block_height.to_string().as_str()),
                    ("per_page", "100"),
                    ("page", page_index.to_string().as_str()),
                ])
                .send()
                .await
                .context("Failed to fetch validators")?
                .json::<ValidatorSetResponse>()
                .await
                .context("Failed to parse validators response")?;

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
    ) -> anyhow::Result<LightBlock> {
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
    pub async fn fetch_header_hash(&self, block_height: u64) -> anyhow::Result<B256> {
        let peer_id = self
            .fetch_peer_id()
            .await
            .context("Failed to fetch peer ID")?;

        let light_block = self
            .fetch_light_block(block_height, peer_id)
            .await
            .context("Failed to fetch light block")?;

        Ok(B256::from_slice(
            light_block.signed_header.header.hash().as_bytes(),
        ))
    }
}
