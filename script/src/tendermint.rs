#![allow(dead_code)]
use crate::types::*;

use anyhow::Context;
use reqwest::Client;
use subtle_encoding::hex;
use tendermint::validator::Info;

use std::env;
use std::sync::Arc;

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
pub const DEFAULT_TENDERMINT_RPC_TIMEOUT_SECS: u64 = 20;

/// The default concurrency for Tendermint RPC requests.
pub const DEFAULT_TENDERMINT_RPC_CONCURRENCY: usize = 25;

/// The default sleep duration for Tendermint RPC requests in milliseconds.
pub const DEFAULT_TENDERMINT_RPC_SLEEP_MS: u64 = 1250;

/// The maximum number of failures allowed when t
pub const DEFAULT_FAILURES_ALLOWED: u32 = 5;

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

    /// Fetches the peer ID from the Tendermint node.
    pub async fn fetch_peer_id(&self) -> anyhow::Result<[u8; 20]> {
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
    pub async fn fetch_block_by_hash(&self, hash: &[u8]) -> anyhow::Result<BlockResponse> {
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

    /// Fetches the block by its height.
    pub async fn fetch_block_by_height(&self, height: u64) -> anyhow::Result<BlockResponse> {
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
    pub async fn fetch_latest_commit(&self) -> anyhow::Result<CommitResponse> {
        let url = format!("{}/commit", self.url);

        self.client
            .get(url)
            .send()
            .await
            .context("Failed to call latest commit endpoint")?
            .json::<CommitResponse>()
            .await
            .context("Failed to parse latest commit response")
    }

    /// Fetches a commit for a specific block height.
    pub async fn fetch_commit(&self, block_height: u64) -> anyhow::Result<CommitResponse> {
        let url = format!("{}/commit", self.url);

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
    pub async fn fetch_validators(&self, block_height: u64) -> anyhow::Result<Vec<Info>> {
        let url = format!("{}/validators", self.url);

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
}
