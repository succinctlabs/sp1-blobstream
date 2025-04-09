use alloy::primitives::B256;
use anyhow::Context;
use futures::stream;
use futures::stream::FuturesOrdered;
use futures::StreamExt;
use sp1_blobstream_primitives::types::ProofInputs;
use std::collections::HashMap;
use tendermint::block::{Commit, Header};
use tendermint::validator::Set as TendermintValidatorSet;
use tendermint::Block;
use tendermint::{block::signed_header::SignedHeader, node::Id, validator::Set};
use tendermint_light_client_verifier::types::{LightBlock, ValidatorSet};

mod retry;
pub use retry::{Retry, RetryFuture};

use crate::tendermint::{
    TendermintRPCClient, DEFAULT_FAILURES_ALLOWED, DEFAULT_TENDERMINT_RPC_CONCURRENCY,
    DEFAULT_TENDERMINT_RPC_SLEEP_MS,
};

pub async fn fetch_input_for_blobstream_proof(
    client: &TendermintRPCClient,
    trusted_block_height: u64,
    target_block_height: u64,
) -> anyhow::Result<ProofInputs> {
    let (trusted_light_block, target_light_block) =
        get_light_blocks(client, trusted_block_height, target_block_height).await?;

    let headers =
        get_headers_in_range(client, trusted_block_height + 1, target_block_height - 1).await?;

    Ok(ProofInputs {
        trusted_light_block,
        target_light_block,
        headers,
    })
}

/// Search to find the end block to request based on the start block.
///
/// Ideally, the end block is the first block that is a multiple of the block update interval that
/// is greater than the start block.
///
/// However, if this block does not meet the consensus threshold for the transition (validated with
/// `is_valid_skip`), then use the first block that does meet the threshold.
pub async fn find_block_to_request(
    client: &TendermintRPCClient,
    start_block: u64,
    block_update_interval: u64,
    data_commitment_max: u64,
) -> anyhow::Result<Option<u64>> {
    // Get the head of the tendermint chain.
    let latest_tendermint_block_nb = get_latest_block_height(client).await?;
    tracing::debug!("Latest tendermint block: {}", latest_tendermint_block_nb);

    // Subtract 1 block to ensure the block is stable.
    let latest_stable_tendermint_block = latest_tendermint_block_nb - 1;

    let block_to_request = std::cmp::min(
        latest_stable_tendermint_block,
        data_commitment_max + start_block,
    );

    let ideal_block_to_request = block_to_request - (block_to_request % block_update_interval);

    if ideal_block_to_request <= start_block {
        return Ok(None);
    }

    // If the consensus threshold is not met with the transition from the start block to the ideal block,
    // the first block to match the threshold will be used as the block to request.
    let mut curr_end_block = ideal_block_to_request;
    loop {
        if curr_end_block - start_block == 1 {
            return Ok(Some(curr_end_block));
        }
        let start_block_validators = client.fetch_validators(start_block).await?;
        let start_validator_set = Set::new(start_block_validators, None);
        let target_block_validators = client.fetch_validators(curr_end_block).await?;
        let target_validator_set = Set::new(target_block_validators, None);
        let target_block_commit = client.fetch_commit(curr_end_block).await?;

        if is_valid_skip(
            start_validator_set,
            target_validator_set,
            target_block_commit.result.signed_header.commit,
        ) {
            return Ok(Some(curr_end_block));
        }

        let mid_block = (curr_end_block + start_block) / 2;
        curr_end_block = mid_block;
    }
}

/// Retrieves light blocks for the trusted and target block heights.
pub async fn get_light_blocks(
    client: &TendermintRPCClient,
    trusted_block_height: u64,
    target_block_height: u64,
) -> anyhow::Result<(LightBlock, LightBlock)> {
    let peer_id = client.fetch_peer_id().await?;

    let trusted_light_block = fetch_light_block(client, trusted_block_height, peer_id)
        .await
        .context("Failed to fetch trusted light block")?;

    let target_light_block = fetch_light_block(client, target_block_height, peer_id)
        .await
        .context("Failed to fetch target light block")?;

    Ok((trusted_light_block, target_light_block))
}

/// Retrieves the block from the Tendermint node.
pub async fn get_block(client: &TendermintRPCClient, height: u64) -> anyhow::Result<Block> {
    let block = client.fetch_block_by_height(height).await?;
    Ok(block.result.block)
}

/// Retrieves the headers for the given range of block heights. Inclusive of start and end.
pub async fn get_headers_in_range(
    client: &TendermintRPCClient,
    start_height: u64,
    end_height: u64,
) -> anyhow::Result<Vec<Header>> {
    let mut batch_headers = stream::iter(start_height..end_height + 1)
        .map(|height| async move {
            get_block(client, height)
                .await
                .expect("Failed to fetch block")
                .header
        })
        .buffer_unordered(100)
        .collect::<Vec<_>>()
        .await;

    batch_headers.sort_by_key(|header| header.height.value());

    Ok(batch_headers)

    // let mut failures: u32 = 0;
    // let mut next_batch_start = start_height;

    // while next_batch_start <= end_height {
    //     if failures == DEFAULT_FAILURES_ALLOWED {
    //         return Err(anyhow::anyhow!(
    //             "Got too many failures attempting to fetch block headers."
    //         ));
    //     }

    //     // Top of the range is non-inclusive so max out at `end_height + 1`.
    //     let batch_end = std::cmp::min(
    //         next_batch_start + DEFAULT_TENDERMINT_RPC_CONCURRENCY as u64,
    //         end_height + 1,
    //     );

    //     tracing::info!(
    //         "Fetching headers from {} to {}",
    //         next_batch_start,
    //         batch_end - 1
    //     );

    //     // Chunk the range into batches of DEFAULT_TENDERMINT_RPC_CONCURRENCY.
    //     let batch_headers: Vec<anyhow::Result<Header>> = (next_batch_start..batch_end)
    //         .map(|height| async move { Ok(get_block(client, height).await?.header) })
    //         .collect::<FuturesOrdered<_>>()
    //         .collect::<Vec<_>>()
    //         .await;

    //     // Check if there are any errors.
    //     let first_err = batch_headers.iter().position(|h| h.is_err());

    //     if let Some(err) = first_err {
    //         // If there is at least one valid result, then it doesn't count as a failure.
    //         if err == 0 {
    //             failures += 1;
    //         }

    //         tracing::debug!(
    //             "Got errors fetching headers, successful header count: {}",
    //             err
    //         );

    //         // Bump the start of the next batch by the number of successful headers in this batch.
    //         next_batch_start += err as u64;

    //         // Extend the headers with the headers that were not err.
    //         headers.extend(batch_headers.into_iter().take(err).map(Result::unwrap));
    //     } else {
    //         // There are no errors, so reset the failure count to 0.
    //         failures = 0;

    //         // The next start should be the (not included) end of this batch.
    //         next_batch_start = batch_end;

    //         // Extend the headers with all of the headers in this batch.
    //         headers.extend(batch_headers.into_iter().map(Result::unwrap));
    //     }

    //     // Sleep for 1.25 seconds to avoid rate limiting.
    //     tokio::time::sleep(DEFAULT_TENDERMINT_RPC_SLEEP_MS * 2_u32.pow(failures)).await;
    // }

    // Ok(headers)
}

/// Retrieves the latest block height from the Tendermint node.
pub async fn get_latest_block_height(client: &TendermintRPCClient) -> anyhow::Result<u64> {
    let latest_commit = client
        .fetch_latest_commit()
        .await
        .context("Failed to fetch latest commit for black hash")?;

    Ok(latest_commit.result.signed_header.header.height.value())
}

/// Retrieves the block height from a given block hash.
pub async fn get_block_height_from_hash(
    client: &TendermintRPCClient,
    hash: &[u8],
) -> anyhow::Result<u64> {
    let block = client
        .fetch_block_by_hash(hash)
        .await
        .context("Failed to fetch block by hash")?;

    Ok(block.result.block.header.height.value())
}

/// Sorts the signatures in the signed header based on the descending order of validators' power.
fn sort_signatures_by_validators_power_desc(
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

/// Fetches a light block for a specific block height and peer ID.
async fn fetch_light_block(
    client: &TendermintRPCClient,
    block_height: u64,
    peer_id: [u8; 20],
) -> anyhow::Result<LightBlock> {
    let commit_response = client.fetch_commit(block_height).await?;
    let mut signed_header = commit_response.result.signed_header;

    let validator_response = client.fetch_validators(block_height).await?;

    let validators = Set::new(validator_response, None);

    let next_validator_response = client.fetch_validators(block_height + 1).await?;
    let next_validators = Set::new(next_validator_response, None);

    sort_signatures_by_validators_power_desc(&mut signed_header, &validators);

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

    // Exit if the threshold is met.
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
pub async fn fetch_header_hash(
    client: &TendermintRPCClient,
    block_height: u64,
) -> anyhow::Result<B256> {
    let peer_id = client
        .fetch_peer_id()
        .await
        .context("Failed to fetch peer ID")?;

    let light_block = fetch_light_block(client, block_height, peer_id)
        .await
        .context("Failed to fetch light block")?;

    Ok(B256::from_slice(
        light_block.signed_header.header.hash().as_bytes(),
    ))
}

/// Implement a signer that may or may not actually be set.
///
/// This is useful to dynamically choose to use the KMS relayer in the operator,
/// without having to change the actual provider type, since the provider is generic over a signer.
pub mod signer {
    use alloy::{
        consensus::{TxEnvelope, TypedTransaction},
        network::{Network, NetworkWallet},
        primitives::Address,
    };

    /// A signer than panics if called and not set.
    #[derive(Clone, Debug)]
    pub struct MaybeWallet<W>(Option<W>);

    impl<W> MaybeWallet<W> {
        pub fn new(signer: Option<W>) -> Self {
            Self(signer)
        }
    }

    impl<W, N> NetworkWallet<N> for MaybeWallet<W>
    where
        W: NetworkWallet<N>,
        N: Network<UnsignedTx = TypedTransaction, TxEnvelope = TxEnvelope>,
    {
        fn default_signer_address(&self) -> Address {
            self.0
                .as_ref()
                .expect("No signer set")
                .default_signer_address()
        }

        fn has_signer_for(&self, address: &Address) -> bool {
            self.0
                .as_ref()
                .expect("No signer set")
                .has_signer_for(address)
        }

        fn signer_addresses(&self) -> impl Iterator<Item = Address> {
            self.0.as_ref().expect("No signer set").signer_addresses()
        }

        #[doc(alias = "sign_tx_from")]
        async fn sign_transaction_from(
            &self,
            sender: Address,
            tx: TypedTransaction,
        ) -> alloy::signers::Result<TxEnvelope> {
            self.0
                .as_ref()
                .expect("No signer set")
                .sign_transaction_from(sender, tx)
                .await
        }
    }
}
