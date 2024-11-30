use alloy::eips::BlockId;
use alloy::network::primitives::HeaderResponse;
use alloy::rpc::types::{BlockTransactionsKind, Filter};
use alloy::sol;
use alloy::sol_types::SolEvent;
use alloy::{
    consensus::BlockHeader,
    network::BlockResponse,
    primitives::{Address, B256},
    providers::{Network, Provider, ProviderBuilder},
    transports::Transport,
};
use anyhow::Result;
use chrono::{TimeZone, Utc};
use clap::Parser;
use futures::StreamExt;
use reqwest::Url;
use std::cmp::Ordering;
use std::env;
use std::str::FromStr;

#[derive(Parser, Debug, Clone)]
#[command(about = "Get transaction costs for an address in a given month")]
pub struct CostScriptArgs {
    #[arg(long)]
    pub from_address: String,
    #[arg(long)]
    pub ethereum_rpc: String,
    #[arg(long)]
    pub base_rpc: String,
    #[arg(long)]
    pub arbitrum_rpc: String,
    #[arg(long)]
    pub month: u32,
    #[arg(long)]
    pub year: i32,
}

sol! {
    event HeadUpdate(uint64 blockNumber, bytes32 headerHash);
}

pub fn get_contract_address(chain_id: u64) -> Option<Address> {
    match chain_id {
        1 => Some(Address::from_str("0x7Cf3876F681Dbb6EdA8f6FfC45D66B996Df08fAe").unwrap()),
        8453 => Some(Address::from_str("0xA83ca7775Bc2889825BcDeDfFa5b758cf69e8794").unwrap()),
        42161 => Some(Address::from_str("0xA83ca7775Bc2889825BcDeDfFa5b758cf69e8794").unwrap()),
        _ => None,
    }
}

#[derive(serde::Serialize, Clone)]
struct RelayTransaction {
    chain_id: u64,
    tx_hash: B256,
    tx_fee_wei: u128,
    from: Address,
    to: Address,
}

async fn get_receipts_for_chain(
    from_addr: Address,
    rpc_url: &str,
    month: u32,
    year: i32,
) -> Result<Vec<RelayTransaction>> {
    let provider = ProviderBuilder::new().on_http(Url::parse(rpc_url).unwrap());
    let chain_id = provider.get_chain_id().await?;

    let to_addr = get_contract_address(chain_id).expect("Chain ID not supported");

    // Get start and end timestamps for the month
    let start = Utc.with_ymd_and_hms(year, month, 1, 0, 0, 0).unwrap();
    let end = if month == 12 {
        Utc.with_ymd_and_hms(year + 1, 1, 1, 0, 0, 0).unwrap()
    } else {
        Utc.with_ymd_and_hms(year, month + 1, 1, 0, 0, 0).unwrap()
    };

    let start_block = find_block_by_timestamp(&provider, start.timestamp() as u64).await?;
    let end_block = find_block_by_timestamp(&provider, end.timestamp() as u64).await?;

    let mut tx_hashes = Vec::new();
    // The maximum number of blocks that Alchemy will return logs for in a single request.
    const ALCHEMY_CHUNK_SIZE: u64 = 100_000;

    let chunks = (start_block.1..=end_block.1)
        .step_by(ALCHEMY_CHUNK_SIZE as usize)
        .map(|chunk_start| {
            let chunk_end = (chunk_start + ALCHEMY_CHUNK_SIZE - 1).min(end_block.1);
            let provider = provider.clone();

            async move {
                let filter = Filter::new()
                    .from_block(chunk_start)
                    .to_block(chunk_end)
                    .address(to_addr)
                    .event_signature(HeadUpdate::SIGNATURE_HASH);
                provider.get_logs(&filter).await
            }
        });

    let mut stream = futures::stream::iter(chunks).buffer_unordered(3);
    while let Some(result) = stream.next().await {
        for log in result? {
            if let Some(tx_hash) = log.transaction_hash {
                tx_hashes.push(tx_hash);
            }
        }
    }

    println!("Collected all transaction hashes for chain {}.", chain_id);

    let mut all_transactions = Vec::new();
    // Get the receipts for the transactions.
    let mut stream = futures::stream::iter(tx_hashes.into_iter().map(|tx_hash| {
        let provider = provider.clone();
        async move { provider.get_transaction_receipt(tx_hash).await }
    }))
    .buffer_unordered(10);

    while let Some(receipt) = stream.next().await {
        if let Ok(Some(receipt)) = receipt {
            all_transactions.push(receipt);
        }
    }

    println!("Collected all receipts for chain {}.", chain_id);

    Ok(all_transactions
        .into_iter()
        .filter(|receipt| receipt.from == from_addr)
        .map(|receipt| RelayTransaction {
            chain_id,
            tx_hash: receipt.transaction_hash,
            tx_fee_wei: receipt.gas_used * receipt.effective_gas_price,
            from: receipt.from,
            to: receipt.to.unwrap_or_default(),
        })
        .collect())
}

#[tokio::main]
async fn main() -> Result<()> {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    env_logger::init();

    let args = CostScriptArgs::parse();

    let from_addr = Address::from_str(&args.from_address).unwrap();

    let (eth_transactions, base_transactions, arbitrum_transactions) = tokio::join!(
        get_receipts_for_chain(from_addr, &args.ethereum_rpc, args.month, args.year),
        get_receipts_for_chain(from_addr, &args.base_rpc, args.month, args.year),
        get_receipts_for_chain(from_addr, &args.arbitrum_rpc, args.month, args.year)
    );
    let (eth_transactions, base_transactions, arbitrum_transactions) = (
        eth_transactions?,
        base_transactions?,
        arbitrum_transactions?,
    );

    let all_transactions = [
        eth_transactions.clone(),
        base_transactions.clone(),
        arbitrum_transactions.clone(),
    ]
    .concat();

    let filename = format!("{}-{}-{}.csv", args.month, args.year, args.from_address);
    let file = std::fs::File::create(format!("filtered_transactions/{}", filename))?;
    fs::create_dir_all("filtered_transactions")?;
    let mut csv_writer = csv::Writer::from_writer(file);

    println!(
        "Writing {} transactions to filtered_transactions/{}",
        all_transactions.len(),
        filename
    );

    for tx in &all_transactions {
        csv_writer.serialize(tx)?;
    }

    let eth_total = eth_transactions
        .iter()
        .map(|tx| tx.tx_fee_wei as f64 / 1e18)
        .sum::<f64>();
    let base_total = base_transactions
        .iter()
        .map(|tx| tx.tx_fee_wei as f64 / 1e18)
        .sum::<f64>();
    let arbitrum_total = arbitrum_transactions
        .iter()
        .map(|tx| tx.tx_fee_wei as f64 / 1e18)
        .sum::<f64>();
    let total = eth_total + base_total + arbitrum_total;

    println!(
        "\n{} paid the following in SP1 Blobstream relaying fees in {}/{}:\n  Ethereum: {:.4} ETH\n  Base: {:.4} ETH\n  Arbitrum: {:.4} ETH\n  Total: {:.4} ETH",
        args.from_address, args.month, args.year, eth_total, base_total, arbitrum_total, total
    );

    csv_writer.flush()?;
    Ok(())
}

/// Finds the block at the provided timestamp, using the provided provider.
async fn find_block_by_timestamp<P, T, N>(
    provider: &P,
    target_timestamp: u64,
) -> Result<(B256, u64)>
where
    P: Provider<T, N>,
    T: Transport + Clone,
    N: Network,
{
    let latest_block = provider
        .get_block(BlockId::latest(), BlockTransactionsKind::Hashes)
        .await?;
    let Some(latest_block) = latest_block else {
        return Err(anyhow::anyhow!("No latest block found"));
    };
    let mut low = 0;
    let mut high = latest_block.header().number();

    while low <= high {
        let mid = (low + high) / 2;
        let block = provider
            .get_block(mid.into(), BlockTransactionsKind::Hashes)
            .await?;
        let Some(block) = block else {
            return Err(anyhow::anyhow!("No block found"));
        };
        let block_timestamp = block.header().timestamp();

        match block_timestamp.cmp(&target_timestamp) {
            Ordering::Equal => {
                return Ok((block.header().hash(), block.header().number()));
            }
            Ordering::Less => low = mid + 1,
            Ordering::Greater => high = mid - 1,
        }
    }

    // Return the block hash of the closest block after the target timestamp
    let block = provider
        .get_block((low - 10).into(), BlockTransactionsKind::Hashes)
        .await?;
    let Some(block) = block else {
        return Err(anyhow::anyhow!("No block found"));
    };
    Ok((block.header().hash(), block.header().number()))
}
