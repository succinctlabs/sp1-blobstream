use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};
use anyhow::Result;
use reqwest::Url;
use std::env;

/// Wrapper of a `SignerMiddleware` client to send transactions to the given
/// contract's `Address`.
pub struct ContractClient {
    chain_id: u64,
    wallet: EthereumWallet,
    contract: Address,
    rpc_url: Url,
}

impl Default for ContractClient {
    fn default() -> Self {
        let chain_id = env::var("CHAIN_ID")
            .expect("CHAIN_ID not set")
            .parse::<u64>()
            .expect("CHAIN_ID not a valid u64");
        let rpc_url = env::var("RPC_URL").expect("RPC_URL not set");
        let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY not set");
        let contract = env::var("CONTRACT_ADDRESS").expect("CONTRACT_ADDRESS not set");

        Self::new(chain_id, &rpc_url, &private_key, &contract)
            .expect("Failed to create ContractClient")
    }
}

impl ContractClient {
    /// Creates a new `ContractClient`.
    pub fn new(chain_id: u64, rpc_url: &str, private_key: &str, contract: &str) -> Result<Self> {
        let signer: PrivateKeySigner = private_key.parse().expect("Failed to parse private key");
        let wallet = EthereumWallet::from(signer);

        let contract = contract.parse::<Address>()?;

        Ok(ContractClient {
            chain_id,
            rpc_url: Url::parse(rpc_url)?,
            wallet,
            contract,
        })
    }

    /// Read data from the contract using calldata.
    pub async fn read(&self, calldata: Vec<u8>) -> Result<Vec<u8>> {
        let tx = TransactionRequest {
            chain_id: Some(self.chain_id),
            to: Some(self.contract.into()),
            from: Some(self.contract),
            input: calldata.into(),
            ..Default::default()
        };

        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .on_http(self.rpc_url.clone());

        let data = provider.call(&tx).await?;

        Ok(data.to_vec())
    }

    /// Get the gas limit.
    fn get_gas_limit(&self) -> u64 {
        if self.chain_id == 42161 || self.chain_id == 421614 {
            15_000_000
        } else {
            1_500_000
        }
    }

    /// Get the gas fee cap.
    async fn get_fee_cap(&self) -> u128 {
        // Base percentage multiplier for the gas fee.
        let mut multiplier = 20;

        // Double the estimated gas fee cap for the testnets.
        if self.chain_id == 17000
            || self.chain_id == 421614
            || self.chain_id == 11155111
            || self.chain_id == 84532
        {
            multiplier = 100
        }

        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .on_http(self.rpc_url.clone());

        // Get the gas price.
        let gas_price = provider.get_gas_price().await.unwrap();

        // Calculate the fee cap.
        (gas_price * (100 + multiplier)) / 100
    }

    /// Send a transaction with the given calldata.
    pub async fn send(&self, calldata: Vec<u8>) -> Result<Option<B256>> {
        let gas_fee_cap = self.get_fee_cap().await;
        let gas_limit = self.get_gas_limit();

        let tx = TransactionRequest {
            chain_id: Some(self.chain_id),
            to: Some(self.contract.into()),
            from: Some(self.contract),
            input: calldata.into(),
            gas: Some(gas_limit.into()),
            gas_price: Some(gas_fee_cap),
            ..Default::default()
        };

        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(self.wallet.clone())
            .on_http(self.rpc_url.clone());

        let tx = provider.send_transaction(tx).await?.watch().await;

        if let Ok(tx) = tx {
            Ok(Some(tx))
        } else {
            Ok(None)
        }
    }
}
