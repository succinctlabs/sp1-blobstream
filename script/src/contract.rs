use anyhow::Result;
use ethers::{
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::{
        transaction::eip2718::TypedTransaction, Address, TransactionReceipt, TransactionRequest,
    },
};
use std::env;

/// Wrapper of a `SignerMiddleware` client to send transactions to the given
/// contract's `Address`.
pub struct ContractClient {
    chain_id: u64,
    client: SignerMiddleware<Provider<Http>, LocalWallet>,
    contract: Address,
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
        let provider = Provider::<Http>::try_from(rpc_url)?;

        let wallet: LocalWallet = private_key.parse::<LocalWallet>()?.with_chain_id(chain_id);
        let client = SignerMiddleware::new(provider.clone(), wallet.clone());
        let contract = contract.parse::<Address>()?;

        Ok(ContractClient {
            chain_id,
            client,
            contract,
        })
    }

    /// Read data from the contract using calldata.
    pub async fn read(&self, calldata: Vec<u8>) -> Result<Vec<u8>> {
        let mut tx = TypedTransaction::default();
        tx.set_chain_id(self.chain_id);
        tx.set_to(self.contract);
        tx.set_data(calldata.into());
        let data = self.client.call(&tx, None).await?;

        Ok(data.to_vec())
    }

    /// Send a transaction with the given calldata.
    pub async fn send(&self, calldata: Vec<u8>) -> Result<Option<TransactionReceipt>> {
        let tx = TransactionRequest::new()
            .chain_id(self.chain_id)
            .to(self.contract)
            .from(self.client.address())
            .data(calldata);

        let tx = self.client.send_transaction(tx, None).await?.await?;

        Ok(tx)
    }
}
