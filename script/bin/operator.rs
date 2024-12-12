use alloy::{
    network::{Ethereum, EthereumWallet},
    primitives::{Address, B256},
    providers::{
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
        Identity, Provider, ProviderBuilder, RootProvider,
    },
    signers::local::PrivateKeySigner,
    sol,
    transports::http::{Client, Http},
};
use anyhow::Result;
use blobstream_script::util::TendermintRPCClient;
use blobstream_script::{relay, TendermintProver};
use log::{error, info};
use primitives::get_header_update_verdict;
use reqwest::Url;
use sp1_sdk::{
    HashableKey, ProverClient, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tendermint_light_client_verifier::Verdict;

const ELF: &[u8] = include_bytes!("../../elf/blobstream-elf");

/// Alias the fill provider for the Ethereum network. Retrieved from the instantiation of the
/// ProviderBuilder. Recommended method for passing around a ProviderBuilder.
type EthereumFillProvider = FillProvider<
    JoinFill<
        JoinFill<
            Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider<Http<Client>>,
    Http<Client>,
    Ethereum,
>;

enum RelayMode {
    Kms,
    Local,
}

struct SP1BlobstreamOperator {
    client: ProverClient,
    pk: SP1ProvingKey,
    vk: SP1VerifyingKey,
    provider: Arc<RootProvider<Http<Client>>>,
    contract_address: Address,
    relayer_address: Option<Address>,
    chain_id: u64,
    use_kms_relayer: RelayMode,
    wallet_filler: Option<Arc<EthereumFillProvider>>,
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract SP1Blobstream {
        bool public frozen;
        uint64 public latestBlock;
        uint256 public state_proofNonce;
        mapping(uint64 => bytes32) public blockHeightToHeaderHash;
        mapping(uint256 => bytes32) public state_dataCommitments;
        uint64 public constant DATA_COMMITMENT_MAX = 10000;
        bytes32 public blobstreamProgramVkey;
        address public verifier;

        function commitHeaderRange(bytes calldata proof, bytes calldata publicValues) external;
    }
}

// Timeout for the proof in seconds.
const PROOF_TIMEOUT_SECONDS: u64 = 60 * 30;

const NUM_RELAY_RETRIES: u32 = 3;

impl SP1BlobstreamOperator {
    pub async fn new() -> Self {
        dotenv::dotenv().ok();

        let client = ProverClient::new();
        let (pk, vk) = client.setup(ELF);
        let use_kms_relayer =
            matches!(env::var("USE_KMS_RELAYER").map(|v| v.to_lowercase()), Ok(v) if v == "true");
        let use_kms_relayer = if use_kms_relayer {
            RelayMode::Kms
        } else {
            RelayMode::Local
        };
        let chain_id: u64 = env::var("CHAIN_ID")
            .expect("CHAIN_ID not set")
            .parse()
            .unwrap();
        let rpc_url: Url = env::var("RPC_URL")
            .expect("RPC_URL not set")
            .parse()
            .unwrap();

        let provider = Arc::new(ProviderBuilder::new().on_http(rpc_url.clone()));

        let (relayer_address, wallet_filler) = match use_kms_relayer {
            RelayMode::Local => {
                let private_key = env::var("PRIVATE_KEY")
                    .expect("PRIVATE_KEY environment variable must be set when USE_KMS_RELAYER is not 'true'. Set USE_KMS_RELAYER=true to use KMS relaying instead.");
                let signer: PrivateKeySigner = private_key.parse().expect(
                    "Failed to parse PRIVATE_KEY - ensure it is a valid Ethereum private key",
                );
                let relayer_address = signer.address();
                let wallet = EthereumWallet::from(signer);
                let wallet_filler = ProviderBuilder::new()
                    .with_recommended_fillers()
                    .wallet(wallet)
                    .on_http(rpc_url.clone());
                (Some(relayer_address), Some(Arc::new(wallet_filler)))
            }
            RelayMode::Kms => (None, None),
        };

        let contract_address = env::var("CONTRACT_ADDRESS")
            .expect("CONTRACT_ADDRESS not set")
            .parse()
            .unwrap();

        Self {
            client,
            pk,
            vk,
            provider,
            chain_id,
            contract_address,
            relayer_address,
            use_kms_relayer,
            wallet_filler,
        }
    }

    /// Check the verifying key in the contract matches the verifying key in the prover.
    async fn check_vkey(&self) -> Result<()> {
        let contract = SP1Blobstream::new(self.contract_address, self.provider.clone());
        let verifying_key = contract
            .blobstreamProgramVkey()
            .call()
            .await?
            .blobstreamProgramVkey;

        if verifying_key.0.to_vec()
            != hex::decode(self.vk.bytes32().strip_prefix("0x").unwrap()).unwrap()
        {
            return Err(anyhow::anyhow!(
                    "The verifying key in the operator does not match the verifying key in the contract!"
                ));
        }

        Ok(())
    }

    async fn request_header_range(
        &self,
        trusted_block: u64,
        target_block: u64,
    ) -> Result<SP1ProofWithPublicValues> {
        let prover = TendermintProver::new();
        let mut stdin = SP1Stdin::new();

        let inputs = prover
            .fetch_input_for_blobstream_proof(trusted_block, target_block)
            .await;

        // Simulate the step from the trusted block to the target block.
        let verdict =
            get_header_update_verdict(&inputs.trusted_light_block, &inputs.target_light_block);
        assert_eq!(verdict, Verdict::Success);

        let encoded_proof_inputs = serde_cbor::to_vec(&inputs)?;
        stdin.write_vec(encoded_proof_inputs);

        self.client
            .prove(&self.pk, stdin)
            .plonk()
            .timeout(Duration::from_secs(PROOF_TIMEOUT_SECONDS))
            .run()
    }

    /// Relay a header range proof to the SP1 Blobstream contract.
    async fn relay_header_range(&self, proof: SP1ProofWithPublicValues) -> Result<B256> {
        // TODO: sp1_sdk should return empty bytes in mock mode.
        let proof_as_bytes = if env::var("SP1_PROVER").unwrap().to_lowercase() == "mock" {
            vec![]
        } else {
            proof.bytes()
        };

        match self.use_kms_relayer {
            RelayMode::Kms => {
                let contract = SP1Blobstream::new(self.contract_address, self.provider.clone());
                let proof_bytes = proof_as_bytes.clone().into();
                let public_values = proof.public_values.to_vec().into();
                let commit_header_range = contract.commitHeaderRange(proof_bytes, public_values);
                relay::relay_with_kms(
                    &relay::KMSRelayRequest {
                        chain_id: self.chain_id,
                        address: self.contract_address.to_checksum(None),
                        calldata: commit_header_range.calldata().to_string(),
                        platform_request: false,
                    },
                    NUM_RELAY_RETRIES,
                )
                .await
            }
            RelayMode::Local => {
                let public_values_bytes = proof.public_values.to_vec();
                let wallet_filler = self
                    .wallet_filler
                    .as_ref()
                    .expect("Wallet filler should be set for non-KMS relayer");
                let contract = SP1Blobstream::new(self.contract_address, wallet_filler.clone());
                let relayer_address = self
                    .relayer_address
                    .expect("Relayer address should be set for non-KMS relayer");

                let gas_limit = relay::get_gas_limit(self.chain_id);
                let max_fee_per_gas = relay::get_fee_cap(self.chain_id, wallet_filler.root()).await;

                let nonce = wallet_filler.get_transaction_count(relayer_address).await?;

                // Wait for 3 required confirmations with a timeout of 60 seconds.
                const NUM_CONFIRMATIONS: u64 = 3;
                const TIMEOUT_SECONDS: u64 = 60;
                let receipt = contract
                    .commitHeaderRange(proof_as_bytes.into(), public_values_bytes.into())
                    .gas_price(max_fee_per_gas)
                    .gas(gas_limit)
                    .nonce(nonce)
                    .send()
                    .await?
                    .with_required_confirmations(NUM_CONFIRMATIONS)
                    .with_timeout(Some(Duration::from_secs(TIMEOUT_SECONDS)))
                    .get_receipt()
                    .await?;

                // If status is false, it reverted.
                if !receipt.status() {
                    error!("Transaction reverted!");
                }

                Ok(receipt.transaction_hash)
            }
        }
    }

    async fn run(&self) -> Result<()> {
        self.check_vkey().await?;

        let fetcher = TendermintRPCClient::default();
        let block_update_interval = get_block_update_interval();

        let contract = match self.use_kms_relayer {
            RelayMode::Kms => SP1Blobstream::new(self.contract_address, self.provider.clone()),
            RelayMode::Local => {
                let wallet_filler = self
                    .wallet_filler
                    .as_ref()
                    .expect("Wallet filler should be set for local mode");
                SP1Blobstream::new(
                    self.contract_address,
                    Arc::new(wallet_filler.root().clone()),
                )
            }
        };
        let data_commitment_max = contract
            .DATA_COMMITMENT_MAX()
            .call()
            .await?
            .DATA_COMMITMENT_MAX;

        let current_block = contract.latestBlock().call().await?.latestBlock;

        let latest_tendermint_block_nb = fetcher.get_latest_block_height().await;

        let latest_stable_tendermint_block = latest_tendermint_block_nb - 1;

        let max_block = std::cmp::min(
            latest_stable_tendermint_block,
            data_commitment_max + current_block,
        );
        let block_to_request = max_block - (max_block % block_update_interval);

        if block_to_request > current_block {
            let max_end_block = block_to_request;

            let target_block = fetcher
                .find_block_to_request(current_block, max_end_block)
                .await;

            info!("Current block: {}", current_block);
            info!("Attempting to step to block {}", target_block);

            match self.request_header_range(current_block, target_block).await {
                Ok(proof) => {
                    let tx_hash = self.relay_header_range(proof).await?;
                    info!(
                        "Posted data commitment from block {} to block {}\nTransaction hash: {}",
                        current_block, target_block, tx_hash
                    );
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Header range request failed: {}", e));
                }
            };
        } else {
            info!("Next block to request is {} which is > the head of the Tendermint chain which is {}. Sleeping.", block_to_request + block_update_interval, latest_stable_tendermint_block);
        }
        Ok(())
    }
}

fn get_loop_interval_mins() -> u64 {
    let loop_interval_mins_env = env::var("LOOP_INTERVAL_MINS");
    let mut loop_interval_mins = 60;
    if loop_interval_mins_env.is_ok() {
        loop_interval_mins = loop_interval_mins_env
            .unwrap()
            .parse::<u64>()
            .expect("invalid LOOP_INTERVAL_MINS");
    }
    loop_interval_mins
}

fn get_block_update_interval() -> u64 {
    let block_update_interval_env = env::var("BLOCK_UPDATE_INTERVAL");
    let mut block_update_interval = 360;
    if block_update_interval_env.is_ok() {
        block_update_interval = block_update_interval_env
            .unwrap()
            .parse::<u64>()
            .expect("invalid BLOCK_UPDATE_INTERVAL");
    }
    block_update_interval
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    env_logger::init();

    let operator = SP1BlobstreamOperator::new().await;

    info!("Starting SP1 Blobstream operator");
    const LOOP_TIMEOUT_MINS: u64 = 20;
    loop {
        let request_interval_mins = get_loop_interval_mins();
        if let Err(e) = tokio::time::timeout(
            tokio::time::Duration::from_secs(60 * LOOP_TIMEOUT_MINS),
            operator.run(),
        )
        .await
        {
            error!("Error running operator: {}", e);
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(60 * request_interval_mins)).await;
    }
}
