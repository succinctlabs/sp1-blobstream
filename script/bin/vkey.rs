use sp1_sdk::{Elf, HashableKey, Prover, ProverClient, ProvingKey};
const BLOBSTREAMX_ELF: &[u8] = include_bytes!("../../elf/blobstream-elf");

#[tokio::main]
pub async fn main() {
    let client = ProverClient::builder().mock().build().await;
    let pk = client.setup(Elf::Static(BLOBSTREAMX_ELF)).await.unwrap();
    println!("VK: {}", pk.verifying_key().bytes32());
}
