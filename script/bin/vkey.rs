use sp1_sdk::{HashableKey, MockProver, Prover, ProvingKey};
const BLOBSTREAMX_ELF: &[u8] = include_bytes!("../../elf/blobstream-elf");

#[tokio::main]
pub async fn main() {
    let client = MockProver::new().await;
    let pk = client
        .setup(sp1_sdk::Elf::Static(BLOBSTREAMX_ELF))
        .await
        .unwrap();
    let vk = pk.verifying_key().clone();
    println!("VK: {}", vk.bytes32());
}
