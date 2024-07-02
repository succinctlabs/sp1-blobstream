# Blobstream X Contracts

## Deploy new Blobstream X contract

Fill out the following fields in `.env` in `contracts` folder:

- `PRIVATE_KEY` - Private key of the account that will deploy the contract
- `RPC_URL` - URL of the Ethereum RPC node
- `ETHERSCAN_API_KEY` - API key for Etherscan

Inside ../script/, run `RUST_LOG=info cargo run --release --bin genesis` to generate the following values. Copy them and paste into `.env`
- `GENESIS_HEIGHT` - Height of the block at which the contract will be deployed.
- `GENESIS_HEADER` - Header of the block at which the contract will be deployed.
- `SP1_BLOBSTREAM_PROGRAM_VKEY` - Program verification key of BlobstreamX program.
- `CREATE2_SALT` - Salt for CREATE2 deployment (determinstic deployment). Ex. 0xaa

Then run the following command:

```bash
source .env
forge script script/Deploy.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast --verify --verifier etherscan --etherscan-api-key $ETHERSCAN_API_KEY
```

## Upgrade existing Blobstream X contract

Fill out the following fields in `.env` in `contracts` folder:

- `CONTRACT_ADDRESS` - Address of the contract to upgrade

Then run the following command:

```bash
source .env
forge script script/Upgrade.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast --verify --verifier etherscan --etherscan-api-key $ETHERSCAN_API_KEY
```
