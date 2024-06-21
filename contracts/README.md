# Blobstream X Contracts

## Deploy new Blobstream X contract

Fill out the following fields in `.env` in `contracts` folder:

- `DEPLOY` - Set to `true` to deploy the contract
- `PRIVATE_KEY` - Private key of the account that will deploy the contract
- `RPC_URL` - URL of the Ethereum RPC node
- `ETHERSCAN_API_KEY` - API key for Etherscan
- `CREATE2_SALT` - Salt for CREATE2 deployment (determinstic deployment)

Inside ../script/, run `RUST_LOG=info cargo run --release --bin genesis` to generate the following values. Copy them and paste into `.env`
- `GENESIS_HEIGHT` - Height of the block at which the contract will be deployed
- `GENESIS_HEADER` - Header of the block at which the contract will be deployed
- `SP1_BLOBSTREAM_PROGRAM_VKEY` - Program verification key of BlobstreamX program

Then run the following command:

```bash
source .env

forge script script/Deploy.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast --verify --verifier etherscan --etherscan-api-key $ETHERSCAN_API_KEY
```

## Upgrade existing Blobstream X contract

In addition to the fields in `.env` for deployment, fill out the following fields in `.env` in `contracts` folder:

- `CONTRACT_ADDRESS` - Address of the contract to upgrade
- `UPGRADE` - Set to `true` to upgrade the contract, and don't set `DEPLOY` to `true`
- `UPDATE_GENESIS_STATE` - Set to true to update the genesis state of the contract using `GENESIS_HEIGHT` and `GENESIS_HEADER`.
- `UPDATE_GATEWAY` - Set to true to update the gateway address of the contract using `GATEWAY_ADDRESS`.

Then run the following command:

```bash
source .env

forge script script/Deploy.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast --verify --verifier etherscan --etherscan-api-key $ETHERSCAN_API_KEY
```
