# SP1 Blobstream X

## Overview

Implementation of [Blobstream X](https://github.com/succinctlabs/blobstreamx) in Rust for SP1.

- `/program`: The SP1 BlobstreamX program.
- `/primitives`: Libraries for types and helper functions used in the program.
- `/script`: Scripts for getting the contract's genesis parameters and deploying the operator to 
    update the light client.
- `/contracts`: The contract's source code and deployment scripts. Backwards-compatible with the
    original BlobstreamX implementation in case we need to upgrade.



## Run the BlobstreamX Light Client
Update the root folder `.env` following `.env.example`

Get the genesis parameters for the `BlobstreamX` contract.

```
cd script

RUST_LOG=info cargo run --bin genesis --release
```

Update `contracts/.env` following `contracts/README.md`.

Deploy the `BlobstreamX` contract with genesis parameters.

In `contracts/`, run

```
forge install

source .env

forge script script/BlobstreamX.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --etherscan-api-key $ETHERSCAN_API_KEY --broadcast --verify
```

Update `.env` following `.env.example`.

Run `BlobstreamX` script to update the LC continuously.


```
cd script

cargo run --bin operator --release
```

## Optimizations
1. Is there a more efficient way to serialize the LightBlocks? We should do some testing to see how many cycles reading the input takes. If we only send in the Headers, rather than the LightBlocks this will be more lightweight.
2. Are the patches working correctly, especially for the Merkle Tree computation?