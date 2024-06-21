# SP1 Blobstream

## Overview

SP1 Blobstream is an implementation of [Blobstream X](https://github.com/succinctlabs/blobstreamx) in Rust for the SP1 zkVM.

- `/program`: The SP1 Blobstream program.
- `/primitives`: Libraries for types and helper functions used in the program.
- `/script`: Scripts for getting the contract's genesis parameters and deploying the operator to 
    update the light client.
- `/contracts`: The contract's source code and deployment scripts. Backwards-compatible with the
    original BlobstreamX implementation in case we need to upgrade.


## Deploying SP1 Blobstream

### Components

An SP1 Blobstream implementation has a few key components:
- An `SP1Blobstream` contract. Contains the logic for verifying SP1 Blobstream proofs, storing the
latest data from the Celestia chain, including the headers and data commitments. Matches the interface
of the existing [BlobstreamX](https://github.com/succinctlabs/blobstreamx/blob/main/contracts/src/BlobstreamX.sol) contract so it can be upgraded in-place.
- An `SP1Verifier` contract. Verifies arbitrary SP1 programs. Most chains will have canonical deployments
upon SP1's mainnet launch. Until then, users can deploy their own `SP1Verifier` contracts to verify
SP1 programs on their chain. The SP1 Blobstream implementation will use the `SP1Verifier` contract to verify
the proofs of the SP1 Blobstream programs.
- The SP1 Blobstream program. An SP1 program that verifies the transition between two Tendermint
headers and computes the data commitment of the intermediate blocks.
- The operator. A Rust script that fetches the latest data from a deployed `SP1Blobstream` contract and a 
Tendermint chain, determines the block to request, requests for/generates a proof, and relays the proof to
the `SP1Blobstream` contract.

### Deployment

1. To deploy an SP1 Blobstream contract for a Tendermint chain do the following.

    Get the genesis parameters for the `SP1Blobstream` contract.

    ```shell
    cd script

    # Example with Celestia Mocha-4 Testnet.
    TENDERMINT_RPC_URL=https://rpc.lunaroasis.net/ cargo run --bin genesis --release
    ```

2. Deploy the `BlobstreamX` contract with genesis parameters: `GENESIS_HEIGHT`, `GENESIS_HEADER`, and `SP1_BLOBSTREAM_PROGRAM_VKEY`.

    ```shell
    cd ../contracts

    forge install

    GENESIS_HEIGHT=<GENESIS_HEIGHT> GENESIS_HEADER=<GENESIS_HEADER> SP1_BLOBSTREAM_PROGRAM_VKEY=<SP1_BLOBSTREAM_PROGRAM_VKEY> forge script script/Deploy.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --etherscan-api-key $ETHERSCAN_API_KEY --broadcast --verify
    ```

    If you see the following error, add `--legacy` to the command.
    ```shell
    Error: Failed to get EIP-1559 fees    
    ```
3. Your deployed contract address will be printed to the terminal.

    ```shell
    == Return ==
    0: address <SP1_BLOBSTREAM_ADDRESS>
    ```

    This will be used when you run the operator in step 5.

4. Export your SP1 Prover Network configuration

    ```shell
    # Export the PRIVATE_KEY you will use to relay proofs.
    export PRIVATE_KEY=<PRIVATE_KEY>

    # Optional
    # If you're using the Succinct network, set SP1_PROVER to "network". Otherwise, set it to "local" or "mock".
    export SP1_PROVER={network|local|mock}
    # Only required if SP1_PROVER is set "network".
    export SP1_PRIVATE_KEY=<SP1_PRIVATE_KEY>
    ```

5. Run the SP1 Blobstream operator to update the LC continuously.

```
cd ../script

TENDERMINT_RPC_URL=https://rpc.celestia-mocha.com/ CHAIN_ID=11155111 RPC_URL=https://ethereum-sepolia.publicnode.com/ CONTRACT_ADDRESS=<SP1_BLOBSTREAM_ADDRESS> cargo run --bin operator --release
```
