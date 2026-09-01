# Quick Start

This guide explains how to deploy the SP1 Blobstream contract and run the operator.

## Deploying SP1 Blobstream

1. To deploy an SP1 Blobstream contract for a Tendermint chain do the following.

    Get the genesis parameters for the `SP1Blobstream` contract.

    ```shell
    cd script

    # Use the RPC endpoint for the Tendermint source chain.
    TENDERMINT_RPC_URL="<TENDERMINT_RPC_URL>" cargo run --bin genesis --release
    ```

2. Add the genesis parameters to `/contracts/.env` mirroring `contracts/.env.example`.

| Parameter                     | Description                                                    |
| ----------------------------- | -------------------------------------------------------------- |
| `GENESIS_HEIGHT`              | The block height of the genesis block for the Tendermint chain |
| `GENESIS_HEADER`              | The header of the genesis block for the Tendermint chain       |
| `SP1_BLOBSTREAM_PROGRAM_VKEY` | The verification key for the SP1 Blobstream program            |

3. Deploy the `SP1Blobstream` contract with genesis parameters: `GENESIS_HEIGHT`, `GENESIS_HEADER`, and `SP1_BLOBSTREAM_PROGRAM_VKEY`.

    ```shell
    cd ../contracts

    forge install

    forge script script/Deploy.s.sol --rpc-url <RPC_URL> --private-key <PRIVATE_KEY> --etherscan-api-key <ETHERSCAN_API_KEY> --broadcast --verify
    ```

    If you see the following error, add `--legacy` to the command.
    ```shell
    Error: Failed to get EIP-1559 fees    
    ```

4. Your deployed contract address will be printed to the terminal.

    ```shell
    == Return ==
    0: address <SP1_BLOBSTREAM_ADDRESS>
    ```

    This will be used when you run the operator in step 6.

5. Export your SP1 Prover Network configuration.

    ```shell
    # Export the PRIVATE_KEY you will use to relay proofs.
    export PRIVATE_KEY=<PRIVATE_KEY>

    # For the Succinct network, set the private key corresponding to the public key in the SP1 Prover Network.
    export NETWORK_PRIVATE_KEY=<NETWORK_PRIVATE_KEY>

    # If you're using a custom RPC URL, set it here.
    export NETWORK_RPC_URL=<NETWORK_RPC_URL>

    # If you're proving locally, set the SP1_PROVER to "cpu".
    export SP1_PROVER=cpu
    ```

6. Run the SP1 Blobstream operator to update the LC continuously.

    ```shell
    cd ../script

    TENDERMINT_RPC_URL="<TENDERMINT_RPC_URL>" \
    RPC_URL="<DESTINATION_CHAIN_RPC_URL>" \
    CONTRACT_ADDRESS="<SP1_BLOBSTREAM_ADDRESS>" \
    SIGNER_MODE=local \
    cargo run --bin operator --release
    ```
