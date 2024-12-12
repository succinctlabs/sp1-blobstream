# Quick Start

This guide will walk you through deploying the SP1 Blobstream contract and running the operator.

## Deploying SP1 Blobstream

1. To deploy an SP1 Blobstream contract for a Tendermint chain do the following.

    Get the genesis parameters for the `SP1Blobstream` contract.

    ```shell
    cd script

    # Example with Celestia Mocha-4 Testnet.
    TENDERMINT_RPC_URL=https://rpc.lunaroasis.net/ cargo run --bin genesis --release
    ```

2. Deploy the `SP1Blobstream` contract with genesis parameters: `GENESIS_HEIGHT`, `GENESIS_HEADER`, and `SP1_BLOBSTREAM_PROGRAM_VKEY`.

    ```shell
    cd ../contracts

    forge install

    GENESIS_HEIGHT=<GENESIS_HEIGHT> GENESIS_HEADER=<GENESIS_HEADER> SP1_BLOBSTREAM_PROGRAM_VKEY=<SP1_BLOBSTREAM_PROGRAM_VKEY> forge script script/Deploy.s.sol --rpc-url <RPC_URL> --private-key <PRIVATE_KEY> --etherscan-api-key <ETHERSCAN_API_KEY> --broadcast --verify
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
    
    TENDERMINT_RPC_URL=https://rpc.celestia-mocha.com/ CHAIN_ID=11155111 RPC_URL=https://ethereum-sepolia.publicnode.com/
    CONTRACT_ADDRESS=<SP1_BLOBSTREAM_ADDRESS> cargo run --bin operator --release
    ```
