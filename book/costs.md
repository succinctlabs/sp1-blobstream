# Costs Script

The costs script allows you to query the costs of the SP1 Blobstream relayer for a given month.

## Usage

Run the script with the following arguments:

### Arguments:
- `from-address`: Source wallet address (0x...)
- `ethereum-rpc`: Ethereum RPC endpoint URL 
- `base-rpc`: Base RPC endpoint URL
- `arbitrum-rpc`: Arbitrum RPC endpoint URL
- `month`: Month number (1-12)
- `year`: Year (e.g. 2023)

### How it works:

1. The script creates a filter to get the `HeadUpdate` logs emitted by the SP1Blobstream contract, which
are emitted whenever a data commitment is posted.
2. It then queries each chain's node for all the logs that match the filter.
3. For each log, it gets the transaction receipt.
4. It sums up the gas used and the effective gas price to get the total fees paid.
5. It prints out the total fees paid in ETH for each chain.

### Example:

```bash
cargo run --bin costs -- \
  --from-address 0x123... \
  --ethereum-rpc https://eth-mainnet.g.alchemy.com/v2/YOUR-API-KEY \
  --base-rpc https://base-mainnet.g.alchemy.com/v2/YOUR-API-KEY \
  --arbitrum-rpc https://arbitrum-mainnet.g.alchemy.com/v2/YOUR-API-KEY \
  --month 10 \
  --year 2024
```

```bash
Writing 252 transactions to filtered_transactions/1-10-0x44eB418A966ff47f5AF6f48AEa6Afde0bf193a8d-0x7Cf3876F681Dbb6EdA8f6FfC45D66B996Df08fAe.csv
0x44eB418A966ff47f5AF6f48AEa6Afde0bf193a8d paid 1.5476 ETH sending transactions to 0x7Cf3876F681Dbb6EdA8f6FfC45D66B996Df08fAe during month 10
```

## Current Relayer Configuration

`0x44eB418A966ff47f5AF6f48AEa6Afde0bf193a8d` is the address of the approved relayer that posts data commitments.




