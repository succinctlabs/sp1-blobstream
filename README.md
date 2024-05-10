# Optimizations
1. Is there a more efficient way to serialize the LightBlocks? We should do some testing to see how many cycles reading the input takes. If we only send in the Headers, rather than the LightBlocks this will be more lightweight.
2. Are the patches working correctly, especially for the Merkle Tree computation?

# Running the program
Add `TENDERMINT_RPC_URL` to `.env` in script, and also add `SP1_PROVER` config. For fast development, set `SP1_PROVER` to mock.

```bash
RUST_LOG=info cargo run --release -- --trusted-block 10 --target-block 50
```