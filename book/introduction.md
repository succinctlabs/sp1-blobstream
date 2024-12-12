# SP1 Blobstream

## Overview

SP1 Blobstream is an implementation of [Blobstream X](https://github.com/succinctlabs/blobstreamx) in Rust for the SP1 zkVM.

- `/program`: The SP1 Blobstream program.
- `/primitives`: Libraries for types and helper functions used in the program.
- `/script`: Scripts for getting the contract's genesis parameters and deploying the operator to 
    update the light client.
- `/contracts`: The contract's source code and deployment scripts. Backwards-compatible with the
    original BlobstreamX implementation in case we need to upgrade.

## Components

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
