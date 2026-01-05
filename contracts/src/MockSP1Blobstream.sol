// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@blobstream/DataRootTuple.sol";
import "@blobstream/lib/tree/binary/BinaryMerkleTree.sol";

import {ISP1Blobstream} from "./interfaces/ISP1Blobstream.sol";
import {IDAOracle} from "@blobstream/IDAOracle.sol";

/// @notice MockSP1Blobstream contract.
contract MockSP1Blobstream is ISP1Blobstream, IDAOracle {

    /// @dev Verify the attestation for the given proof nonce, tuple, and proof. This is taken from
    /// the existing Blobstream contract and is used to verify the data hash for a specific block
    /// against a posted data commitment.
    function verifyAttestation(
        uint256 _proofNonce,
        DataRootTuple memory _tuple,
        BinaryMerkleProof memory _proof
    ) external view returns (bool) {
        return true;
    }
}
