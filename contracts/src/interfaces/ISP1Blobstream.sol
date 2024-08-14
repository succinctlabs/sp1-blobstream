// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "@blobstream/DataRootTuple.sol";
import "@blobstream/lib/tree/binary/BinaryMerkleTree.sol";

interface ISP1Blobstream {
    /// @notice Emits event with the new head update.
    event HeadUpdate(uint64 blockNumber, bytes32 headerHash);

    /// @notice Trusted header not found.
    error TrustedHeaderNotFound();

    /// @notice Target block for proof must be greater than latest block and less than the
    /// latest block plus the maximum number of skipped blocks.
    error TargetBlockNotInRange();

    /// @notice Contract is frozen.
    error ContractFrozen();

    /// @notice Trusted header mismatch.
    error TrustedHeaderMismatch();

    /// @notice Data commitment stored for the block range [startBlock, endBlock) with proof nonce.
    /// @param proofNonce The nonce of the proof.
    /// @param startBlock The start block of the block range.
    /// @param endBlock The end block of the block range.
    /// @param dataCommitment The data commitment for the block range.
    event DataCommitmentStored(
        uint256 proofNonce,
        uint64 indexed startBlock,
        uint64 indexed endBlock,
        bytes32 indexed dataCommitment
    );

    /// @notice Validator bitmap associated with the proof from trustedBlock to targetBlock. The uint256
    /// is encoded as a bitmap of the validators from the trustedBlock that signed off on the new header.
    /// @param trustedBlock The trusted block of the block range.
    /// @param targetBlock The target block of the block range.
    /// @param validatorBitmap The validator bitmap for the block range.
    event ValidatorBitmapEquivocation(
        uint64 trustedBlock, uint64 targetBlock, uint256 validatorBitmap
    );

    /// @notice Relayer not approved.
    error RelayerNotApproved();
}
