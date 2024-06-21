// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "@blobstream/DataRootTuple.sol";
import "@blobstream/lib/tree/binary/BinaryMerkleTree.sol";

import {IBlobstreamX} from "./interfaces/IBlobstreamX.sol";
import {IDAOracle} from "@blobstream/IDAOracle.sol";
import {TimelockedUpgradeable} from "@succinctx/upgrades/TimelockedUpgradeable.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

contract BlobstreamX is IBlobstreamX, IDAOracle, TimelockedUpgradeable {
    /// @notice The address of the gateway contract.
    /// @dev DEPECATED: Do not use.
    address public gateway_deprecated;

    /// @notice The block is the first one in the next data commitment.
    uint64 public latestBlock;

    /// @notice The maximum number of blocks that can be skipped in a single request.
    /// @dev Reflects the maximum data commitment size you can request from a Celestia node.
    uint64 public constant DATA_COMMITMENT_MAX = 1000;

    /// @notice Nonce for proof events. Must be incremented sequentially.
    uint256 public state_proofNonce;

    /// @notice Maps block heights to their header hashes.
    mapping(uint64 => bytes32) public blockHeightToHeaderHash;

    /// @notice Mapping of data commitment nonces to data commitments.
    mapping(uint256 => bytes32) public state_dataCommitments;

    /// @notice Header range function id.
    /// @dev DEPRECATED: Do not use.
    bytes32 public headerRangeFunctionId_deprecated;

    /// @notice Next header function id.
    /// @dev DEPRECATED: Do not use.
    bytes32 public nextHeaderFunctionId_depcrecated;

    /// @notice Indicator of if the contract is frozen.
    bool public frozen;

    /// @notice The verification key for the BlobstreamX program.
    bytes32 public blobstreamXProgramVkey;

    /// @notice The deployed SP1 verifier contract.
    ISP1Verifier public verifier;

    struct InitParameters {
        address guardian;
        uint64 height;
        bytes32 header;
        bytes32 blobstreamXProgramVkey;
        address verifier;
    }

    struct ProofOutputs {
        bytes32 trustedHeaderHash;
        bytes32 targetHeaderHash;
        bytes32 dataCommitment;
        uint64 trustedBlock;
        uint64 targetBlock;
        uint256 validatorBitmap;
    }

    function VERSION() external pure override returns (string memory) {
        return "1.0.1";
    }

    /// @dev Initializes the contract.
    /// @param _params The initialization parameters.
    function initialize(InitParameters calldata _params) external initializer {
        __TimelockedUpgradeable_init(_params.guardian, _params.guardian);

        frozen = false;

        blockHeightToHeaderHash[_params.height] = _params.header;
        latestBlock = _params.height;
        blobstreamXProgramVkey = _params.blobstreamXProgramVkey;
        verifier = ISP1Verifier(_params.verifier);

        state_proofNonce = 1;
    }

    /// @notice Only the guardian can set the contract to a frozen state.
    function updateFreeze(bool _freeze) external onlyGuardian {
        frozen = _freeze;
    }

    /// @notice Only the guardian can update the genesis state of the light client.
    function updateGenesisState(uint32 _height, bytes32 _header) external onlyGuardian {
        blockHeightToHeaderHash[_height] = _header;
        latestBlock = _height;
    }

    /// @notice Only the guardian can update the verifier contract.
    function updateVerifier(address _verifier) external onlyGuardian {
        verifier = ISP1Verifier(_verifier);
    }

    /// @notice Only the guardian can update the program vkey.
    function updateProgramVkey(bytes32 _programVkey) external onlyGuardian {
        blobstreamXProgramVkey = _programVkey;
    }

    /// @notice Commits the new header at targetBlock and the data commitment for the block range [latestBlock, targetBlock).
    /// @param proof The proof bytes for the SP1 proof.
    /// @param publicValues The public commitments from the SP1 proof.
    function commitHeaderRange(bytes calldata proof, bytes calldata publicValues) external {
        if (frozen) {
            revert ContractFrozen();
        }
        ProofOutputs memory po = abi.decode(publicValues, (ProofOutputs));

        bytes32 trustedHeader = blockHeightToHeaderHash[latestBlock];
        if (trustedHeader == bytes32(0)) {
            revert TrustedHeaderNotFound();
        }

        if (po.targetBlock <= latestBlock || po.targetBlock - latestBlock > DATA_COMMITMENT_MAX) {
            revert TargetBlockNotInRange();
        }

        // Verify the proof with the associated public values. This will revert if proof invalid.
        verifier.verifyProof(blobstreamXProgramVkey, publicValues, proof);

        // Store the new header and data commitment, and update the latest block and event nonce.
        blockHeightToHeaderHash[po.targetBlock] = po.targetHeaderHash;
        state_dataCommitments[state_proofNonce] = po.dataCommitment;

        emit HeadUpdate(po.targetBlock, po.targetHeaderHash);

        emit DataCommitmentStored(state_proofNonce, latestBlock, po.targetBlock, po.dataCommitment);

        emit ValidatorBitmapEquivocation(po.trustedBlock, po.targetBlock, po.validatorBitmap);

        state_proofNonce++;
        latestBlock = po.targetBlock;
    }

    /// @dev Verify the attestation for the given proof nonce, tuple, and proof. This is taken from
    /// the existing Blobstream contract and is used to verify the data hash for a specific block
    /// against a posted data commitment.
    function verifyAttestation(
        uint256 _proofNonce,
        DataRootTuple memory _tuple,
        BinaryMerkleProof memory _proof
    ) external view returns (bool) {
        if (frozen) {
            revert ContractFrozen();
        }

        // Note: state_proofNonce slightly differs from Blobstream.sol because it is incremented
        //   after each commit.
        if (_proofNonce == 0 || _proofNonce >= state_proofNonce) {
            return false;
        }

        // Load the tuple root at the given index from storage.
        bytes32 root = state_dataCommitments[_proofNonce];

        // Verify the proof.
        (bool isProofValid,) = BinaryMerkleTree.verify(root, _proof, abi.encode(_tuple));

        return isProofValid;
    }
}
