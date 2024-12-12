// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@blobstream/DataRootTuple.sol";
import "@blobstream/lib/tree/binary/BinaryMerkleTree.sol";

import {ISP1Blobstream} from "./interfaces/ISP1Blobstream.sol";
import {IDAOracle} from "@blobstream/IDAOracle.sol";
import {TimelockedUpgradeable} from "@succinctx/upgrades/TimelockedUpgradeable.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

/// @notice SP1Blobstream contract.
contract SP1Blobstream is ISP1Blobstream, IDAOracle, TimelockedUpgradeable {
    /// @notice The address of the gateway contract.
    /// @dev DEPECATED: Do not use. Compatibility for upgrades from BlobstreamX.
    address public gateway_deprecated;

    /// @notice The block is the first one in the next data commitment.
    uint64 public latestBlock;

    /// @notice The maximum number of blocks that can be skipped in a single request.
    /// @dev Reflects the maximum data commitment size you can request from a Celestia node.
    uint64 public constant DATA_COMMITMENT_MAX = 10000;

    /// @notice Nonce for proof events. Must be incremented sequentially.
    uint256 public state_proofNonce;

    /// @notice Maps block heights to their header hashes.
    mapping(uint64 => bytes32) public blockHeightToHeaderHash;

    /// @notice Mapping of data commitment nonces to data commitments.
    mapping(uint256 => bytes32) public state_dataCommitments;

    /// @notice Header range function id.
    /// @dev DEPRECATED: Do not use. Compatibility for upgrades from BlobstreamX.
    bytes32 public headerRangeFunctionId_deprecated;

    /// @notice Next header function id.
    /// @dev DEPRECATED: Do not use. Compatibility for upgrades from BlobstreamX.
    bytes32 public nextHeaderFunctionId_depcrecated;

    /// @notice Indicator of if the contract is frozen.
    bool public frozen;

    /// @notice The verification key for the SP1Blobstream program.
    bytes32 public blobstreamProgramVkey;

    /// @notice The deployed SP1 verifier contract.
    ISP1Verifier public verifier;

    /// @notice Approved relayers for the contract.
    mapping(address => bool) public approvedRelayers;

    /// @notice Check the relayer is approved.
    bool public checkRelayer = false;

    struct InitParameters {
        address guardian;
        uint64 height;
        bytes32 header;
        bytes32 blobstreamProgramVkey;
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

    /// @notice If the relayer check is enabled, only approved relayers can call the function.
    modifier onlyApprovedRelayer() {
        if (checkRelayer && !approvedRelayers[msg.sender]) {
            revert RelayerNotApproved();
        }
        _;
    }

    function VERSION() external pure override returns (string memory) {
        return "1.1.0";
    }

    /// @dev Initializes the contract.
    /// @param _params The initialization parameters.
    function initialize(InitParameters calldata _params) external initializer {
        __TimelockedUpgradeable_init(_params.guardian, _params.guardian);

        frozen = false;

        blockHeightToHeaderHash[_params.height] = _params.header;
        latestBlock = _params.height;
        blobstreamProgramVkey = _params.blobstreamProgramVkey;
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
        blobstreamProgramVkey = _programVkey;
    }

    /// @notice Set a relayer's approval status.
    function setRelayerApproval(address _relayer, bool _approved) external onlyGuardian {
        approvedRelayers[_relayer] = _approved;
    }

    /// @notice Set the relayer check.
    function setCheckRelayer(bool _checkRelayer) external onlyGuardian {
        checkRelayer = _checkRelayer;
    }

    /// @notice Commits the new header at targetBlock and the data commitment for the block range
    /// [latestBlock, targetBlock).
    /// @param proof The proof bytes for the SP1 proof.
    /// @param publicValues The public commitments from the SP1 proof.
    function commitHeaderRange(bytes calldata proof, bytes calldata publicValues)
        external
        onlyApprovedRelayer
    {
        if (frozen) {
            revert ContractFrozen();
        }

        // Parse the outputs from the committed public values associated with the proof.
        ProofOutputs memory po = abi.decode(publicValues, (ProofOutputs));

        // Proof must be linked to the current latest block in the contract.
        bytes32 trustedHeader = blockHeightToHeaderHash[latestBlock];
        if (trustedHeader == bytes32(0)) {
            revert TrustedHeaderNotFound();
        }
        if (trustedHeader != po.trustedHeaderHash) {
            revert TrustedHeaderMismatch();
        }
        if (po.targetBlock <= latestBlock || po.targetBlock - latestBlock > DATA_COMMITMENT_MAX) {
            revert TargetBlockNotInRange();
        }

        // Verify the proof with the associated public values. This will revert if proof invalid.
        verifier.verifyProof(blobstreamProgramVkey, publicValues, proof);

        emit HeadUpdate(po.targetBlock, po.targetHeaderHash);
        emit DataCommitmentStored(state_proofNonce, latestBlock, po.targetBlock, po.dataCommitment);
        emit ValidatorBitmapEquivocation(po.trustedBlock, po.targetBlock, po.validatorBitmap);

        // Store the new header and data commitment, and update the latest block and event nonce.
        blockHeightToHeaderHash[po.targetBlock] = po.targetHeaderHash;
        state_dataCommitments[state_proofNonce] = po.dataCommitment;
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
