// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice External verifier boundary. A production verifier must bind every
/// public argument to the proof; the pool treats false and reverts as failure.
interface ISealedCashVerifier {
    struct PublicInputs {
        uint256 chainId;
        address pool;
        bytes32 domain;
        bytes32 protocolVersion;
        bytes32 circuitVersion;
        uint8 operation;
        bytes32 root;
        address asset;
        uint256 publicAmount;
        bool isDeposit;
        address recipient;
        address relayer;
        uint256 relayerFee;
        uint8 inputCount;
        uint8 outputCount;
        bytes32[2] nullifiers;
        bytes32[2] commitments;
        bytes32[2] ciphertextHashes;
    }

    function verifyProof(
        bytes calldata proof,
        PublicInputs calldata inputs
    ) external view returns (bool);
}