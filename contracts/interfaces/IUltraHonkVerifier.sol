// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice ABI emitted by bb.js UltraHonk Solidity verifier generation.
interface IUltraHonkVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs)
        external
        view
        returns (bool);
}