// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ISealedCashHasher} from "./interfaces/ISealedCashHasher.sol";
import {LibPoseidon2Yul} from "poseidon2-evm/src/bn254/yul/LibPoseidon2Yul.sol";

/// @notice Raw BN254 Poseidon2 permutation hasher used by the Noir circuit.
/// @dev Noir calls poseidon2_permutation([left, right, 0, 0])[0].  This is
/// deliberately not the poseidon2-evm sponge hash_2 (which applies a domain
/// separator and a variable-length sponge convention).  The permutation is
/// linked inline, so this primitive has no mutable or immutable dependency.
contract SealedCashPoseidon2RawHasher is ISealedCashHasher {
    uint256 public constant BN254_SCALAR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    error NonCanonicalField();

    function hashLeftRight(bytes32 left, bytes32 right) external pure returns (bytes32) {
        uint256 leftField = uint256(left);
        uint256 rightField = uint256(right);
        if (leftField >= BN254_SCALAR_MODULUS || rightField >= BN254_SCALAR_MODULUS) {
            revert NonCanonicalField();
        }
        return bytes32(LibPoseidon2Yul.poseidon2_core(leftField, rightField, 0, 0));
    }
}