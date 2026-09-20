// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ISealedCashHasher} from "./interfaces/ISealedCashHasher.sol";
import {IPoseidon2} from "poseidon2-evm/src/IPoseidon2.sol";

/// @notice BN254 Poseidon2 Merkle hasher matching Noir's
/// std::hash::poseidon2_permutation([left, right, 0, 0])[0].
contract SealedCashPoseidon2Hasher is ISealedCashHasher {
    uint256 public constant BN254_SCALAR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    IPoseidon2 public immutable poseidon2;

    error ZeroAddress();
    error NonCanonicalField();

    constructor(address poseidon2_) {
        if (poseidon2_ == address(0)) revert ZeroAddress();
        poseidon2 = IPoseidon2(poseidon2_);
    }

    function hashLeftRight(bytes32 left, bytes32 right) external view returns (bytes32) {
        uint256 leftField = uint256(left);
        uint256 rightField = uint256(right);
        if (leftField >= BN254_SCALAR_MODULUS || rightField >= BN254_SCALAR_MODULUS) {
            revert NonCanonicalField();
        }
        return bytes32(poseidon2.hash_2(leftField, rightField));
    }
}