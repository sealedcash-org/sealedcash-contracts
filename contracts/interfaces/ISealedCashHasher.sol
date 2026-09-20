// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface ISealedCashHasher {
    function hashLeftRight(bytes32 left, bytes32 right) external view returns (bytes32);
}