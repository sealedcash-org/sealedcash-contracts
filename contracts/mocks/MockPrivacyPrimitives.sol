// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ISealedCashHasher} from "../interfaces/ISealedCashHasher.sol";
import {ISealedCashVerifier} from "../interfaces/ISealedCashVerifier.sol";

contract MockPrivacyHasher is ISealedCashHasher {
    function hashLeftRight(bytes32 left, bytes32 right) external pure returns (bytes32) {
        return bytes32(uint256(keccak256(abi.encode(left, right))) % 21888242871839275222246405745257275088548364400416034343698204186575808495617);
    }
}

contract MockPrivacyVerifier is ISealedCashVerifier {
    bool public result = true;
    bool public shouldRevert;
    bytes32 public expectedInputsHash;
    uint256 public expectedDepositAmount;
    address public expectedDepositAsset;
    bool public expectedDepositSet;
    bytes32 public lastRoot;
    address public lastAsset;
    uint256 public lastAmount;

    function setResult(bool result_) external { result = result_; }
    function setShouldRevert(bool value) external { shouldRevert = value; }
    function setExpectedInputsHash(bytes32 value) external { expectedInputsHash = value; }
    function setExpectedDeposit(address asset, uint256 amount) external {
        expectedDepositAsset = asset;
        expectedDepositAmount = amount;
        expectedDepositSet = true;
    }

    function hashInputs(PublicInputs calldata inputs) public pure returns (bytes32) {
        bytes32 context = keccak256(abi.encode(
            inputs.chainId, inputs.pool, inputs.domain, inputs.protocolVersion,
            inputs.circuitVersion, inputs.operation, inputs.root, inputs.asset,
            inputs.publicAmount
        ));
        bytes32 action = keccak256(abi.encode(
            inputs.isDeposit, inputs.recipient, inputs.relayer,
            inputs.relayerFee, inputs.inputCount, inputs.outputCount,
            inputs.nullifiers, inputs.commitments, inputs.ciphertextHashes
        ));
        return keccak256(abi.encode(context, action));
    }

    function verifyProof(
        bytes calldata,
        PublicInputs calldata inputs
    ) external view returns (bool) {
        if (shouldRevert) revert("mock verifier failure");
        bool expectedDepositMatches =
            !inputs.isDeposit ||
            !expectedDepositSet ||
            (inputs.asset == expectedDepositAsset && inputs.publicAmount == expectedDepositAmount);
        return result &&
            expectedDepositMatches &&
            (expectedInputsHash == bytes32(0) || expectedInputsHash == hashInputs(inputs));
    }
}