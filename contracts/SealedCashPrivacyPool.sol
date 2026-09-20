// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {AccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ISealedCashHasher} from "./interfaces/ISealedCashHasher.sol";
import {ISealedCashVerifier} from "./interfaces/ISealedCashVerifier.sol";

/// @title SealedCashPrivacyPool
/// @notice Privacy-pool settlement boundary for a separately audited ZK system.
/// @dev This contract is only a foundation until real verifier/hasher contracts
/// are deployed. It never treats an invalid or unavailable proof as valid.
contract SealedCashPrivacyPool is
    AccessControlDefaultAdminRules,
    Pausable,
    ReentrancyGuard
{
    using SafeERC20 for IERC20;

    uint8 public constant TREE_DEPTH = 32;
    uint8 public constant MAX_INPUTS = 2;
    uint8 public constant MAX_OUTPUTS = 2;
    uint8 public constant OP_DEPOSIT = 1;
    uint8 public constant OP_TRANSACT = 2;
    uint8 public constant OP_WITHDRAW = 3;
    uint16 public constant ROOT_HISTORY_SIZE = 64;
    // Canonical field-native constants (all strictly below the BN254 modulus).
    bytes32 public constant PROTOCOL_VERSION = bytes32(uint256(2));
    bytes32 public constant CIRCUIT_VERSION = bytes32(uint256(3));
    bytes32 public constant CIPHERTEXT_DOMAIN = bytes32(uint256(4));
    uint256 public constant BN254_SCALAR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 public constant MAX_CIPHERTEXT_SIZE = 4096;
    uint48 public constant DEFAULT_ADMIN_TRANSFER_DELAY = 2 days;
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    struct VerificationRequest {
        uint8 operation;
        bytes32 root;
        bytes32[2] nullifiers;
        uint8 inputCount;
        bytes32[2] commitments;
        uint8 outputCount;
        bytes32[2] ciphers;
        address asset;
        uint256 amount;
        bool isDeposit;
        address recipient;
        address relayer;
        uint256 fee;
    }

    ISealedCashVerifier public immutable verifier;
    ISealedCashHasher public immutable hasher;
    bytes32[TREE_DEPTH] public zeroes;
    bytes32[TREE_DEPTH] public filledSubtrees;
    uint64 public nextLeafIndex;
    bytes32 public currentRoot;
    uint64 public rootCursor;

    mapping(bytes32 => bool) public commitments;
    mapping(bytes32 => bool) public nullifiers;
    mapping(address => bool) public allowedTokens;
    mapping(address => uint256) public liabilities;
    mapping(address => uint256) public minimumDeposit;
    mapping(address => uint256) public maxRelayerFee;
    uint256 public enabledAssetCount;
    mapping(bytes32 => uint64) public rootLeafIndex;
    mapping(bytes32 => bool) public rootKnown;
    bytes32 public immutable verifierCodeHash;
    bytes32 public immutable hasherCodeHash;

    error ZeroAddress();
    error ZeroValue();
    error InvalidCount();
    error TreeFull();
    error DuplicateCommitment();
    error DuplicateNullifier();
    error UnknownRoot();
    error InvalidProof();
    error TokenNotAllowed();
    error UnsupportedTokenBehavior();
    error InsufficientLiability();
    error InvalidNativeValue();
    error InvalidRelayerFee();
    error NativeTransferFailed();
    error RecipientRequired();
    error PrimitiveCodeChanged();
    error InvalidOperation();
    error InvalidUnusedSlot();

    event TokenAllowlistUpdated(address indexed token, bool allowed);
    event AssetConfigUpdated(address indexed asset, bool allowed, uint256 minimumDeposit, uint256 maxRelayerFee);
    event Deposit(
        address indexed asset,
        uint256 amount,
        bytes32 indexed commitment,
        uint64 leafIndex,
        bytes encryptedOutput
    );
    event EncryptedOutput(bytes32 indexed commitment, bytes encryptedOutput);
    event OutputInserted(bytes32 indexed commitment, uint64 leafIndex, bytes32 root, bytes32 ciphertextHash, bytes encryptedOutput);
    event PrivateTransaction(
        bytes32 indexed root,
        address indexed asset,
        uint8 inputCount,
        uint8 outputCount,
        bytes32[2] nullifiers,
        bytes32[2] commitments
    );
    event Withdrawal(
        address indexed asset,
        address indexed recipient,
        address indexed relayer,
        uint256 amount,
        uint256 relayerFee,
        bytes32[2] nullifiers
    );

    constructor(
        address admin,
        address pauser,
        address verifier_,
        address hasher_
    ) AccessControlDefaultAdminRules(DEFAULT_ADMIN_TRANSFER_DELAY, admin) {
        if (
            admin == address(0) ||
            pauser == address(0) ||
            verifier_ == address(0) ||
            hasher_ == address(0)
        ) revert ZeroAddress();
        verifier = ISealedCashVerifier(verifier_);
        hasher = ISealedCashHasher(hasher_);
        verifierCodeHash = _codeHash(verifier_);
        hasherCodeHash = _codeHash(hasher_);
        _grantRole(PAUSER_ROLE, pauser);
        _pause();

        bytes32 zero = bytes32(0);
        for (uint8 i; i < TREE_DEPTH; ++i) {
            zeroes[i] = zero;
            filledSubtrees[i] = zero;
            zero = ISealedCashHasher(hasher_).hashLeftRight(zero, zero);
        }
        currentRoot = zero;
        rootKnown[zero] = true;
        rootLeafIndex[zero] = 0;
    }

    function setTokenAllowed(address token, bool allowed)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
        whenPaused
    {
        if (token == address(0)) revert ZeroAddress();
        if (allowed && (minimumDeposit[token] == 0 || maxRelayerFee[token] == 0)) revert TokenNotAllowed();
        _setAllowed(token, allowed);
        emit TokenAllowlistUpdated(token, allowed);
    }

    function setAssetConfig(address asset, bool allowed, uint256 minimum, uint256 feeCap)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
        whenPaused
    {
        if (allowed && (minimum == 0 || feeCap == 0)) revert ZeroValue();
        minimumDeposit[asset] = minimum;
        maxRelayerFee[asset] = feeCap;
        _setAllowed(asset, allowed);
        emit AssetConfigUpdated(asset, allowed, minimum, feeCap);
        emit TokenAllowlistUpdated(asset, allowed);
    }

    function depositNative(bytes32 commitment, bytes calldata encryptedOutput, bytes calldata proof)
        external
        payable
        whenNotPaused
        nonReentrant
    {
        if (msg.value == 0) revert ZeroValue();
        if (!allowedTokens[address(0)] || msg.value < minimumDeposit[address(0)]) revert TokenNotAllowed();
        _acceptCommitment(commitment);
        bytes32[2] memory outputs = [commitment, bytes32(0)];
        bytes32[2] memory ciphers = [_ciphertextHash(encryptedOutput), bytes32(0)];
        _verifyDeposit(proof, address(0), msg.value, outputs, ciphers);
        liabilities[address(0)] += msg.value;
        (uint64 index, bytes32 root) = _insert(commitment);
        emit Deposit(address(0), msg.value, commitment, index, encryptedOutput);
        emit EncryptedOutput(commitment, encryptedOutput);
        emit OutputInserted(commitment, index, root, keccak256(encryptedOutput), encryptedOutput);
    }

    function depositERC20(
        address token,
        uint256 amount,
        bytes32 commitment,
        bytes calldata encryptedOutput,
        bytes calldata proof
    ) external whenNotPaused nonReentrant {
        if (!allowedTokens[token] || amount < minimumDeposit[token]) revert TokenNotAllowed();
        _acceptCommitment(commitment);
        IERC20 erc20 = IERC20(token);
        uint256 beforeBalance = erc20.balanceOf(address(this));
        erc20.safeTransferFrom(msg.sender, address(this), amount);
        if (erc20.balanceOf(address(this)) - beforeBalance != amount) {
            revert UnsupportedTokenBehavior();
        }
        bytes32[2] memory outputs = [commitment, bytes32(0)];
        bytes32[2] memory ciphers = [_ciphertextHash(encryptedOutput), bytes32(0)];
        _verifyDeposit(proof, token, amount, outputs, ciphers);
        liabilities[token] += amount;
        (uint64 index, bytes32 root) = _insert(commitment);
        emit Deposit(token, amount, commitment, index, encryptedOutput);
        emit EncryptedOutput(commitment, encryptedOutput);
        emit OutputInserted(commitment, index, root, keccak256(encryptedOutput), encryptedOutput);
    }

    function transact(
        bytes32 root,
        bytes32[2] calldata inputNullifiers,
        uint8 inputCount,
        bytes32[2] calldata outputCommitments,
        uint8 outputCount,
        address asset,
        uint256 relayerFee,
        address relayer,
        bytes[2] calldata encryptedOutputs,
        bytes calldata proof
    ) external whenNotPaused nonReentrant {
        if (!_isKnownRoot(root)) revert UnknownRoot();
        if (inputCount == 0 || inputCount > MAX_INPUTS || outputCount == 0 || outputCount > MAX_OUTPUTS) {
            revert InvalidCount();
        }
        if (relayerFee != 0 && relayer == address(0)) revert InvalidRelayerFee();
        if (relayerFee > maxRelayerFee[asset]) revert InvalidRelayerFee();
        bytes32[2] memory ciphers = [
            outputCount > 0 ? _ciphertextHash(encryptedOutputs[0]) : bytes32(0),
            outputCount > 1 ? _ciphertextHash(encryptedOutputs[1]) : bytes32(0)
        ];
        VerificationRequest memory request;
        request.operation = OP_TRANSACT;
        request.root = root;
        request.nullifiers = inputNullifiers;
        request.inputCount = inputCount;
        request.commitments = outputCommitments;
        request.outputCount = outputCount;
        request.ciphers = ciphers;
        request.asset = asset;
        request.relayer = relayer;
        request.fee = relayerFee;
        _verify(proof, request);
        _consumeNullifiers(inputNullifiers, inputCount);
        if (relayerFee != 0) {
            if (liabilities[asset] < relayerFee) revert InsufficientLiability();
            liabilities[asset] -= relayerFee;
            _send(asset, relayer, relayerFee);
        }
        for (uint8 i; i < outputCount; ++i) {
            _acceptCommitment(outputCommitments[i]);
            (uint64 index, bytes32 newRoot) = _insert(outputCommitments[i]);
            emit OutputInserted(outputCommitments[i], index, newRoot, ciphers[i], encryptedOutputs[i]);
        }
        _emitPrivateTransaction(request);
    }

    function withdraw(
        bytes32 root,
        bytes32[2] calldata inputNullifiers,
        uint8 inputCount,
        address asset,
        uint256 amount,
        address recipient,
        address relayer,
        uint256 relayerFee,
        bytes32[2] calldata outputCommitments,
        uint8 outputCount,
        bytes[2] calldata encryptedOutputs,
        bytes calldata proof
    ) external whenNotPaused nonReentrant {
        if (!_isKnownRoot(root)) revert UnknownRoot();
        if (inputCount == 0 || inputCount > MAX_INPUTS) revert InvalidCount();
        if (recipient == address(0)) revert RecipientRequired();
        if (relayerFee > amount || (relayerFee != 0 && relayer == address(0)) || relayerFee > maxRelayerFee[asset]) revert InvalidRelayerFee();
        uint256 total = amount + relayerFee;
        if (liabilities[asset] < total) revert InsufficientLiability();
        if (outputCount > MAX_OUTPUTS) revert InvalidCount();
        bytes32[2] memory ciphers = [
            outputCount > 0 ? _ciphertextHash(encryptedOutputs[0]) : bytes32(0),
            outputCount > 1 ? _ciphertextHash(encryptedOutputs[1]) : bytes32(0)
        ];
        VerificationRequest memory request;
        request.operation = OP_WITHDRAW;
        request.root = root;
        request.nullifiers = inputNullifiers;
        request.inputCount = inputCount;
        request.commitments = outputCommitments;
        request.outputCount = outputCount;
        request.ciphers = ciphers;
        request.asset = asset;
        request.amount = amount;
        request.recipient = recipient;
        request.relayer = relayer;
        request.fee = relayerFee;
        _verify(proof, request);
        _consumeNullifiers(inputNullifiers, inputCount);
        liabilities[asset] -= total;
        _send(asset, recipient, amount);
        if (relayerFee != 0) _send(asset, relayer, relayerFee);
        for (uint8 i; i < outputCount; ++i) {
            _acceptCommitment(outputCommitments[i]);
            (uint64 index, bytes32 newRoot) = _insert(outputCommitments[i]);
            emit OutputInserted(outputCommitments[i], index, newRoot, ciphers[i], encryptedOutputs[i]);
        }
        _emitWithdrawal(request);
    }

    function pause() external onlyRole(PAUSER_ROLE) { _pause(); }
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) { _unpause(); }

    function _verifyDeposit(
        bytes calldata proof,
        address asset,
        uint256 amount,
        bytes32[2] memory outputs,
        bytes32[2] memory ciphers
    ) private view {
        VerificationRequest memory request;
        request.operation = OP_DEPOSIT;
        request.commitments = outputs;
        request.outputCount = 1;
        request.ciphers = ciphers;
        request.asset = asset;
        request.amount = amount;
        request.isDeposit = true;
        _verify(proof, request);
    }

    function _verify(bytes calldata proof, VerificationRequest memory request) private view {
        _checkPrimitives();
        if (request.operation == 0 || request.operation > OP_WITHDRAW) revert InvalidOperation();
        if (request.inputCount > MAX_INPUTS || request.outputCount > MAX_OUTPUTS) revert InvalidCount();
        for (uint8 i = request.inputCount; i < MAX_INPUTS; ++i) {
            if (request.nullifiers[i] != bytes32(0)) revert InvalidUnusedSlot();
        }
        for (uint8 i = request.outputCount; i < MAX_OUTPUTS; ++i) {
            if (request.commitments[i] != bytes32(0) || request.ciphers[i] != bytes32(0)) revert InvalidUnusedSlot();
        }
        ISealedCashVerifier.PublicInputs memory inputs = ISealedCashVerifier.PublicInputs({
            chainId: block.chainid,
            pool: address(this),
            domain: _domain(),
            protocolVersion: PROTOCOL_VERSION,
            circuitVersion: CIRCUIT_VERSION,
            operation: request.operation,
            root: request.root,
            asset: request.asset,
            publicAmount: request.amount,
            isDeposit: request.isDeposit,
            recipient: request.recipient,
            relayer: request.relayer,
            relayerFee: request.fee,
            inputCount: request.inputCount,
            outputCount: request.outputCount,
            nullifiers: request.nullifiers,
            commitments: request.commitments,
            ciphertextHashes: request.ciphers
        });
        _validateCanonical(inputs);
        bool valid;
        try verifier.verifyProof(proof, inputs) returns (bool result) {
            valid = result;
        } catch {
            revert InvalidProof();
        }
        if (!valid) revert InvalidProof();
    }

    function _emitPrivateTransaction(VerificationRequest memory request) private {
        emit PrivateTransaction(
            request.root,
            request.asset,
            request.inputCount,
            request.outputCount,
            request.nullifiers,
            request.commitments
        );
    }

    function _emitWithdrawal(VerificationRequest memory request) private {
        emit Withdrawal(
            request.asset,
            request.recipient,
            request.relayer,
            request.amount,
            request.fee,
            request.nullifiers
        );
    }

    function _consumeNullifiers(bytes32[2] calldata values, uint8 count) private {
        for (uint8 i; i < count; ++i) {
            bytes32 value = values[i];
            if (value == bytes32(0) || nullifiers[value]) revert DuplicateNullifier();
            nullifiers[value] = true;
        }
    }

    function _acceptCommitment(bytes32 commitment) private view {
        if (commitment == bytes32(0) || commitments[commitment]) revert DuplicateCommitment();
    }

    function _insert(bytes32 commitment) private returns (uint64 index, bytes32 root) {
        index = nextLeafIndex;
        if (index >= 2 ** TREE_DEPTH) revert TreeFull();
        commitments[commitment] = true;
        bytes32 node = commitment;
        uint64 current = index;
        for (uint8 level; level < TREE_DEPTH; ++level) {
            if ((current & 1) == 0) {
                filledSubtrees[level] = node;
                node = hasher.hashLeftRight(node, zeroes[level]);
            } else {
                node = hasher.hashLeftRight(filledSubtrees[level], node);
            }
            current >>= 1;
        }
        currentRoot = node;
        rootCursor += 1;
        rootKnown[node] = true;
        rootLeafIndex[node] = index;
        nextLeafIndex = index + 1;
        root = node;
    }

    function _isKnownRoot(bytes32 root) private view returns (bool) {
        if (!rootKnown[root]) return false;
        uint64 insertedAt = rootLeafIndex[root];
        return nextLeafIndex >= insertedAt && nextLeafIndex - insertedAt <= ROOT_HISTORY_SIZE;
    }

    function _checkPrimitives() private view {
        if (_codeHash(address(verifier)) != verifierCodeHash || _codeHash(address(hasher)) != hasherCodeHash) {
            revert PrimitiveCodeChanged();
        }
    }

    function _setAllowed(address asset, bool allowed) private {
        bool wasAllowed = allowedTokens[asset];
        if (wasAllowed == allowed) return;
        allowedTokens[asset] = allowed;
        if (allowed) {
            enabledAssetCount += 1;
        } else {
            enabledAssetCount -= 1;
        }
    }

    function _domain() private view returns (bytes32) {
        return hasher.hashLeftRight(bytes32(block.chainid), bytes32(uint256(uint160(address(this)))));
    }

    function _ciphertextHash(bytes calldata ciphertext) private view returns (bytes32 state) {
        if (ciphertext.length > MAX_CIPHERTEXT_SIZE) revert InvalidCount();
        state = hasher.hashLeftRight(CIPHERTEXT_DOMAIN, bytes32(ciphertext.length));
        for (uint256 offset; offset < ciphertext.length; offset += 31) {
            uint256 remaining = ciphertext.length - offset;
            uint256 take = remaining > 31 ? 31 : remaining;
            bytes32 chunk;
            assembly ("memory-safe") {
                chunk := calldataload(add(ciphertext.offset, offset))
            }
            if (take < 32) chunk = bytes32(uint256(chunk) >> ((32 - take) * 8));
            state = hasher.hashLeftRight(state, chunk);
        }
    }

    function _validateCanonical(ISealedCashVerifier.PublicInputs memory inputs) private pure {
        if (inputs.chainId > type(uint128).max || inputs.publicAmount > type(uint128).max || inputs.relayerFee > type(uint128).max) revert InvalidProof();
        if (uint256(uint160(inputs.pool)) >= BN254_SCALAR_MODULUS || uint256(uint160(inputs.asset)) >= BN254_SCALAR_MODULUS || uint256(uint160(inputs.recipient)) >= BN254_SCALAR_MODULUS || uint256(uint160(inputs.relayer)) >= BN254_SCALAR_MODULUS) revert InvalidProof();
        if (uint256(inputs.domain) >= BN254_SCALAR_MODULUS || uint256(inputs.protocolVersion) >= BN254_SCALAR_MODULUS || uint256(inputs.circuitVersion) >= BN254_SCALAR_MODULUS || uint256(inputs.root) >= BN254_SCALAR_MODULUS) revert InvalidProof();
        for (uint8 i; i < 2; ++i) {
            if (uint256(inputs.nullifiers[i]) >= BN254_SCALAR_MODULUS || uint256(inputs.commitments[i]) >= BN254_SCALAR_MODULUS || uint256(inputs.ciphertextHashes[i]) >= BN254_SCALAR_MODULUS) revert InvalidProof();
        }
    }

    function _codeHash(address account) private view returns (bytes32 hash) {
        assembly ("memory-safe") { hash := extcodehash(account) }
    }

    function _send(address asset, address recipient, uint256 amount) private {
        if (amount == 0) return;
        if (asset == address(0)) {
            (bool ok,) = payable(recipient).call{value: amount}("");
            if (!ok) revert NativeTransferFailed();
        } else {
            IERC20(asset).safeTransfer(recipient, amount);
        }
    }
}