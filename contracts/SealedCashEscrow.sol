// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {AccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/// @title SealedCashEscrow
/// @notice Atomic, transparent swap escrow. This contract does not provide privacy,
/// bridge assets, or verify Zcash/Ironwood proofs.
contract SealedCashEscrow is
    AccessControlDefaultAdminRules,
    EIP712,
    Pausable,
    ReentrancyGuard
{
    using SafeERC20 for IERC20;

    bytes32 public constant SOLVER_ROLE = keccak256("SOLVER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    uint256 public constant BPS_DENOMINATOR = 10_000;
    uint48 public constant DEFAULT_ADMIN_TRANSFER_DELAY = 2 days;

    bytes32 public constant INTENT_TYPEHASH = keccak256(
        "SwapIntent(bytes32 intentId,address owner,address recipient,address inputToken,uint256 inputAmount,address outputToken,uint256 minimumOutputAmount,uint16 maximumFeeBps,bytes32 nonce,uint64 deadline)"
    );

    enum Status {
        None,
        Funded,
        Settled,
        Cancelled,
        Refunded
    }

    struct SwapIntent {
        bytes32 intentId;
        address owner;
        address recipient;
        address inputToken;
        uint256 inputAmount;
        address outputToken;
        uint256 minimumOutputAmount;
        uint16 maximumFeeBps;
        bytes32 nonce;
        uint64 deadline;
    }

    struct Position {
        address owner;
        address recipient;
        address inputToken;
        uint256 inputAmount;
        address outputToken;
        uint256 minimumOutputAmount;
        uint16 maximumFeeBps;
        uint64 deadline;
        Status status;
    }

    address public immutable treasury;
    uint16 public immutable protocolFeeCeilingBps;

    mapping(bytes32 intentId => Position position) public positions;
    mapping(address owner => mapping(bytes32 nonce => bool consumed)) public nonceConsumed;
    mapping(address token => uint256 amount) public trackedLiabilities;
    mapping(address token => bool allowed) public allowedTokens;

    error WrongChain(uint256 actual, uint256 expected);
    error ZeroAddress();
    error InvalidIntent();
    error IntentExpired();
    error IntentUnavailable();
    error NonceAlreadyConsumed();
    error InvalidSignature();
    error InvalidNativeValue();
    error UnauthorizedOwner();
    error OutputBelowMinimum();
    error FeeExceedsIntentLimit();
    error UnsupportedTokenBehavior();
    error NativeTransferFailed();
    error InsufficientExcess();
    error TokenNotAllowed();

    event NonceConsumed(address indexed owner, bytes32 indexed nonce, bytes32 indexed intentId);
    event IntentFunded(
        bytes32 indexed intentId,
        address indexed owner,
        address indexed recipient,
        address inputToken,
        uint256 inputAmount,
        address outputToken,
        uint256 minimumOutputAmount,
        uint16 maximumFeeBps,
        uint64 deadline
    );
    event IntentSettled(
        bytes32 indexed intentId,
        address indexed solver,
        address indexed recipient,
        address inputToken,
        uint256 inputAmount,
        address outputToken,
        uint256 outputAmount,
        uint256 protocolFee
    );
    event IntentCancelled(
        bytes32 indexed intentId,
        address indexed owner,
        address indexed inputToken,
        uint256 refundedAmount
    );
    event IntentRefunded(
        bytes32 indexed intentId,
        address indexed owner,
        address indexed inputToken,
        uint256 refundedAmount
    );
    event ExcessRecovered(address indexed token, address indexed recipient, uint256 amount);
    event TokenAllowlistUpdated(address indexed token, bool allowed);

    constructor(
        address initialAdmin,
        address initialSolver,
        address initialPauser,
        address treasury_,
        uint16 protocolFeeCeilingBps_
    )
        AccessControlDefaultAdminRules(DEFAULT_ADMIN_TRANSFER_DELAY, initialAdmin)
        EIP712("SealedCashEscrow", "1")
    {
        if (block.chainid != 4663) revert WrongChain(block.chainid, 4663);
        if (
            initialAdmin == address(0) ||
            initialSolver == address(0) ||
            initialPauser == address(0) ||
            treasury_ == address(0)
        ) revert ZeroAddress();
        if (protocolFeeCeilingBps_ > BPS_DENOMINATOR) revert InvalidIntent();

        treasury = treasury_;
        protocolFeeCeilingBps = protocolFeeCeilingBps_;
        _grantRole(SOLVER_ROLE, initialSolver);
        _grantRole(PAUSER_ROLE, initialPauser);
    }

    function hashIntent(SwapIntent calldata intent) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    INTENT_TYPEHASH,
                    intent.intentId,
                    intent.owner,
                    intent.recipient,
                    intent.inputToken,
                    intent.inputAmount,
                    intent.outputToken,
                    intent.minimumOutputAmount,
                    intent.maximumFeeBps,
                    intent.nonce,
                    intent.deadline
                )
            )
        );
    }

    function computeIntentId(address owner, bytes32 nonce) public pure returns (bytes32) {
        return keccak256(abi.encode(owner, nonce));
    }

    function setTokenAllowed(
        address token,
        bool allowed
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (token == address(0)) revert ZeroAddress();
        allowedTokens[token] = allowed;
        emit TokenAllowlistUpdated(token, allowed);
    }

    function fundNative(
        SwapIntent calldata intent,
        bytes calldata signature
    ) external payable whenNotPaused nonReentrant {
        if (intent.inputToken != address(0) || msg.value != intent.inputAmount) {
            revert InvalidNativeValue();
        }
        if (msg.sender != intent.owner) revert UnauthorizedOwner();

        _consumeIntent(intent, signature);
        trackedLiabilities[address(0)] += intent.inputAmount;
        _emitIntentFunded(intent);
    }

    function fundERC20(
        SwapIntent calldata intent,
        bytes calldata signature
    ) external whenNotPaused nonReentrant {
        if (intent.inputToken == address(0)) revert InvalidIntent();

        _consumeIntent(intent, signature);
        trackedLiabilities[intent.inputToken] += intent.inputAmount;

        IERC20 token = IERC20(intent.inputToken);
        uint256 beforeBalance = token.balanceOf(address(this));
        token.safeTransferFrom(intent.owner, address(this), intent.inputAmount);
        if (token.balanceOf(address(this)) - beforeBalance != intent.inputAmount) {
            revert UnsupportedTokenBehavior();
        }

        _emitIntentFunded(intent);
    }

    function settle(
        bytes32 intentId,
        uint256 outputAmount,
        uint256 protocolFee
    ) external payable onlyRole(SOLVER_ROLE) whenNotPaused nonReentrant {
        Position storage position = positions[intentId];
        if (position.status != Status.Funded || block.timestamp > position.deadline) {
            revert IntentUnavailable();
        }
        if (outputAmount < position.minimumOutputAmount) revert OutputBelowMinimum();
        if (
            protocolFee >
            (position.inputAmount * position.maximumFeeBps) / BPS_DENOMINATOR
        ) revert FeeExceedsIntentLimit();

        if (position.outputToken == address(0)) {
            if (msg.value != outputAmount) revert InvalidNativeValue();
        } else if (msg.value != 0) {
            revert InvalidNativeValue();
        }

        position.status = Status.Settled;
        trackedLiabilities[position.inputToken] -= position.inputAmount;

        _deliverOutput(position.outputToken, position.recipient, outputAmount);
        _releaseInput(position.inputToken, msg.sender, position.inputAmount - protocolFee);
        if (protocolFee != 0) {
            _releaseInput(position.inputToken, treasury, protocolFee);
        }

        emit IntentSettled(
            intentId,
            msg.sender,
            position.recipient,
            position.inputToken,
            position.inputAmount,
            position.outputToken,
            outputAmount,
            protocolFee
        );
    }

    function cancel(bytes32 intentId) external nonReentrant {
        Position storage position = positions[intentId];
        if (position.status != Status.Funded) revert IntentUnavailable();
        if (msg.sender != position.owner) revert UnauthorizedOwner();

        position.status = Status.Cancelled;
        trackedLiabilities[position.inputToken] -= position.inputAmount;
        _releaseInput(position.inputToken, position.owner, position.inputAmount);
        emit IntentCancelled(intentId, position.owner, position.inputToken, position.inputAmount);
    }

    function refundExpired(bytes32 intentId) external nonReentrant {
        Position storage position = positions[intentId];
        if (position.status != Status.Funded || block.timestamp <= position.deadline) {
            revert IntentUnavailable();
        }

        position.status = Status.Refunded;
        trackedLiabilities[position.inputToken] -= position.inputAmount;
        _releaseInput(position.inputToken, position.owner, position.inputAmount);
        emit IntentRefunded(intentId, position.owner, position.inputToken, position.inputAmount);
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function recoverExcess(
        address token,
        address recipient,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (recipient == address(0)) revert ZeroAddress();
        uint256 balance = token == address(0)
            ? address(this).balance
            : IERC20(token).balanceOf(address(this));
        if (amount > balance - trackedLiabilities[token]) revert InsufficientExcess();

        _releaseInput(token, recipient, amount);
        emit ExcessRecovered(token, recipient, amount);
    }

    function _consumeIntent(
        SwapIntent calldata intent,
        bytes calldata signature
    ) private {
        if (
            intent.intentId != computeIntentId(intent.owner, intent.nonce) ||
            intent.nonce == bytes32(0) ||
            intent.owner == address(0) ||
            intent.recipient == address(0) ||
            intent.recipient == address(this) ||
            intent.inputAmount == 0 ||
            intent.minimumOutputAmount == 0 ||
            intent.inputToken == intent.outputToken ||
            intent.maximumFeeBps > protocolFeeCeilingBps
        ) revert InvalidIntent();
        if (
            (intent.inputToken != address(0) && !allowedTokens[intent.inputToken]) ||
            (intent.outputToken != address(0) && !allowedTokens[intent.outputToken])
        ) revert TokenNotAllowed();
        if (block.timestamp > intent.deadline) revert IntentExpired();
        if (nonceConsumed[intent.owner][intent.nonce]) revert NonceAlreadyConsumed();
        if (positions[intent.intentId].status != Status.None) revert IntentUnavailable();
        if (!SignatureChecker.isValidSignatureNow(intent.owner, hashIntent(intent), signature)) {
            revert InvalidSignature();
        }

        nonceConsumed[intent.owner][intent.nonce] = true;
        positions[intent.intentId] = Position({
            owner: intent.owner,
            recipient: intent.recipient,
            inputToken: intent.inputToken,
            inputAmount: intent.inputAmount,
            outputToken: intent.outputToken,
            minimumOutputAmount: intent.minimumOutputAmount,
            maximumFeeBps: intent.maximumFeeBps,
            deadline: intent.deadline,
            status: Status.Funded
        });
        emit NonceConsumed(intent.owner, intent.nonce, intent.intentId);
    }

    function _deliverOutput(address token, address recipient, uint256 amount) private {
        if (token == address(0)) {
            _sendNative(recipient, amount);
            return;
        }

        IERC20 outputToken = IERC20(token);
        uint256 beforeBalance = outputToken.balanceOf(recipient);
        outputToken.safeTransferFrom(msg.sender, recipient, amount);
        if (outputToken.balanceOf(recipient) - beforeBalance != amount) {
            revert UnsupportedTokenBehavior();
        }
    }

    function _releaseInput(address token, address recipient, uint256 amount) private {
        if (amount == 0) return;
        if (token == address(0)) {
            _sendNative(recipient, amount);
        } else {
            IERC20(token).safeTransfer(recipient, amount);
        }
    }

    function _sendNative(address recipient, uint256 amount) private {
        (bool success, ) = payable(recipient).call{value: amount}("");
        if (!success) revert NativeTransferFailed();
    }

    function _emitIntentFunded(SwapIntent calldata intent) private {
        emit IntentFunded(
            intent.intentId,
            intent.owner,
            intent.recipient,
            intent.inputToken,
            intent.inputAmount,
            intent.outputToken,
            intent.minimumOutputAmount,
            intent.maximumFeeBps,
            intent.deadline
        );
    }
}