import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";
import {
  encodeAbiParameters,
  keccak256,
  stringToHex,
  zeroAddress,
  type Hex,
} from "viem";

describe("SealedCashEscrow", async function () {
  const { viem, networkHelpers } = await network.create({
    network: "hardhatMainnet",
    chainType: "l1",
  });
  const publicClient = await viem.getPublicClient();
  let sequence = 0;

  const intentTypes = {
    SwapIntent: [
      { name: "intentId", type: "bytes32" },
      { name: "owner", type: "address" },
      { name: "recipient", type: "address" },
      { name: "inputToken", type: "address" },
      { name: "inputAmount", type: "uint256" },
      { name: "outputToken", type: "address" },
      { name: "minimumOutputAmount", type: "uint256" },
      { name: "maximumFeeBps", type: "uint16" },
      { name: "nonce", type: "bytes32" },
      { name: "deadline", type: "uint64" },
    ],
  } as const;

  async function deployFixture() {
    const [admin, owner, solver, pauser, treasury, recipient, stranger] =
      await viem.getWalletClients();
    const escrow = await viem.deployContract("SealedCashEscrow", [
      admin.account.address,
      solver.account.address,
      pauser.account.address,
      treasury.account.address,
      300,
    ]);
    const input = await viem.deployContract("TestToken", ["Input", "IN"]);
    const output = await viem.deployContract("TestToken", ["Output", "OUT"]);
    const taxed = await viem.deployContract("TaxedToken");

    await input.write.mint([owner.account.address, 10_000n]);
    await output.write.mint([solver.account.address, 10_000n]);
    await taxed.write.mint([owner.account.address, 10_000n]);
    await escrow.write.setTokenAllowed([input.address, true]);
    await escrow.write.setTokenAllowed([output.address, true]);
    await escrow.write.setTokenAllowed([taxed.address, true]);
    await input.write.approve([escrow.address, 10_000n], { account: owner.account });
    await output.write.approve([escrow.address, 10_000n], { account: solver.account });
    await taxed.write.approve([escrow.address, 10_000n], { account: owner.account });

    return {
      admin,
      owner,
      solver,
      pauser,
      treasury,
      recipient,
      stranger,
      escrow,
      input,
      output,
      taxed,
    };
  }

  async function makeIntent(
    fixture: Awaited<ReturnType<typeof deployFixture>>,
    overrides: Partial<{
      intentId: Hex;
      owner: `0x${string}`;
      recipient: `0x${string}`;
      inputToken: `0x${string}`;
      inputAmount: bigint;
      outputToken: `0x${string}`;
      minimumOutputAmount: bigint;
      maximumFeeBps: number;
      nonce: Hex;
      deadline: bigint;
    }> = {},
  ) {
    sequence += 1;
    const block = await publicClient.getBlock();
    const owner = overrides.owner ?? fixture.owner.account.address;
    const nonce = overrides.nonce ?? keccak256(stringToHex(`nonce-${sequence}`));
    const intentId =
      overrides.intentId ??
      keccak256(
        encodeAbiParameters(
          [{ type: "address" }, { type: "bytes32" }],
          [owner, nonce],
        ),
      );
    return {
      intentId,
      owner,
      recipient: fixture.recipient.account.address,
      inputToken: fixture.input.address,
      inputAmount: 1_000n,
      outputToken: fixture.output.address,
      minimumOutputAmount: 900n,
      maximumFeeBps: 100,
      nonce,
      deadline: block.timestamp + 3_600n,
      ...overrides,
    };
  }

  async function signIntent(
    fixture: Awaited<ReturnType<typeof deployFixture>>,
    intent: Awaited<ReturnType<typeof makeIntent>>,
    signer = fixture.owner,
  ) {
    return signer.signTypedData({
      domain: {
        name: "SealedCashEscrow",
        version: "1",
        chainId: 4663,
        verifyingContract: fixture.escrow.address,
      },
      types: intentTypes,
      primaryType: "SwapIntent",
      message: intent,
    });
  }

  async function statusOf(
    fixture: Awaited<ReturnType<typeof deployFixture>>,
    intentId: Hex,
  ) {
    const position = (await fixture.escrow.read.positions([intentId])) as readonly unknown[];
    return position[8];
  }

  it("funds a relayed ERC-20 intent and settles atomically within signed bounds", async function () {
    const fixture = await deployFixture();
    const intent = await makeIntent(fixture);
    const signature = await signIntent(fixture, intent);

    await fixture.escrow.write.fundERC20([intent, signature], {
      account: fixture.stranger.account,
    });

    assert.equal(await fixture.escrow.read.trackedLiabilities([fixture.input.address]), 1_000n);
    assert.equal(await fixture.input.read.balanceOf([fixture.escrow.address]), 1_000n);

    await fixture.escrow.write.settle([intent.intentId, 900n, 10n], {
      account: fixture.solver.account,
    });

    assert.equal(await statusOf(fixture, intent.intentId), 2);
    assert.equal(await fixture.escrow.read.trackedLiabilities([fixture.input.address]), 0n);
    assert.equal(await fixture.output.read.balanceOf([fixture.recipient.account.address]), 900n);
    assert.equal(await fixture.input.read.balanceOf([fixture.solver.account.address]), 990n);
    assert.equal(await fixture.input.read.balanceOf([fixture.treasury.account.address]), 10n);
  });

  it("funds native input and lets only the owner cancel for a full refund", async function () {
    const fixture = await deployFixture();
    const intent = await makeIntent(fixture, {
      inputToken: zeroAddress,
      inputAmount: 1_000n,
    });
    const signature = await signIntent(fixture, intent);

    await fixture.escrow.write.fundNative([intent, signature], {
      account: fixture.owner.account,
      value: 1_000n,
    });
    assert.equal(await publicClient.getBalance({ address: fixture.escrow.address }), 1_000n);

    await viem.assertions.revertWithCustomError(
      fixture.escrow.write.cancel([intent.intentId], { account: fixture.stranger.account }),
      fixture.escrow,
      "UnauthorizedOwner",
    );
    await fixture.escrow.write.cancel([intent.intentId], { account: fixture.owner.account });

    assert.equal(await publicClient.getBalance({ address: fixture.escrow.address }), 0n);
    assert.equal(await statusOf(fixture, intent.intentId), 3);
  });

  it("allows anyone to trigger an expired refund that always pays the owner", async function () {
    const fixture = await deployFixture();
    const block = await publicClient.getBlock();
    const intent = await makeIntent(fixture, { deadline: block.timestamp + 60n });
    const signature = await signIntent(fixture, intent);
    await fixture.escrow.write.fundERC20([intent, signature]);

    await networkHelpers.time.increaseTo(intent.deadline + 1n);
    await fixture.escrow.write.refundExpired([intent.intentId], {
      account: fixture.stranger.account,
    });

    assert.equal(await fixture.input.read.balanceOf([fixture.owner.account.address]), 10_000n);
    assert.equal(await statusOf(fixture, intent.intentId), 4);
  });

  it("rejects reuse of an owner nonce and its deterministic intent id", async function () {
    const fixture = await deployFixture();
    const first = await makeIntent(fixture);
    const firstSignature = await signIntent(fixture, first);
    await fixture.escrow.write.fundERC20([first, firstSignature]);

    const replay = await makeIntent(fixture, {
      nonce: first.nonce,
      intentId: first.intentId,
    });
    const replaySignature = await signIntent(fixture, replay);
    await viem.assertions.revertWithCustomError(
      fixture.escrow.write.fundERC20([replay, replaySignature]),
      fixture.escrow,
      "NonceAlreadyConsumed",
    );
  });

  it("rejects signatures from an account other than the owner", async function () {
    const fixture = await deployFixture();
    const intent = await makeIntent(fixture);
    const badSignature = await signIntent(fixture, intent, fixture.stranger);

    await viem.assertions.revertWithCustomError(
      fixture.escrow.write.fundERC20([intent, badSignature]),
      fixture.escrow,
      "InvalidSignature",
    );
  });

  it("rejects a signature replayed against a different contract", async function () {
    const fixture = await deployFixture();
    const secondEscrow = await viem.deployContract("SealedCashEscrow", [
      fixture.admin.account.address,
      fixture.solver.account.address,
      fixture.pauser.account.address,
      fixture.treasury.account.address,
      300,
    ]);
    await secondEscrow.write.setTokenAllowed([fixture.input.address, true]);
    await secondEscrow.write.setTokenAllowed([fixture.output.address, true]);
    await fixture.input.write.approve([secondEscrow.address, 10_000n], {
      account: fixture.owner.account,
    });
    const intent = await makeIntent(fixture);
    const firstContractSignature = await signIntent(fixture, intent);

    await viem.assertions.revertWithCustomError(
      secondEscrow.write.fundERC20([intent, firstContractSignature]),
      secondEscrow,
      "InvalidSignature",
    );
  });

  it("enforces minimum output and the signed fee ceiling without changing state", async function () {
    const fixture = await deployFixture();
    const intent = await makeIntent(fixture);
    const signature = await signIntent(fixture, intent);
    await fixture.escrow.write.fundERC20([intent, signature]);

    await viem.assertions.revertWithCustomError(
      fixture.escrow.write.settle([intent.intentId, 899n, 0n], {
        account: fixture.solver.account,
      }),
      fixture.escrow,
      "OutputBelowMinimum",
    );
    await viem.assertions.revertWithCustomError(
      fixture.escrow.write.settle([intent.intentId, 900n, 11n], {
        account: fixture.solver.account,
      }),
      fixture.escrow,
      "FeeExceedsIntentLimit",
    );
    assert.equal(await statusOf(fixture, intent.intentId), 1);
    assert.equal(await fixture.escrow.read.trackedLiabilities([fixture.input.address]), 1_000n);
  });

  it("blocks funding while paused but keeps owner cancellation available", async function () {
    const fixture = await deployFixture();
    const funded = await makeIntent(fixture);
    await fixture.escrow.write.fundERC20([funded, await signIntent(fixture, funded)]);
    await fixture.escrow.write.pause([], { account: fixture.pauser.account });

    const blocked = await makeIntent(fixture);
    let fundingRejected = false;
    try {
      await fixture.escrow.write.fundERC20([blocked, await signIntent(fixture, blocked)]);
    } catch {
      fundingRejected = true;
    }
    assert.equal(fundingRejected, true);
    await fixture.escrow.write.cancel([funded.intentId], { account: fixture.owner.account });
    assert.equal(await fixture.input.read.balanceOf([fixture.owner.account.address]), 10_000n);
  });

  it("rejects settlement by an account without the solver role", async function () {
    const fixture = await deployFixture();
    const intent = await makeIntent(fixture);
    await fixture.escrow.write.fundERC20([intent, await signIntent(fixture, intent)]);

    let rejected = false;
    try {
      await fixture.escrow.write.settle([intent.intentId, 900n, 0n], {
        account: fixture.stranger.account,
      });
    } catch {
      rejected = true;
    }
    assert.equal(rejected, true);
    assert.equal(await statusOf(fixture, intent.intentId), 1);
  });

  it("settles an ERC-20 input for exact native output", async function () {
    const fixture = await deployFixture();
    const intent = await makeIntent(fixture, {
      outputToken: zeroAddress,
      minimumOutputAmount: 900n,
    });
    await fixture.escrow.write.fundERC20([intent, await signIntent(fixture, intent)]);
    const recipientBefore = await publicClient.getBalance({
      address: fixture.recipient.account.address,
    });

    await fixture.escrow.write.settle([intent.intentId, 900n, 0n], {
      account: fixture.solver.account,
      value: 900n,
    });

    assert.equal(
      await publicClient.getBalance({ address: fixture.recipient.account.address }),
      recipientBefore + 900n,
    );
    assert.equal(await statusOf(fixture, intent.intentId), 2);
  });

  it("rejects taxed input tokens and rolls back nonce and liability changes", async function () {
    const fixture = await deployFixture();
    const intent = await makeIntent(fixture, { inputToken: fixture.taxed.address });
    const signature = await signIntent(fixture, intent);

    await viem.assertions.revertWithCustomError(
      fixture.escrow.write.fundERC20([intent, signature]),
      fixture.escrow,
      "UnsupportedTokenBehavior",
    );
    assert.equal(
      await fixture.escrow.read.nonceConsumed([fixture.owner.account.address, intent.nonce]),
      false,
    );
    assert.equal(await fixture.escrow.read.trackedLiabilities([fixture.taxed.address]), 0n);
  });

  it("lets the admin recover only balances above tracked liabilities", async function () {
    const fixture = await deployFixture();
    const intent = await makeIntent(fixture);
    await fixture.escrow.write.fundERC20([intent, await signIntent(fixture, intent)]);
    await fixture.input.write.mint([fixture.escrow.address, 50n]);

    await viem.assertions.revertWithCustomError(
      fixture.escrow.write.recoverExcess(
        [fixture.input.address, fixture.treasury.account.address, 51n],
        { account: fixture.admin.account },
      ),
      fixture.escrow,
      "InsufficientExcess",
    );
    await fixture.escrow.write.recoverExcess(
      [fixture.input.address, fixture.treasury.account.address, 50n],
      { account: fixture.admin.account },
    );

    assert.equal(await fixture.input.read.balanceOf([fixture.escrow.address]), 1_000n);
    assert.equal(await fixture.escrow.read.trackedLiabilities([fixture.input.address]), 1_000n);
  });

  it("keeps multiple positions fully collateralized through independent cancellation", async function () {
    const fixture = await deployFixture();
    const first = await makeIntent(fixture, { inputAmount: 1_000n });
    const second = await makeIntent(fixture, { inputAmount: 2_000n });
    await fixture.escrow.write.fundERC20([first, await signIntent(fixture, first)]);
    await fixture.escrow.write.fundERC20([second, await signIntent(fixture, second)]);

    assert.equal(await fixture.input.read.balanceOf([fixture.escrow.address]), 3_000n);
    assert.equal(await fixture.escrow.read.trackedLiabilities([fixture.input.address]), 3_000n);
    await fixture.escrow.write.cancel([first.intentId], { account: fixture.owner.account });

    assert.equal(await fixture.input.read.balanceOf([fixture.escrow.address]), 2_000n);
    assert.equal(await fixture.escrow.read.trackedLiabilities([fixture.input.address]), 2_000n);
    assert.equal(await statusOf(fixture, second.intentId), 1);
  });
});