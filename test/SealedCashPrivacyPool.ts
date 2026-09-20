import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { network } from "hardhat";
import { keccak256, numberToHex, stringToHex, zeroAddress, type Hex } from "viem";

describe("SealedCashPrivacyPool", async function () {
  const { viem } = await network.create({ network: "hardhatMainnet", chainType: "l1" });
  const publicClient = await viem.getPublicClient();
  let sequence = 0;

  async function fixture() {
    const [admin, user, recipient, relayer, stranger] = await viem.getWalletClients();
    const hasher = await viem.deployContract("MockPrivacyHasher");
    const verifier = await viem.deployContract("MockPrivacyVerifier");
    const pool = await viem.deployContract("SealedCashPrivacyPool", [
      admin.account.address, admin.account.address, verifier.address, hasher.address,
    ]);
    const token = await viem.deployContract("TestToken", ["Stock", "STK"]);
    const taxed = await viem.deployContract("TaxedToken");
    await token.write.mint([user.account.address, 10_000n]);
    await taxed.write.mint([user.account.address, 10_000n]);
    assert.equal(await pool.read.paused(), true);
    await pool.write.setAssetConfig([zeroAddress, true, 1n, 100n]);
    await pool.write.setAssetConfig([token.address, true, 1n, 100n]);
    await pool.write.setAssetConfig([taxed.address, true, 1n, 100n]);
    assert.equal(await pool.read.enabledAssetCount(), 3n);
    await pool.write.unpause();
    await token.write.approve([pool.address, 10_000n], { account: user.account });
    await taxed.write.approve([pool.address, 10_000n], { account: user.account });
    return { admin, user, recipient, relayer, stranger, hasher, verifier, pool, token, taxed };
  }

  const modulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  const canonical = (value: Hex) => numberToHex(BigInt(value) % modulus, { size: 32 });
  const commitment = () => canonical(keccak256(stringToHex(`commitment-${++sequence}`)));
  const proof = "0x" as Hex;
  const zeroBytes32 = "0x0000000000000000000000000000000000000000000000000000000000000000" as Hex;

  it("accepts native and exact ERC20 deposits and records liabilities", async () => {
    const f = await fixture();
    await f.pool.write.depositNative([commitment(), "0x", "0x"], { account: f.user.account, value: 100n });
    await f.pool.write.depositERC20([f.token.address, 250n, commitment(), "0x", "0x"], { account: f.user.account });
    assert.equal(await f.pool.read.liabilities([zeroAddress]), 100n);
    assert.equal(await f.pool.read.liabilities([f.token.address]), 250n);
    assert.equal(await f.pool.read.nextLeafIndex(), 2n);
    await f.pool.write.depositERC20([f.token.address, 1n, commitment(), "0x", "0x"], { account: f.user.account });
  });

  it("enforces configured minimum deposits and relayer fee caps", async () => {
    const f = await fixture();
    await f.pool.write.pause([], { account: f.admin.account });
    await f.pool.write.setAssetConfig([f.token.address, true, 200n, 5n], { account: f.admin.account });
    await f.pool.write.unpause([], { account: f.admin.account });
    await viem.assertions.revertWithCustomError(
      f.pool.write.depositERC20([f.token.address, 100n, commitment(), "0x", "0x"], { account: f.user.account }),
      f.pool, "TokenNotAllowed",
    );
    await f.pool.write.depositERC20([f.token.address, 500n, commitment(), "0x", "0x"], { account: f.user.account });
    const root = await f.pool.read.currentRoot();
    await viem.assertions.revertWithCustomError(
      f.pool.write.transact([root, [keccak256(stringToHex("fee-n")), zeroBytes32], 1, [commitment(), zeroBytes32], 1, f.token.address, 6n, f.relayer.account.address, ["0x", "0x"], proof]),
      f.pool, "InvalidRelayerFee",
    );
  });

  it("rejects taxed token transfers, zero and duplicate commitments", async () => {
    const f = await fixture();
    const c = commitment();
    await viem.assertions.revertWithCustomError(
      f.pool.write.depositERC20([f.taxed.address, 100n, c, "0x", "0x"], { account: f.user.account }),
      f.pool, "UnsupportedTokenBehavior",
    );
    await f.pool.write.depositNative([c, "0x", "0x"], { account: f.user.account, value: 1n });
    await viem.assertions.revertWithCustomError(
      f.pool.write.depositNative([c, "0x", "0x"], { account: f.user.account, value: 1n }),
      f.pool, "DuplicateCommitment",
    );
    await viem.assertions.revertWithCustomError(
      f.pool.write.depositNative(["0x0000000000000000000000000000000000000000000000000000000000000000", "0x", "0x"], { account: f.user.account, value: 1n }),
      f.pool, "DuplicateCommitment",
    );
  });

  it("fails closed for invalid proofs and unknown roots", async () => {
    const f = await fixture();
    const root = await f.pool.read.currentRoot();
    await f.verifier.write.setResult([false]);
    await viem.assertions.revertWithCustomError(
      f.pool.write.transact([root, [commitment(), zeroBytes32], 1, [commitment(), zeroBytes32], 1, f.token.address, 0n, zeroAddress, ["0x", "0x"], proof]),
      f.pool, "InvalidProof",
    );
    await viem.assertions.revertWithCustomError(
      f.pool.write.transact([keccak256(stringToHex("unknown")), [commitment(), zeroBytes32], 1, [commitment(), zeroBytes32], 1, f.token.address, 0n, zeroAddress, ["0x", "0x"], proof]),
      f.pool, "UnknownRoot",
    );
  });

  it("rejects a deposit whose proof binds a different exact amount", async () => {
    const f = await fixture();
    await f.verifier.write.setExpectedDeposit([f.token.address, 99n]);
    await viem.assertions.revertWithCustomError(
      f.pool.write.depositERC20([f.token.address, 100n, commitment(), "0x", "0x"], { account: f.user.account }),
      f.pool,
      "InvalidProof",
    );
    assert.equal(await f.pool.read.liabilities([f.token.address]), 0n);
  });

  it("rejects duplicate nullifiers within and across transactions", async () => {
    const f = await fixture();
    const root = await f.pool.read.currentRoot();
    const n = canonical(keccak256(stringToHex("nullifier")));
    const out = commitment();
    await viem.assertions.revertWithCustomError(
      f.pool.write.transact([root, [n, n], 2, [out, zeroBytes32], 1, f.token.address, 0n, zeroAddress, ["0x", "0x"], proof]),
      f.pool, "DuplicateNullifier",
    );
    await f.pool.write.transact([root, [n, zeroBytes32], 1, [out, zeroBytes32], 1, f.token.address, 0n, zeroAddress, ["0x", "0x"], proof]);
    const nextRoot = await f.pool.read.currentRoot();
    await viem.assertions.revertWithCustomError(
      f.pool.write.transact([nextRoot, [n, zeroBytes32], 1, [commitment(), zeroBytes32], 1, f.token.address, 0n, zeroAddress, ["0x", "0x"], proof]),
      f.pool, "DuplicateNullifier",
    );
  });

  it("withdraws with a relayer fee and preserves liabilities", async () => {
    const f = await fixture();
    await f.pool.write.depositERC20([f.token.address, 1_000n, commitment(), "0x", "0x"], { account: f.user.account });
    const root = await f.pool.read.currentRoot();
    const n = canonical(keccak256(stringToHex("withdraw-nullifier")));
    await f.pool.write.withdraw([root, [n, zeroBytes32], 1, f.token.address, 900n, f.recipient.account.address, f.relayer.account.address, 10n, [zeroBytes32, zeroBytes32], 0, ["0x", "0x"], proof]);
    assert.equal(await f.pool.read.liabilities([f.token.address]), 90n);
    assert.equal(await f.token.read.balanceOf([f.recipient.account.address]), 900n);
    assert.equal(await f.token.read.balanceOf([f.relayer.account.address]), 10n);
  });

  it("enforces pause and pauser authorization", async () => {
    const f = await fixture();
    await viem.assertions.revertWithCustomError(
      f.pool.write.pause([], { account: f.stranger.account }), f.pool, "AccessControlUnauthorizedAccount",
    );
    await f.pool.write.pause([], { account: f.admin.account });
    await f.pool.write.setAssetConfig([f.token.address, false, 1n, 100n], { account: f.admin.account });
    assert.equal(await f.pool.read.enabledAssetCount(), 2n);
    await viem.assertions.revertWithCustomError(
      f.pool.write.unpause([], { account: f.stranger.account }), f.pool, "AccessControlUnauthorizedAccount",
    );
    await f.pool.write.unpause([], { account: f.admin.account });
    await f.pool.write.pause([], { account: f.admin.account });
    await viem.assertions.revertWithCustomError(
      f.pool.write.depositNative([commitment(), "0x", "0x"], { account: f.user.account, value: 1n }),
      f.pool, "EnforcedPause",
    );
  });

  it("rejects asset configuration changes while active", async () => {
    const f = await fixture();
    await viem.assertions.revertWithCustomError(
      f.pool.write.setAssetConfig([f.token.address, false, 1n, 100n], { account: f.admin.account }),
      f.pool,
      "ExpectedPause",
    );
  });
});