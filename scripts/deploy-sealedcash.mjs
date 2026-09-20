import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createPublicClient, createWalletClient, http, keccak256, zeroAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const root = new URL("..", import.meta.url);
const chainId = Number(process.env.CHAIN_ID ?? 4663);
const rpcUrl = process.env.PRODUCTION_RPC_URL ?? process.env.ROBINHOOD_RPC_URL ?? process.env.RPC_URL;
const rawKey = process.env.DEPLOYER_PRIVATE_KEY;
const dev = process.env.SEALEDCASH_DEV === "1";
const production = process.env.NODE_ENV === "production" || process.env.SEALEDCASH_RELEASE === "production";

if (!rpcUrl) throw new Error("RPC_URL is required.");
if (!rawKey) throw new Error("DEPLOYER_PRIVATE_KEY is required.");
if (production && dev) {
  throw new Error("Refusing development Groth16 parameters on production/mainnet.");
}
if (production && dev) throw new Error("Development Groth16 artifacts are forbidden for production.");
const manifestPath = process.env.SEALEDCASH_PRODUCTION_MANIFEST ?? "circuits/production-ultrahonk-release.json";
const manifest = production ? JSON.parse(await readFile(new URL(manifestPath, root)).catch(() => "{}")) : {};
if (production && (manifest.status !== "ready" || manifest.setup !== "transparent" || manifest.proofSystem !== "ultrahonk" || manifest.productionSafe !== true)) {
  throw new Error("A ready, production-safe transparent-setup UltraHonk manifest is required.");
}
const key = rawKey.startsWith("0x") ? rawKey : `0x${rawKey}`;
if (!/^0x[0-9a-fA-F]{64}$/.test(key)) throw new Error("DEPLOYER_PRIVATE_KEY must be 32-byte hex.");

const account = privateKeyToAccount(key);
const chain = {
  id: chainId, name: process.env.CHAIN_NAME ?? "SealedCash network",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: [rpcUrl] } },
};
const transport = http(rpcUrl);
const publicClient = createPublicClient({ chain, transport });
const walletClient = createWalletClient({ account, chain, transport });
if (await publicClient.getChainId() !== chainId) throw new Error("RPC chain mismatch.");
if (production && chainId !== 4663) throw new Error("Production deployments are restricted to chain 4663.");
const admin = process.env.SEALEDCASH_ADMIN_ADDRESS;
const pauser = process.env.SEALEDCASH_PAUSER_ADDRESS;
if (production && (!admin || !pauser || admin.toLowerCase() === account.address.toLowerCase() || pauser.toLowerCase() === account.address.toLowerCase() || admin.toLowerCase() === pauser.toLowerCase())) {
  throw new Error("Production admin and pauser must be explicit, distinct, and not the deployer.");
}
const address = (value, label) => {
  if (!/^0x[0-9a-fA-F]{40}$/.test(value ?? "") || value === zeroAddress) throw new Error(`${label} must be a non-zero address.`);
  return value;
};
const roleAbi = [
  { type: "function", name: "hasRole", stateMutability: "view", inputs: [{ type: "bytes32" }, { type: "address" }], outputs: [{ type: "bool" }] },
];

async function artifact(name, file = name) {
  return JSON.parse(await readFile(new URL(`artifacts/contracts/${file}.sol/${name}.json`, root)));
}
function artifactBytecode(artifact_, allowLinkPlaceholders = false) {
  const value = typeof artifact_.bytecode === "string" ? artifact_.bytecode : artifact_.bytecode?.object;
  if (typeof value !== "string" || !value.startsWith("0x") || value.length <= 2 ||
      (!allowLinkPlaceholders && !/^0x[0-9a-fA-F]+$/.test(value))) {
    throw new Error("Artifact has no deployable bytecode.");
  }
  return value;
}
function linkedBytecode(artifact_, libraries = {}) {
  const rawBytecode = artifactBytecode(artifact_, true);
  let bytecode = rawBytecode.slice(2);
  for (const [source, references] of Object.entries(artifact_.linkReferences ?? {})) {
    for (const [library, locations] of Object.entries(references)) {
      const libraryAddress = libraries[library];
      if (!libraryAddress) throw new Error(`Missing link address for ${source}:${library}`);
      const replacement = libraryAddress.slice(2).toLowerCase();
      for (const { start, length } of locations) {
        if (length !== 20) throw new Error(`Unsupported link length for ${library}`);
        const offset = start * 2;
        bytecode = `${bytecode.slice(0, offset)}${replacement}${bytecode.slice(offset + length * 2)}`;
      }
    }
  }
  const linked = `0x${bytecode}`;
  if (!/^0x[0-9a-fA-F]+$/.test(linked)) throw new Error("Artifact bytecode still contains unresolved library links.");
  return linked;
}
async function deploy(name, args = [], file = name, libraries = {}) {
  const a = await artifact(name, file);
  const hash = await walletClient.deployContract({ abi: a.abi, bytecode: linkedBytecode(a, libraries), args, account });
  const receipt = await publicClient.waitForTransactionReceipt({ hash, confirmations: 1 });
  if (receipt.status !== "success" || !receipt.contractAddress) throw new Error(`${name} deployment failed`);
  const runtime = await publicClient.getCode({ address: receipt.contractAddress });
  return { address: receipt.contractAddress, tx: hash, receipt, runtimeCodeHash: keccak256(runtime), abi: a.abi };
}

// The raw hasher embeds LibPoseidon2Yul and has no external Poseidon2
// dependency. Do not use the old deployed SealedCashPoseidon2Hasher: its
// poseidon2-evm hash_2 entry point is a sponge/domain hash, not Noir's raw
// [left, right, 0, 0] permutation.
const hasherName = manifest.hasher?.contractName ?? "SealedCashPoseidon2RawHasher";
const hasher = await deploy(
  hasherName,
  [],
  manifest.hasher?.artifactFile ?? hasherName,
);
const verifierName = dev ? "SealedCashDevGroth16Verifier" : (manifest.verifier?.contractName ?? "SealedCashProductionUltraHonkVerifier");
if (production && /groth16/i.test(verifierName) ) throw new Error("Production verifier cannot be a Groth16 artifact.");
let verifierLibraries = {};
let deployedVerifierLibraries = {};
if (!dev && verifierName === "HonkVerifier") {
  const artifactFile = manifest.verifier?.artifactFile ?? "generated/SealedCashUltraHonkVerifier";
  const relations = await deploy("RelationsLib", [], artifactFile);
  const transcript = await deploy("ZKTranscriptLib", [], artifactFile);
  verifierLibraries = { RelationsLib: relations.address, ZKTranscriptLib: transcript.address };
  deployedVerifierLibraries = { relations, transcript };
}
const verifier = await deploy(
  verifierName,
  [],
  manifest.verifier?.artifactFile ?? verifierName,
  verifierLibraries,
);
const adapterName = manifest.adapter?.contractName ?? "SealedCashUltraHonkAdapter";
const adapter = await deploy(adapterName, [verifier.address], manifest.adapter?.artifactFile ?? adapterName);
const pool = await deploy("SealedCashPrivacyPool", [
  production ? address(admin, "SEALEDCASH_ADMIN_ADDRESS") : account.address,
  production ? address(pauser, "SEALEDCASH_PAUSER_ADDRESS") : account.address,
  adapter.address, hasher.address,
]);
const poolCode = await publicClient.getCode({ address: pool.address });
if (!poolCode || poolCode === "0x") throw new Error("Pool has no runtime bytecode.");
const defaultAdminRole = `0x${"00".repeat(32)}`;
const pauserRole = keccak256(new TextEncoder().encode("PAUSER_ROLE"));
if (production) {
  const [adminGranted, pauserGranted] = await Promise.all([
    publicClient.readContract({ address: pool.address, abi: roleAbi, functionName: "hasRole", args: [defaultAdminRole, admin] }),
    publicClient.readContract({ address: pool.address, abi: roleAbi, functionName: "hasRole", args: [pauserRole, pauser] }),
  ]);
  if (!adminGranted || !pauserGranted) throw new Error("Configured production admin/pauser roles were not granted.");
}

const record = {
  schemaVersion: 2, chainId, deployer: account.address,
  admin: production ? admin : account.address, pauser: production ? pauser : account.address,
  paused: true, enabledAssets: [], development: dev, proofSystem: production ? "ultrahonk" : "groth16",
  deploymentBlock: Number(pool.receipt.blockNumber),
  deploymentHash: pool.receipt.blockHash,
  hasher, verifierLibraries: deployedVerifierLibraries,
  generatedVerifier: verifier, adapter, pool, receipts: {
    hasher: hasher.receipt, generatedVerifier: verifier.receipt, adapter: adapter.receipt, pool: pool.receipt,
  },
  runtimeBytecodeHashes: { hasher: hasher.runtimeCodeHash, generatedVerifier: verifier.runtimeCodeHash, adapter: adapter.runtimeCodeHash, pool: keccak256(poolCode) },
};
await mkdir(new URL("../deployments/", import.meta.url), { recursive: true });
const path = new URL(`../deployments/sealedcash-${chainId}.json`, import.meta.url);
const json = JSON.stringify(record, (_key, value) => typeof value === "bigint" ? value.toString() : value, 2);
await import("node:fs/promises").then(fs => fs.writeFile(path, `${json}\n`));
console.log(json);