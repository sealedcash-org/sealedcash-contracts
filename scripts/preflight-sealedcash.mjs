import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createPublicClient, http, keccak256, getAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const root = new URL("..", import.meta.url);
const failures = [];
const checks = {};
const fail = (name, reason) => { checks[name] = { ok: false, reason }; failures.push(`${name}: ${reason}`); };
const pass = (name, details = "ok") => { checks[name] = { ok: true, details }; };
const env = (name) => process.env[name]?.trim();
const address = (value) => /^0x[0-9a-f]{40}$/i.test(value ?? "");
const hash = (value) => /^[a-f0-9]{64}$/i.test(value ?? "");

const rpc = env("PRODUCTION_RPC_URL") ?? env("ROBINHOOD_RPC_URL") ?? env("RPC_URL");
const chainId = Number(env("CHAIN_ID") ?? 4663);
if (!rpc) fail("productionRpc", "PRODUCTION_RPC_URL is required");
if (chainId !== 4663) fail("chain", "chain must be 4663");
let client;
if (rpc) {
  try {
    client = createPublicClient({ transport: http(rpc, { timeout: 15_000 }) });
    if (await client.getChainId() !== 4663) fail("productionRpc", "RPC chain is not 4663");
    else pass("productionRpc");
  } catch (error) { fail("productionRpc", "RPC unavailable"); }
}

const key = env("DEPLOYER_PRIVATE_KEY");
let deployer;
if (!key || !/^(?:0x)?[0-9a-f]{64}$/i.test(key)) fail("deployer", "deployer key is not configured");
else {
  deployer = privateKeyToAccount(key.startsWith("0x") ? key : `0x${key}`);
  if (client) {
    try {
      const balance = await client.getBalance({ address: deployer.address });
      if (balance === 0n) fail("deployerBalance", "deployer has no native balance");
      else pass("deployerBalance");
    } catch { fail("deployerBalance", "cannot read deployer balance"); }
  }
}
const admin = env("SEALEDCASH_ADMIN_ADDRESS");
const pauser = env("SEALEDCASH_PAUSER_ADDRESS");
if (!address(admin) || !address(pauser) || !deployer || admin.toLowerCase() === deployer?.address.toLowerCase() || pauser.toLowerCase() === deployer?.address.toLowerCase() || admin.toLowerCase() === pauser.toLowerCase()) {
  fail("roles", "admin and pauser must be distinct non-deployer addresses");
} else if (client && env("SEALEDCASH_CONTRACT_ADDRESS")) {
  const hasRoleAbi = [{ type: "function", name: "hasRole", stateMutability: "view", inputs: [{ type: "bytes32" }, { type: "address" }], outputs: [{ type: "bool" }] }];
  try {
    const pauserRole = keccak256(new TextEncoder().encode("PAUSER_ROLE"));
    const [a, p] = await Promise.all([
      client.readContract({ address: getAddress(env("SEALEDCASH_CONTRACT_ADDRESS")), abi: hasRoleAbi, functionName: "hasRole", args: [`0x${"00".repeat(32)}`, getAddress(admin)] }),
      client.readContract({ address: getAddress(env("SEALEDCASH_CONTRACT_ADDRESS")), abi: hasRoleAbi, functionName: "hasRole", args: [pauserRole, getAddress(pauser)] }),
    ]);
    if (!a || !p) fail("roles", "on-chain admin/pauser role check failed"); else pass("roles");
  } catch { fail("roles", "cannot verify on-chain roles"); }
}

const manifestPath = env("SEALEDCASH_PRODUCTION_MANIFEST") ?? "circuits/production-ultrahonk-release.json";
try {
  const manifest = JSON.parse(await readFile(new URL(manifestPath, root), "utf8"));
  if (manifest.status !== "ready" || manifest.productionSafe !== true || manifest.setup !== "transparent" || manifest.proofSystem !== "ultrahonk") fail("artifactManifest", "manifest is not a ready transparent UltraHonk release");
  else if (JSON.stringify(manifest).match(/groth16/i)) fail("artifactManifest", "production manifest contains a Groth16 artifact");
  else pass("artifactManifest");
  for (const [name, item] of Object.entries(manifest.artifacts ?? {})) {
    if (!item?.path || !hash(item.sha256)) { fail(`artifact:${name}`, "missing path or SHA-256"); continue; }
    try {
      const actual = createHash("sha256").update(await readFile(new URL(item.path, root))).digest("hex");
      if (actual !== item.sha256.toLowerCase()) fail(`artifact:${name}`, "SHA-256 mismatch"); else pass(`artifact:${name}`);
    } catch { fail(`artifact:${name}`, "artifact cannot be read"); }
  }
} catch { fail("artifactManifest", "production manifest cannot be read"); }

for (const [name, variable] of [["prover", "SEALEDCASH_PROVER_URL"], ["relayer", "SEALEDCASH_RELAYER_URL"], ["indexer", "SEALEDCASH_INDEXER_URL"]]) {
  const endpoint = env(variable);
  if (!endpoint || !/^https?:\/\//i.test(endpoint)) { fail(name, `${variable} is required`); continue; }
  try { const response = await fetch(`${endpoint.replace(/\/$/, "")}/health`, { signal: AbortSignal.timeout(8_000) }); if (!response.ok) throw new Error(); pass(name); }
  catch { fail(name, "health endpoint unavailable"); }
}
if (!env("SEALEDCASH_RECOVERY_CONTACTS") || !env("SEALEDCASH_RECOVERY_CONFIG_SHA256") || !hash(env("SEALEDCASH_RECOVERY_CONFIG_SHA256"))) fail("recovery", "recovery contacts and config hash are required");
else pass("recovery");

const report = { schemaVersion: 1, generatedAt: new Date().toISOString(), chainId, status: failures.length ? "blocked" : "ready", checks, failures };
const reportPath = env("SEALEDCASH_RELEASE_REPORT") ?? "deployments/sealedcash-preflight.json";
await mkdir(new URL(".", new URL(reportPath, root)), { recursive: true });
await writeFile(new URL(reportPath, root), `${JSON.stringify(report, null, 2)}\n`);
if (failures.length) throw new Error(`SealedCash preflight blocked (${failures.length} failures); report written.`);
console.log(JSON.stringify(report));