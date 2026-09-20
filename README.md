# SealedCash Contracts

Production Solidity boundaries for SealedCash: a privacy-pool settlement
contract, a transparent signed-intent escrow, field-checked Poseidon adapters,
and the setup-free Noir/UltraHonk verifier adapter.

**Official organization:** https://github.com/sealedcash-org  
**Support:** support@sealedcash.com

**Repository:** https://github.com/sealedcash-org/sealedcash-contracts

## Capability and status

This package currently provides local-buildable Solidity contracts and tests
for the privacy-pool and escrow mechanisms described below. It does **not**
provide a live bridge, a hosted relayer, a production proof release, a
deployed contract address, or an audit. The setup-free verifier adapter is an
integration boundary; a generated verifier and independently reviewed circuit
release must be supplied before any production use.

This repository contains contracts and local tests. It does not claim that any
deployment is live, audited, or safe for real funds. No deployed addresses,
RPC endpoints, proof manifests, or private keys belong in this repository.

## Scope

- `SealedCashPrivacyPool.sol` maintains a bounded commitment tree, recent root
  history, nullifier set, asset liabilities, encrypted-output hashes, and a
  fail-closed verifier boundary.
- `SealedCashEscrow.sol` settles EIP-712 signed swap intents atomically with
  explicit token allowlists, fee ceilings, pause controls, and excess recovery.
- `SealedCashUltraHonkAdapter.sol` converts the pool's typed public inputs into
  the generated verifier ABI. The generated verifier itself is supplied by a
  separately reviewed circuit release.
- Poseidon adapters are explicit; the raw Poseidon2 permutation is the one
  compatible with the Noir circuit boundary.

The test doubles under `contracts/mocks` are test-only and must never be
configured in a production deployment.

## Development

Use Node.js 20 or newer and a package manager that honors the pinned manifest.

```sh
cp .env.example .env
npm install
npm run build
npm test
```

### Environment variables

| Variable | Local value | Purpose |
| --- | --- | --- |
| `RPC_URL` | empty placeholder | RPC endpoint for an explicitly approved deployment |
| `CHAIN_ID` | `4663` | Expected chain identifier |
| `CHAIN_NAME` | empty placeholder | Human-readable chain name |
| `DEPLOYER_PRIVATE_KEY` | empty placeholder | Deployment signer, supplied only by a secret manager |
| `SEALEDCASH_RELEASE` | `development` | Deployment safety mode |
| `SEALEDCASH_PRODUCTION_MANIFEST` | empty placeholder | Reviewed UltraHonk release manifest path |
| `SEALEDCASH_ADMIN_ADDRESS` | empty placeholder | Distinct production admin |
| `SEALEDCASH_PAUSER_ADDRESS` | empty placeholder | Distinct production pauser |

The checked-in `.env.example` contains placeholders only. Never put real
values in `.env`, source code, issues, or pull requests.

The local Hardhat network uses chain ID `4663` so EIP-712 and domain checks
match the protocol's current source. The tests do not contact a public network.

## Deployment safety

Deployments are intentionally not turnkey. Before any real deployment:

1. Build and review the production compiler profile.
2. Obtain an independently reviewed and hashed Noir/UltraHonk release
   manifest. Do not use development Groth16 parameters.
3. Use an RPC endpoint and key supplied through a secret manager, never a
   committed file or shell history.
4. Set distinct admin and pauser addresses that are not the deployer.
5. Keep the pool paused until verifier, hasher, asset configuration, and
   collateral accounting have been independently checked.
6. Record deployment receipts and runtime hashes outside this repository.

`npm run preflight` validates required configuration and fails closed. The
deployment script requires explicit environment values and refuses a
production flag without a ready transparent UltraHonk manifest. It is not a
substitute for an audit or operational approval.

## Releases

Releases are published from tags such as `v0.1.0` by the protected GitHub
workflow. Contract bytecode and deployment records should be attached only
after review; this source repository intentionally excludes live deployment
records.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
