# Contributing to SealedCash Contracts

Read the code and tests before proposing changes. Keep pull requests focused,
explain security assumptions, and add regression coverage for behavior changes.

```sh
npm install
npm run build
npm test
```

Do not commit `.env` files, private keys, RPC URLs containing credentials,
deployment records, generated proof parameters, or unreviewed verifier output.
Changes to pool accounting, proof inputs, role management, pause behavior, or
token transfer handling require a clear threat-model note in the pull request.

By contributing, you agree that your work is provided under the MIT license.
Questions and support requests belong at support@sealedcash.com.
