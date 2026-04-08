# @clgplatform/verify

Independent verifier for CLG signed receipts and receipt chains.

![npm](https://img.shields.io/npm/v/@clgplatform/verify) ![node](https://img.shields.io/node/v/@clgplatform/verify) ![license](https://img.shields.io/badge/license-BUSL--1.1-orange)

## What it is

`@clgplatform/verify` is a verification layer for receipts emitted by CLG-integrated runtimes.
It validates receipt integrity and authenticity cryptographically.

## What it verifies

- canonical hash matches content
- signature is valid
- required fields are present
- previous receipt hashes link correctly in chains

## What it does not do

- does not intercept MCP tool calls
- does not enforce mandates
- does not create receipts
- does not replace runtime controls or governance processes

It can verify offline when you provide a local key/resolver.
By default, CLI/library flows may resolve keys over HTTP unless you pass a local resolver.

## Installation

```bash
npm install @clgplatform/verify
```

## Quick start

```ts
import { verifyReceipt, fileResolver } from '@clgplatform/verify';

const result = await verifyReceipt(receipt, fileResolver('./signing-key.pem'));
console.log(result.valid);
```

## CLI usage

```bash
# single receipt
clg-verify receipt receipt.json

# chain
clg-verify chain receipts.json

# local key file
clg-verify --public-key signing-key.pem receipt receipt.json

# JWKS-style endpoint
clg-verify --jwks https://api.clgplatform.com/.well-known/clg-keys receipt receipt.json

# force no default HTTP key lookup (requires --public-key or --jwks)
clg-verify --offline --public-key signing-key.pem receipt receipt.json

# pretty JSON output
clg-verify --pretty --public-key signing-key.pem chain receipts.json

# stdin
cat receipt.json | clg-verify --public-key signing-key.pem receipt -
```

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Valid |
| 1 | Invalid |
| 2 | Error (network, file, parse) |

## Library usage

Single receipt:

```ts
import { verifyReceipt, httpResolver } from '@clgplatform/verify';

const result = await verifyReceipt(receipt, httpResolver('https://api.clgplatform.com'));
```

Receipt chain:

```ts
import { verifyChain, jwksResolver } from '@clgplatform/verify';

const result = await verifyChain(receipts, jwksResolver('https://api.clgplatform.com/.well-known/clg-keys'));
```

## Resolvers

- `httpResolver(baseUrl?)` → fetches `{baseUrl}/v1/keys/{kid}`
- `jwksResolver(url?)` → fetches key set once and caches by `kid`
- `staticResolver(pem)` → always returns the same PEM
- `fileResolver(path)` → reads PEM from local file

You can also pass a PEM string directly to `verifyReceipt` / `verifyChain`.

## How verification works

1. Select canonical content fields.
2. Canonicalize the content.
3. Hash canonical content.
4. Compare computed hash with `receipt_hash`.
5. Verify signature with signer public key.
6. Verify `previous_receipt_hashes` links for chains.

## Use with @clgplatform/mcp

- `@clgplatform/mcp` guards MCP tool execution and creates signed receipts.
- `@clgplatform/verify` verifies those receipts afterward.

## Status

Beta.

## License

BUSL-1.1. See [`LICENSE`](./LICENSE).
