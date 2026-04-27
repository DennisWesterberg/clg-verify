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

It can verify offline when you provide a local key or resolver.
The CLI defaults to HTTP key resolution unless you pass `--public-key`, `--jwks`, or `--offline`.
Library usage resolves keys according to the PEM string or resolver you pass to `verifyReceipt` or `verifyChain`.

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

## JWKS Verification (v1.4.0+)

Verify receipts using the platform's RFC 7517 JWKS endpoint — no manual key exchange needed:

```ts
import { verifyReceiptWithJwks } from '@clgplatform/verify';

const result = await verifyReceiptWithJwks(receipt, {
  baseUrl: 'https://clgplatform.com',
});
console.log(result.valid); // true if hash + signature check out
```

This fetches `/.well-known/jwks.json`, finds the key matching the receipt's
`signing_key_id`, converts JWK→PEM, and verifies. Existing `verifyReceipt()` is unchanged.

You can also use the lower-level functions directly:

```ts
import { fetchJwks, findKeyByKid, jwkToPem } from '@clgplatform/verify';

const jwks = await fetchJwks('https://clgplatform.com');
const jwk = findKeyByKid(jwks, receipt.signing_key_id);
const pem = jwkToPem(jwk);
// use pem with verifyReceipt or your own crypto
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
