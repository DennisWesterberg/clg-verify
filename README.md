# @clgplatform/verify

> Standalone cryptographic verifier for CLG decision receipts. Trust math, not us.

Part of the [CLG (Causal Liability Gateway)](https://clgplatform.com) product suite — a system that makes AI actions verifiable, mandate-bound, and technically auditable through signed decision receipts, tamper-evident chaining, and independent verification.

This package verifies the integrity and authenticity of signed decision receipts produced by the CLG Platform — without contacting the platform itself.

## What it does

- **Hash verification**: Recomputes the canonical hash of receipt content and compares it to the stored `receipt_hash`.
- **Signature verification**: Validates the ECDSA-P256/SHA-256 signature using the signing key's public key.
- **Chain verification**: Checks that `previous_receipt_hashes` link receipts into an unbroken chain.
- **Zero dependencies**: Uses only `node:crypto` and `node:fs` from the Node.js standard library.

## Quick start

```bash
npm install @clgplatform/verify
```

```ts
import { verifyReceipt, staticResolver } from '@clgplatform/verify';

const result = await verifyReceipt(receipt, publicKeyPem);
console.log(result.valid); // true or false
```

## CLI usage

```bash
npm install -g @clgplatform/verify

# Verify a single receipt (fetches public key from CLG platform)
clg-verify receipt path/to/receipt.json

# Verify with a local public key
clg-verify --public-key signing-key.pem receipt receipt.json

# Verify a receipt chain
clg-verify --public-key signing-key.pem chain receipts.json

# Human-readable output
clg-verify --pretty --public-key key.pem receipt receipt.json

# Read from stdin
cat receipt.json | clg-verify --public-key key.pem receipt -
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0    | Valid   |
| 1    | Invalid |
| 2    | Error (network, file, parse) |

## Library usage

### Verify a single receipt

```ts
import { verifyReceipt, httpResolver } from '@clgplatform/verify';

const result = await verifyReceipt(receipt, httpResolver('https://api.clgplatform.com'));

if (result.valid) {
  console.log('Receipt is authentic and untampered');
} else {
  console.error('Verification failed:', result.errors);
}
```

### Verify a chain

```ts
import { verifyChain, fileResolver } from '@clgplatform/verify';

const receipts = JSON.parse(fs.readFileSync('chain.json', 'utf-8'));
const result = await verifyChain(receipts, fileResolver('./signing-key.pem'));

console.log(`Chain: ${result.length} receipts, valid: ${result.valid}`);
if (result.chainErrors.length > 0) {
  console.error('Chain errors:', result.chainErrors);
}
```

## Resolvers

Resolvers fetch the public key needed to verify signatures:

| Resolver | Description |
|----------|-------------|
| `httpResolver(baseUrl?)` | Fetches from `{baseUrl}/v1/keys/{kid}`. Default: CLG platform API. |
| `jwksResolver(url?)` | Fetches JWKS-like key set from `{url}`. Caches after first call. |
| `staticResolver(pem)` | Returns the same PEM key for any signing_key_id. |
| `fileResolver(path)` | Reads PEM from a file path. |

You can also pass a PEM string directly instead of a resolver.

## How verification works

1. **Content extraction**: All fields except `receipt_hash`, `signature_value`, and `signing_key_id` are extracted.
2. **Canonicalization**: Object keys are sorted recursively, timestamps normalized to second precision, unicode NFC-normalized.
3. **Hash computation**: SHA-256 of the canonical JSON produces a deterministic hash.
4. **Hash comparison**: The computed hash must match `receipt_hash` stored in the receipt.
5. **Signature check**: The `signature_value` (base64 DER) is verified against `receipt_hash` using the signer's ECDSA-P256 public key.
6. **Chain linking**: For chains, each receipt's `previous_receipt_hashes` must include the preceding receipt's hash.

If any step fails, the receipt (or chain) is marked invalid with specific error messages.

## Status

**Beta** — API may change before 1.0.0 stable.

## License

[Business Source License 1.1](./LICENSE)
