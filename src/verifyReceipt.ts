import { createHash } from 'node:crypto';
import { verifySignature } from './crypto.js';
import { computeCanonicalHash } from '@clgplatform/sdk';
import { fetchJwks, findKeyByKid } from './jwksClient.js';
import { jwkToPem } from './jwkToPem.js';
import type { Receipt, VerificationResult, PublicKeyResolver, JwksVerifyOptions, JsonWebKey } from './types.js';

/** Fields that must be present in every valid receipt. */
const REQUIRED_FIELDS = ['receipt_hash', 'signature_value', 'signing_key_id'];

/**
 * Verify a single CLG decision receipt.
 *
 * Hash computation uses the shared SDK canonicalization flow
 * (field selection → normalization → serialization → SHA-256).
 * This is the same code path used by the platform's internal verifier.
 *
 * @param receipt The receipt object as returned by the CLG platform
 * @param publicKey Either a PEM string or a resolver function
 */
export async function verifyReceipt(
  receipt: Receipt,
  publicKey: string | PublicKeyResolver,
): Promise<VerificationResult> {
  const errors: string[] = [];
  const receiptId = receipt.receipt_id as string | undefined;

  // Check required fields
  const requiredFieldsPresent = REQUIRED_FIELDS.every((f) => {
    const present = typeof receipt[f] === 'string' && receipt[f] !== '';
    if (!present) errors.push(`missing required field: ${f}`);
    return present;
  });

  // Compute hash using shared SDK canonicalization
  const computedHash = computeCanonicalHash(receipt as Record<string, unknown>);
  const hashMatchesContent = computedHash === receipt.receipt_hash;
  if (!hashMatchesContent) {
    errors.push(
      `hash mismatch: computed ${computedHash}, receipt says ${receipt.receipt_hash}`,
    );
  }

  // Resolve public key
  let pem: string;
  try {
    pem =
      typeof publicKey === 'string'
        ? publicKey
        : await publicKey(receipt.signing_key_id);
  } catch (e) {
    errors.push(`public key resolution failed: ${(e as Error).message}`);
    return {
      valid: false,
      receipt_id: receiptId,
      receipt_hash: receipt.receipt_hash,
      checks: { hashMatchesContent, signatureValid: false, requiredFieldsPresent },
      errors,
    };
  }

  // Verify signature
  const signatureValid = verifySignature(receipt.receipt_hash, receipt.signature_value, pem);
  if (!signatureValid) {
    errors.push('signature verification failed');
  }

  const valid = hashMatchesContent && signatureValid && requiredFieldsPresent;

  return {
    valid,
    receipt_id: receiptId,
    receipt_hash: receipt.receipt_hash,
    checks: { hashMatchesContent, signatureValid, requiredFieldsPresent },
    errors,
  };
}

/**
 * Compute a JWK thumbprint (SHA-256, base64url) matching the canonical form
 * used in receipt format 1.3.0's signing_public_key_hash.
 *
 * Canonical JSON: {"crv":"P-256","kty":"EC","x":"...","y":"..."}
 */
function computeJwkThumbprint(jwk: JsonWebKey): string {
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });
  return createHash('sha256').update(canonical, 'utf8').digest('base64url');
}

/**
 * Verify a single CLG decision receipt using JWKS for key resolution.
 *
 * Fetches the platform's /.well-known/jwks.json, finds the key matching
 * the receipt's signing_key_id, converts JWK→PEM, and verifies.
 *
 * For receipt version 1.3.0+, also verifies key binding: the receipt's
 * signing_public_key_hash must match the JWK thumbprint.
 *
 * @param receipt The receipt object
 * @param options { baseUrl } — the CLG platform base URL
 */
export async function verifyReceiptWithJwks(
  receipt: Receipt,
  options: JwksVerifyOptions,
): Promise<VerificationResult> {
  const errors: string[] = [];
  const receiptId = receipt.receipt_id as string | undefined;
  const receiptVersion = (receipt.receipt_version as string) ?? '1.0.0';

  // Check required fields
  const REQUIRED_FIELDS = ['receipt_hash', 'signature_value', 'signing_key_id'];
  const requiredFieldsPresent = REQUIRED_FIELDS.every((f) => {
    const present = typeof receipt[f] === 'string' && receipt[f] !== '';
    if (!present) errors.push(`missing required field: ${f}`);
    return present;
  });

  // Compute hash using shared SDK canonicalization
  const computedHash = computeCanonicalHash(receipt as Record<string, unknown>);
  const hashMatchesContent = computedHash === receipt.receipt_hash;
  if (!hashMatchesContent) {
    errors.push(
      `hash mismatch: computed ${computedHash}, receipt says ${receipt.receipt_hash}`,
    );
  }

  // Resolve key via JWKS
  let pem: string;
  let jwk: JsonWebKey;
  try {
    const jwks = await fetchJwks(options.baseUrl);
    jwk = findKeyByKid(jwks, receipt.signing_key_id);
    pem = jwkToPem(jwk);
  } catch (e) {
    errors.push(`public key resolution failed: ${(e as Error).message}`);
    return {
      valid: false,
      receipt_id: receiptId,
      receipt_hash: receipt.receipt_hash,
      checks: { hashMatchesContent, signatureValid: false, requiredFieldsPresent, keyBindingValid: null },
      errors,
    };
  }

  // Verify signature
  const signatureValid = verifySignature(receipt.receipt_hash, receipt.signature_value, pem);
  if (!signatureValid) {
    errors.push('signature verification failed');
  }

  // Key binding check (receipt 1.3.0+)
  let keyBindingValid: boolean | null = null;
  if (receiptVersion === '1.3.0') {
    const receiptKeyHash = receipt.signing_public_key_hash as string | undefined;
    if (!receiptKeyHash) {
      keyBindingValid = false;
      errors.push('receipt version 1.3.0 missing signing_public_key_hash');
    } else {
      const computedThumbprint = computeJwkThumbprint(jwk!);
      keyBindingValid = receiptKeyHash === computedThumbprint;
      if (!keyBindingValid) {
        errors.push(`signing_public_key_hash_mismatch: receipt=${receiptKeyHash}, jwks=${computedThumbprint}`);
      }
    }
  }

  const valid = hashMatchesContent && signatureValid && requiredFieldsPresent && (keyBindingValid !== false);

  return {
    valid,
    receipt_id: receiptId,
    receipt_hash: receipt.receipt_hash,
    checks: { hashMatchesContent, signatureValid, requiredFieldsPresent, keyBindingValid },
    errors,
  };
}
