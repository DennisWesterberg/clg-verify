import { verifySignature } from './crypto.js';
import { computeCanonicalHash } from '@clgplatform/sdk';
import { fetchJwks, findKeyByKid } from './jwksClient.js';
import { jwkToPem } from './jwkToPem.js';
import type { Receipt, VerificationResult, PublicKeyResolver, JwksVerifyOptions } from './types.js';

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
 * Verify a single CLG decision receipt using JWKS for key resolution.
 *
 * Fetches the platform's /.well-known/jwks.json, finds the key matching
 * the receipt's signing_key_id, converts JWK→PEM, and verifies.
 *
 * This is a convenience wrapper — existing verifyReceipt() is unchanged.
 *
 * @param receipt The receipt object
 * @param options { baseUrl } — the CLG platform base URL
 */
export async function verifyReceiptWithJwks(
  receipt: Receipt,
  options: JwksVerifyOptions,
): Promise<VerificationResult> {
  const resolver: PublicKeyResolver = async (signingKeyId: string) => {
    const jwks = await fetchJwks(options.baseUrl);
    const jwk = findKeyByKid(jwks, signingKeyId);
    return jwkToPem(jwk);
  };
  return verifyReceipt(receipt, resolver);
}
