import { canonicalize } from './canonicalizer.js';
import { sha256, verifySignature } from './crypto.js';
import type { Receipt, VerificationResult, PublicKeyResolver } from './types.js';
import {
  getCanonicalFields as getCanonicalFieldsFromSdk,
} from '@clgplatform/sdk';

/**
 * Canonical field definitions are imported from @clgplatform/sdk.
 * This eliminates duplication with the platform's receipt generators
 * and internal verifier.
 *
 * See sdk/src/canonicalFields.ts for the single source of truth.
 */

/** Fields that must be present in every valid receipt. */
const REQUIRED_FIELDS = ['receipt_hash', 'signature_value', 'signing_key_id'];

/**
 * Extract the signed content from a receipt by picking only canonical fields.
 * Field list comes from @clgplatform/sdk getCanonicalFields().
 */
function extractSignedContent(receipt: Receipt): Record<string, unknown> {
  const kind = receipt.receipt_kind as string | undefined;
  const fields = getCanonicalFieldsFromSdk(kind);
  const content: Record<string, unknown> = {};
  for (const field of fields) {
    if (field in receipt) {
      content[field] = receipt[field];
    }
  }
  return content;
}

/**
 * Verify a single CLG decision receipt.
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

  // Compute hash of signed content
  const signedContent = extractSignedContent(receipt);
  const canonical = canonicalize(signedContent);
  const computedHash = sha256(canonical);
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
