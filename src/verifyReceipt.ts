import { canonicalize } from './canonicalizer.js';
import { sha256, verifySignature } from './crypto.js';
import type { Receipt, VerificationResult, PublicKeyResolver } from './types.js';

/**
 * Canonical signed fields for receipt_version 1.1.0.
 *
 * These are the exact fields included in the `unsigned` object by the
 * platform's receipt generators before hashing. The hash is SHA-256 of
 * the canonical JSON of an object containing exactly these fields.
 *
 * Fields NOT in this list (receipt_id, receipt_kind, algorithm, agent_id,
 * task_input, output, top_p, top_k, passthrough_hash, created_at, version,
 * data_source_warnings, etc.) are metadata attached after signing and are
 * NOT part of the signed content.
 *
 * Two receipt kinds exist:
 * - `agent_decision`: 25 fields (no decision_outcome)
 * - `mandate_evaluation`: 26 fields (includes decision_outcome)
 */
const BASE_CANONICAL_FIELDS_V1_1: readonly string[] = [
  'receipt_version',
  'workflow_id',
  'task_id',
  'deployer_id',
  'model_id',
  'model_provider',
  'model_version_hash',
  'temperature',
  'task_input_hash',
  'data_sources',
  'reasoning_artifact_hash',
  'artifact_categories',
  'reasoning_steps_count',
  'tools_invoked',
  'confidence_score',
  'output_hash',
  'decision_type',
  'decision_value',
  'alternatives_considered',
  'human_override',
  'previous_receipt_hashes',
  'chain_position',
  'workflow_depth',
  'system_instruction_hash',
  'timestamp',
];

/** Additional field for mandate_evaluation receipts. */
const MANDATE_EVALUATION_EXTRA_FIELDS: readonly string[] = ['decision_outcome'];

/** Fields that must be present in every valid receipt. */
const REQUIRED_FIELDS = ['receipt_hash', 'signature_value', 'signing_key_id'];

/**
 * Determine canonical field set based on receipt kind.
 *
 * mandate_evaluation receipts include `decision_outcome` in the signed area;
 * agent_decision receipts do not.
 */
function getCanonicalFields(receipt: Receipt): readonly string[] {
  const kind = receipt.receipt_kind as string | undefined;
  if (kind === 'mandate_evaluation') {
    return [...BASE_CANONICAL_FIELDS_V1_1, ...MANDATE_EVALUATION_EXTRA_FIELDS];
  }
  return BASE_CANONICAL_FIELDS_V1_1;
}

/**
 * Extract the signed content from a receipt by picking only canonical fields.
 *
 * Only fields defined in the canonical set for this receipt kind are included.
 * This ensures that extra API-response metadata does not affect the hash computation.
 */
function extractSignedContent(receipt: Receipt): Record<string, unknown> {
  const fields = getCanonicalFields(receipt);
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
