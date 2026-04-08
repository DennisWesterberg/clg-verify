import { createSign, generateKeyPairSync, createHash } from 'node:crypto';

export function generateTestKeyPair() {
  return generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

export function sha256(input: Buffer | string): string {
  return createHash('sha256').update(input).digest('hex');
}

export function sign(hash: string, privateKeyPem: string): string {
  const s = createSign('SHA256');
  s.update(Buffer.from(hash, 'hex'));
  s.end();
  return s.sign(privateKeyPem, 'base64');
}

/**
 * Canonical signed fields for receipt_version 1.1.0.
 * Must match the verifier's field list exactly.
 */
const BASE_CANONICAL_FIELDS = [
  'receipt_version', 'workflow_id', 'task_id', 'deployer_id', 'model_id',
  'model_provider', 'model_version_hash', 'temperature', 'task_input_hash',
  'data_sources', 'reasoning_artifact_hash', 'artifact_categories',
  'reasoning_steps_count', 'tools_invoked', 'confidence_score', 'output_hash',
  'decision_type', 'decision_value', 'alternatives_considered', 'human_override',
  'previous_receipt_hashes', 'chain_position', 'workflow_depth',
  'system_instruction_hash', 'timestamp',
];

/**
 * Build a valid receipt with correct hash and signature.
 *
 * Only canonical fields (as defined by the receipt_kind) are included in
 * the hash, mirroring the platform's receipt generators.
 */
export function buildReceipt(
  content: Record<string, unknown>,
  privateKeyPem: string,
  signingKeyId = 'test-key-1',
) {
  // Determine canonical fields based on receipt_kind
  const isMandateEval = content.receipt_kind === 'mandate_evaluation';
  const canonicalFields = isMandateEval
    ? [...BASE_CANONICAL_FIELDS, 'decision_outcome']
    : BASE_CANONICAL_FIELDS;

  // Extract only canonical fields that exist in content
  const signedContent: Record<string, unknown> = {};
  for (const field of canonicalFields) {
    if (field in content) {
      signedContent[field] = content[field];
    }
  }

  const sorted = sortDeep(signedContent);
  const canonical = Buffer.from(JSON.stringify(sorted), 'utf-8');
  const receiptHash = sha256(canonical);
  const signatureValue = sign(receiptHash, privateKeyPem);

  return {
    ...content,
    receipt_hash: receiptHash,
    signature_value: signatureValue,
    signing_key_id: signingKeyId,
  };
}

function sortDeep(value: unknown): unknown {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) return value.map(sortDeep);
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) {
      out[key] = sortDeep(obj[key]);
    }
    return out;
  }
  return value;
}
