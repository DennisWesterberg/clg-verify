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
 * Build a valid receipt with correct hash and signature.
 */
export function buildReceipt(
  content: Record<string, unknown>,
  privateKeyPem: string,
  signingKeyId = 'test-key-1',
) {
  // Canonicalize: sort keys, JSON.stringify
  const sorted = sortDeep(content);
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
