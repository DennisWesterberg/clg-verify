import { createSign, generateKeyPairSync, createHash } from 'node:crypto';
import { computeCanonicalHash } from '@clgplatform/sdk';

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
 *
 * Uses the SDK's computeCanonicalHash to produce the hash — this is
 * the same code path used by the platform's receipt generators and
 * the verifier, ensuring test fixtures match real receipts exactly.
 */
export function buildReceipt(
  content: Record<string, unknown>,
  privateKeyPem: string,
  signingKeyId = 'test-key-1',
) {
  const receiptHash = computeCanonicalHash(content);
  const signatureValue = sign(receiptHash, privateKeyPem);

  return {
    ...content,
    receipt_hash: receiptHash,
    signature_value: signatureValue,
    signing_key_id: signingKeyId,
  };
}
