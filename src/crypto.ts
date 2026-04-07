import { createHash, createVerify } from 'node:crypto';

export function sha256(input: Buffer | string): string {
  return createHash('sha256').update(input).digest('hex');
}

/**
 * Verify an ECDSA-P256/SHA-256 signature.
 * @param receiptHash Hex-encoded SHA-256 hash of the canonicalized receipt content
 * @param signature Base64-encoded DER signature
 * @param publicKeyPem PEM-encoded SPKI public key
 */
export function verifySignature(
  receiptHash: string,
  signature: string,
  publicKeyPem: string,
): boolean {
  try {
    const verify = createVerify('SHA256');
    verify.update(Buffer.from(receiptHash, 'hex'));
    verify.end();
    return verify.verify(publicKeyPem, signature, 'base64');
  } catch {
    return false;
  }
}
