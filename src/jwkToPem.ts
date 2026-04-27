import { createPublicKey } from 'node:crypto';
import type { JsonWebKey } from './types.js';

/**
 * Convert a JWK (ECDSA-P256) back to PEM-encoded SPKI public key.
 * Uses Node.js built-in crypto — no external dependencies.
 */
export function jwkToPem(jwk: JsonWebKey): string {
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    throw new Error(`Unsupported key type: kty=${jwk.kty}, crv=${jwk.crv}`);
  }
  if (!jwk.x || !jwk.y) {
    throw new Error('JWK missing x or y coordinate');
  }
  const keyObj = createPublicKey({
    key: {
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
      y: jwk.y,
    },
    format: 'jwk',
  });
  return keyObj.export({ type: 'spki', format: 'pem' }) as string;
}
