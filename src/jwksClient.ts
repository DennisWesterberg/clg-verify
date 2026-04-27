import type { JsonWebKey, JwksResponse } from './types.js';

/**
 * Fetch the JWKS from a CLG platform's /.well-known/jwks.json endpoint.
 */
export async function fetchJwks(baseUrl: string): Promise<JwksResponse> {
  const url = `${baseUrl.replace(/\/$/, '')}/.well-known/jwks.json`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`JWKS fetch failed: HTTP ${res.status} from ${url}`);
  }
  const data = (await res.json()) as JwksResponse;
  if (!data || !Array.isArray(data.keys)) {
    throw new Error('Invalid JWKS response: missing keys array');
  }
  return data;
}

/**
 * Find a specific key by kid in a JWKS response.
 * Throws if the key is not found.
 */
export function findKeyByKid(jwks: JwksResponse, kid: string): JsonWebKey {
  const key = jwks.keys.find(k => k.kid === kid);
  if (!key) {
    const available = jwks.keys.map(k => k.kid).join(', ');
    throw new Error(
      `Key ${kid} not found in JWKS. Available kids: ${available || '(none)'}`,
    );
  }
  return key;
}
