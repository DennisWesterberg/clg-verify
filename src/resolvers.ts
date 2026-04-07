import { readFileSync } from 'node:fs';
import type { PublicKeyResolver } from './types.js';

/**
 * Resolves public keys by fetching from the CLG platform API.
 * GET {baseUrl}/v1/keys/{signing_key_id}
 */
export function httpResolver(
  baseUrl: string = 'https://api.clgplatform.com',
): PublicKeyResolver {
  return async (signingKeyId: string): Promise<string> => {
    const url = `${baseUrl.replace(/\/$/, '')}/v1/keys/${encodeURIComponent(signingKeyId)}`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} fetching key ${signingKeyId} from ${url}`);
    }
    const data = (await res.json()) as { public_key_pem?: string };
    if (!data.public_key_pem) {
      throw new Error(`No public_key_pem in response for ${signingKeyId}`);
    }
    return data.public_key_pem;
  };
}

/**
 * Resolves public keys from a JWKS-like endpoint.
 * Fetches once and caches all keys.
 * GET {wellKnownUrl} → { keys: [{ kid, public_key_pem }] }
 */
export function jwksResolver(
  wellKnownUrl: string = 'https://api.clgplatform.com/.well-known/clg-keys',
): PublicKeyResolver {
  let cache: Map<string, string> | null = null;

  return async (signingKeyId: string): Promise<string> => {
    if (!cache) {
      const res = await fetch(wellKnownUrl);
      if (!res.ok) {
        throw new Error(`HTTP ${res.status} fetching JWKS from ${wellKnownUrl}`);
      }
      const data = (await res.json()) as {
        keys: Array<{ kid: string; public_key_pem: string }>;
      };
      cache = new Map(data.keys.map((k) => [k.kid, k.public_key_pem]));
    }
    const pem = cache.get(signingKeyId);
    if (!pem) {
      throw new Error(`Key ${signingKeyId} not found in JWKS`);
    }
    return pem;
  };
}

/**
 * Returns the same static PEM key for any signing_key_id.
 * Useful when you have the key locally and don't need network access.
 */
export function staticResolver(key: string): PublicKeyResolver {
  return async (): Promise<string> => key;
}

/**
 * Reads a PEM public key from a file path.
 */
export function fileResolver(path: string): PublicKeyResolver {
  return async (): Promise<string> => readFileSync(path, 'utf-8');
}
