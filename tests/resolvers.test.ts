import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { httpResolver, jwksResolver, staticResolver, fileResolver } from '../src/resolvers.js';
import { writeFileSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

describe('staticResolver', () => {
  it('returns the same key for any signing_key_id', async () => {
    const resolver = staticResolver('my-public-key-pem');
    expect(await resolver('any-id')).toBe('my-public-key-pem');
    expect(await resolver('other-id')).toBe('my-public-key-pem');
  });
});

describe('fileResolver', () => {
  const tmpPath = join(tmpdir(), 'clg-verify-test-key.pem');

  beforeEach(() => {
    writeFileSync(tmpPath, '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n');
  });

  afterEach(() => {
    try {
      unlinkSync(tmpPath);
    } catch {
      // ignore
    }
  });

  it('reads PEM from file', async () => {
    const resolver = fileResolver(tmpPath);
    const result = await resolver('any-id');
    expect(result).toContain('BEGIN PUBLIC KEY');
  });
});

describe('httpResolver', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('fetches public key from /v1/keys/:id', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        signing_key_id: 'k1',
        algorithm: 'ECDSA-P256',
        public_key_pem: 'pem-data',
      }),
    });

    const resolver = httpResolver('https://api.example.com');
    const result = await resolver('k1');
    expect(result).toBe('pem-data');
    expect(globalThis.fetch).toHaveBeenCalledWith('https://api.example.com/v1/keys/k1');
  });

  it('throws on HTTP error', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({ ok: false, status: 404 });

    const resolver = httpResolver('https://api.example.com');
    await expect(resolver('missing')).rejects.toThrow('HTTP 404');
  });

  it('throws when response lacks public_key_pem', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: async () => ({ signing_key_id: 'k1' }),
    });

    const resolver = httpResolver('https://api.example.com');
    await expect(resolver('k1')).rejects.toThrow('No public_key_pem');
  });
});

describe('jwksResolver', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('fetches and caches JWKS', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        keys: [
          { kid: 'k1', public_key_pem: 'pem1' },
          { kid: 'k2', public_key_pem: 'pem2' },
        ],
      }),
    });

    const resolver = jwksResolver('https://example.com/.well-known/clg-keys');
    expect(await resolver('k1')).toBe('pem1');
    expect(await resolver('k2')).toBe('pem2');
    // Only fetched once
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  it('throws for unknown key', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: async () => ({ keys: [{ kid: 'k1', public_key_pem: 'pem1' }] }),
    });

    const resolver = jwksResolver('https://example.com/.well-known/clg-keys');
    await expect(resolver('unknown')).rejects.toThrow('not found in JWKS');
  });

  it('throws on HTTP error', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({ ok: false, status: 500 });

    const resolver = jwksResolver('https://example.com/.well-known/clg-keys');
    await expect(resolver('k1')).rejects.toThrow('HTTP 500');
  });
});
