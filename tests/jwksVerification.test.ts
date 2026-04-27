import { describe, expect, it, beforeAll, afterAll } from 'vitest';
import { createServer } from 'node:http';
import { generateKeyPairSync, createSign, createPublicKey } from 'node:crypto';
import { fetchJwks, findKeyByKid } from '../src/jwksClient.js';
import { jwkToPem } from '../src/jwkToPem.js';
import { verifyReceiptWithJwks } from '../src/verifyReceipt.js';
import { buildReceipt, generateTestKeyPair } from './helpers.js';
import type { JsonWebKey, JwksResponse } from '../src/types.js';

function pemToJwk(publicKeyPem: string, kid: string): JsonWebKey {
  const keyObj = createPublicKey(publicKeyPem);
  const jwk = keyObj.export({ format: 'jwk' }) as Record<string, string>;
  return {
    kty: 'EC' as const,
    crv: 'P-256' as const,
    x: jwk.x,
    y: jwk.y,
    kid,
    use: 'sig' as const,
    alg: 'ES256' as const,
  };
}

describe('JWKS Verification', () => {
  const kp = generateTestKeyPair();
  const kid = 'test-key-jwks';
  const jwk = pemToJwk(kp.publicKey, kid);
  const jwksPayload: JwksResponse = { keys: [jwk] };

  let server: ReturnType<typeof createServer>;
  let baseUrl: string;

  beforeAll(async () => {
    server = createServer((req, res) => {
      if (req.url === '/.well-known/jwks.json') {
        res.writeHead(200, { 'Content-Type': 'application/jwk-set+json' });
        res.end(JSON.stringify(jwksPayload));
      } else {
        res.writeHead(404);
        res.end();
      }
    });
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve());
    });
    const addr = server.address() as { port: number };
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });

  afterAll(() => {
    server.close();
  });

  it('Test A: fetchJwks parses valid JWKS response', async () => {
    const result = await fetchJwks(baseUrl);
    expect(result.keys).toHaveLength(1);
    expect(result.keys[0].kty).toBe('EC');
    expect(result.keys[0].crv).toBe('P-256');
    expect(result.keys[0].kid).toBe(kid);
    expect(result.keys[0].x).toBeDefined();
    expect(result.keys[0].y).toBeDefined();
  });

  it('Test B: findKeyByKid correct lookup', async () => {
    const jwks = await fetchJwks(baseUrl);
    const found = findKeyByKid(jwks, kid);
    expect(found.kid).toBe(kid);
    expect(found.kty).toBe('EC');
  });

  it('Test C: jwkToPem produces valid PEM (verify known signature)', () => {
    const pem = jwkToPem(jwk);
    expect(pem).toContain('BEGIN PUBLIC KEY');

    // Sign something with the private key and verify with reconstructed PEM
    const hash = 'b'.repeat(64);
    const signer = createSign('SHA256');
    signer.update(Buffer.from(hash, 'hex'));
    signer.end();
    const sig = signer.sign(kp.privateKey, 'base64');

    const { createVerify } = require('node:crypto');
    const verifier = createVerify('SHA256');
    verifier.update(Buffer.from(hash, 'hex'));
    verifier.end();
    expect(verifier.verify(pem, sig, 'base64')).toBe(true);
  });

  it('Test D: verifyReceiptWithJwks end-to-end', async () => {
    const receipt = buildReceipt(
      {
        receipt_version: '1.2.0',
        workflow_id: 'wf-jwks-test',
        task_id: 'task-jwks-1',
        deployer_id: 'test-deployer',
        task_input: { question: 'does JWKS work?' },
        output: { answer: 'yes' },
        timestamp: '2026-04-27T18:00:00Z',
      },
      kp.privateKey,
      kid,
    );

    const result = await verifyReceiptWithJwks(receipt, { baseUrl });
    expect(result.valid).toBe(true);
    expect(result.checks.hashMatchesContent).toBe(true);
    expect(result.checks.signatureValid).toBe(true);
    expect(result.checks.requiredFieldsPresent).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('Test E: wrong kid → clear error', async () => {
    const receipt = buildReceipt(
      {
        receipt_version: '1.2.0',
        workflow_id: 'wf-bad-kid',
        task_id: 'task-bad-kid',
        deployer_id: 'test',
        task_input: 'test',
        output: 'test',
        timestamp: '2026-04-27T18:00:00Z',
      },
      kp.privateKey,
      'nonexistent-key-id',
    );

    const result = await verifyReceiptWithJwks(receipt, { baseUrl });
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('nonexistent-key-id'))).toBe(true);
  });
});
