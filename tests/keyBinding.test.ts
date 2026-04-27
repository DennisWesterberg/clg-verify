/**
 * Key Binding Tests for @clgplatform/verify 1.5.0
 *
 * Tests:
 *   1: verifyReceiptWithJwks for 1.3.0 PASS
 *   2: wrong signing_public_key_hash gives fail
 *   3: tampered signing_key_id gives not false pass
 *   4: 1.2.0 with JWKS works (keyBindingValid = null)
 */
import { describe, expect, it, beforeAll, afterAll } from 'vitest';
import { createServer } from 'node:http';
import { createPublicKey, createHash } from 'node:crypto';
import { verifyReceiptWithJwks } from '../src/verifyReceipt.js';
import { buildReceipt, generateTestKeyPair } from './helpers.js';
import { computeCanonicalHash } from '@clgplatform/sdk';
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

function computeJwkThumbprint(jwk: JsonWebKey): string {
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });
  return createHash('sha256').update(canonical, 'utf8').digest('base64url');
}

describe('Key Binding (receipt 1.3.0)', () => {
  const kpA = generateTestKeyPair();
  const kpB = generateTestKeyPair();
  const kidA = 'key-A';
  const kidB = 'key-B';
  const jwkA = pemToJwk(kpA.publicKey, kidA);
  const jwkB = pemToJwk(kpB.publicKey, kidB);
  const thumbprintA = computeJwkThumbprint(jwkA);

  const jwksPayload: JwksResponse = { keys: [jwkA, jwkB] };

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

  // Test 1: verifyReceiptWithJwks for 1.3.0 PASS
  it('Test 1: 1.3.0 receipt with correct signing_public_key_hash → valid', async () => {
    const receipt = buildReceipt(
      {
        receipt_version: '1.3.0',
        workflow_id: 'wf-kb-1',
        task_id: 'task-kb-1',
        deployer_id: 'test-deployer',
        task_input: { question: 'key binding works?' },
        output: { answer: 'yes' },
        timestamp: '2026-04-27T20:00:00Z',
        signing_public_key_hash: thumbprintA,
      },
      kpA.privateKey,
      kidA,
    );

    const result = await verifyReceiptWithJwks(receipt, { baseUrl });
    expect(result.valid).toBe(true);
    expect(result.checks.hashMatchesContent).toBe(true);
    expect(result.checks.signatureValid).toBe(true);
    expect(result.checks.keyBindingValid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  // Test 2: wrong signing_public_key_hash gives fail
  it('Test 2: wrong signing_public_key_hash → invalid with mismatch error', async () => {
    const wrongThumbprint = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const receipt = buildReceipt(
      {
        receipt_version: '1.3.0',
        workflow_id: 'wf-kb-2',
        task_id: 'task-kb-2',
        deployer_id: 'test-deployer',
        task_input: { question: 'wrong hash?' },
        output: { answer: 'fail' },
        timestamp: '2026-04-27T20:00:00Z',
        signing_public_key_hash: wrongThumbprint,
      },
      kpA.privateKey,
      kidA,
    );

    const result = await verifyReceiptWithJwks(receipt, { baseUrl });
    expect(result.valid).toBe(false);
    expect(result.checks.keyBindingValid).toBe(false);
    expect(result.errors.some(e => e.includes('signing_public_key_hash_mismatch'))).toBe(true);
  });

  // Test 3: tampered signing_key_id gives not false pass
  it('Test 3: tampered signing_key_id → no false PASS', async () => {
    const receipt = buildReceipt(
      {
        receipt_version: '1.3.0',
        workflow_id: 'wf-kb-3',
        task_id: 'task-kb-3',
        deployer_id: 'test-deployer',
        task_input: { test: 'tampered kid' },
        output: { result: 'should fail' },
        timestamp: '2026-04-27T20:00:00Z',
        signing_public_key_hash: thumbprintA,
      },
      kpA.privateKey,
      kidA, // Correctly signed with key A
    );

    // Tamper: change signing_key_id to point to key B
    const tampered = { ...receipt, signing_key_id: kidB };

    const result = await verifyReceiptWithJwks(tampered, { baseUrl });
    expect(result.valid).toBe(false);

    // Either key binding fails (B's thumbprint != A's) or signature fails (signed with A, verified with B)
    const hasKeyBindingFail = result.checks.keyBindingValid === false;
    const hasSignatureFail = result.checks.signatureValid === false;
    expect(hasKeyBindingFail || hasSignatureFail).toBe(true);

    // Explicitly: not a silent PASS
    expect(result.valid).toBe(false);
  });

  // Test 4: 1.2.0 with JWKS works (keyBindingValid = null)
  it('Test 4: 1.2.0 receipt with JWKS → keyBindingValid is null', async () => {
    const receipt = buildReceipt(
      {
        receipt_version: '1.2.0',
        workflow_id: 'wf-kb-4',
        task_id: 'task-kb-4',
        deployer_id: 'test-deployer',
        task_input: { question: 'old version?' },
        output: { answer: 'still works' },
        timestamp: '2026-04-27T20:00:00Z',
      },
      kpA.privateKey,
      kidA,
    );

    const result = await verifyReceiptWithJwks(receipt, { baseUrl });
    expect(result.valid).toBe(true);
    expect(result.checks.hashMatchesContent).toBe(true);
    expect(result.checks.signatureValid).toBe(true);
    expect(result.checks.keyBindingValid).toBeNull();
    expect(result.errors).toHaveLength(0);
  });
});
