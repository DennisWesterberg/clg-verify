import { describe, expect, it } from 'vitest';
import { verifyReceipt } from '../src/verifyReceipt.js';
import { buildReceipt, generateTestKeyPair } from './helpers.js';

describe('verifyReceipt', () => {
  const { publicKey, privateKey } = generateTestKeyPair();

  it('verifies a valid receipt', async () => {
    const receipt = buildReceipt(
      {
        task_id: 't1',
        workflow_id: 'w1',
        decision_type: 'tool-call',
        decision_outcome: 'approve',
        timestamp: '2026-04-07T12:00:00Z',
      },
      privateKey,
    );

    const result = await verifyReceipt(receipt, publicKey);
    expect(result.valid).toBe(true);
    expect(result.checks.hashMatchesContent).toBe(true);
    expect(result.checks.signatureValid).toBe(true);
    expect(result.checks.requiredFieldsPresent).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it('detects tampered content (hash mismatch)', async () => {
    const receipt = buildReceipt(
      { task_id: 't1', decision_outcome: 'approve' },
      privateKey,
    );
    // Tamper with content
    receipt.decision_outcome = 'deny';

    const result = await verifyReceipt(receipt, publicKey);
    expect(result.valid).toBe(false);
    expect(result.checks.hashMatchesContent).toBe(false);
    expect(result.errors.some((e) => e.includes('hash mismatch'))).toBe(true);
  });

  it('detects invalid signature', async () => {
    const receipt = buildReceipt(
      { task_id: 't1', decision_outcome: 'approve' },
      privateKey,
    );
    // Corrupt signature
    receipt.signature_value = 'AAAA' + receipt.signature_value.slice(4);

    const result = await verifyReceipt(receipt, publicKey);
    expect(result.valid).toBe(false);
    expect(result.checks.signatureValid).toBe(false);
  });

  it('detects wrong public key', async () => {
    const otherKeys = generateTestKeyPair();
    const receipt = buildReceipt(
      { task_id: 't1', decision_outcome: 'approve' },
      privateKey,
    );

    const result = await verifyReceipt(receipt, otherKeys.publicKey);
    expect(result.valid).toBe(false);
    expect(result.checks.signatureValid).toBe(false);
  });

  it('detects missing required fields', async () => {
    // Manually construct receipt without signing_key_id
    const result = await verifyReceipt(
      {
        receipt_hash: 'abc',
        signature_value: 'def',
        signing_key_id: '',
      },
      publicKey,
    );
    expect(result.valid).toBe(false);
    expect(result.checks.requiredFieldsPresent).toBe(false);
    expect(result.errors.some((e) => e.includes('signing_key_id'))).toBe(true);
  });

  it('handles resolver function', async () => {
    const receipt = buildReceipt({ task_id: 't1' }, privateKey, 'key-42');

    const resolver = async (kid: string) => {
      expect(kid).toBe('key-42');
      return publicKey;
    };

    const result = await verifyReceipt(receipt, resolver);
    expect(result.valid).toBe(true);
  });

  it('handles resolver error', async () => {
    const receipt = buildReceipt({ task_id: 't1' }, privateKey);

    const failResolver = async () => {
      throw new Error('key not found');
    };

    const result = await verifyReceipt(receipt, failResolver);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('key not found'))).toBe(true);
  });
});
