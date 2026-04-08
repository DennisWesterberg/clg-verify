import { describe, expect, it } from 'vitest';
import { verifyReceipt } from '../src/verifyReceipt.js';
import { buildReceipt, generateTestKeyPair } from './helpers.js';

describe('verifyReceipt', () => {
  const { publicKey, privateKey } = generateTestKeyPair();

  it('verifies a valid receipt', async () => {
    const receipt = buildReceipt(
      {
        receipt_kind: 'mandate_evaluation',
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
      { receipt_kind: 'mandate_evaluation', task_id: 't1', decision_outcome: 'approve' },
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
      { receipt_kind: 'mandate_evaluation', task_id: 't1', decision_outcome: 'approve' },
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
      { receipt_kind: 'mandate_evaluation', task_id: 't1', decision_outcome: 'approve' },
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

  it('verifies agent_decision receipt (no decision_outcome in hash)', async () => {
    const receipt = buildReceipt(
      {
        receipt_kind: 'agent_decision',
        task_id: 't1',
        workflow_id: 'w1',
        decision_type: 'tool-call',
        decision_value: 'calc',
        timestamp: '2026-04-08T10:00:00Z',
      },
      privateKey,
    );

    const result = await verifyReceipt(receipt, publicKey);
    expect(result.valid).toBe(true);
    expect(result.checks.hashMatchesContent).toBe(true);
    expect(result.checks.signatureValid).toBe(true);
  });

  it('ignores extra API metadata fields when computing hash', async () => {
    const receipt = buildReceipt(
      {
        receipt_kind: 'agent_decision',
        task_id: 't1',
        workflow_id: 'w1',
        timestamp: '2026-04-08T10:00:00Z',
      },
      privateKey,
    );

    // Simulate extra fields the API adds after signing
    (receipt as any).receipt_id = 'uuid-123';
    (receipt as any).agent_id = 'agent-1';
    (receipt as any).task_input = { x: 1 };
    (receipt as any).output = { y: 2 };
    (receipt as any).top_p = 0.9;
    (receipt as any).top_k = 40;
    (receipt as any).created_at = '2026-04-08T10:00:00Z';
    (receipt as any).passthrough_hash = null;
    (receipt as any).algorithm = 'ECDSA-P256';

    const result = await verifyReceipt(receipt, publicKey);
    expect(result.valid).toBe(true);
    expect(result.checks.hashMatchesContent).toBe(true);
    expect(result.checks.signatureValid).toBe(true);
  });

  it('would fail on old behavior (extra fields included in hash)', async () => {
    // This test proves the fix: if we hashed all non-signature fields
    // (old behavior), adding extra metadata would break the hash.
    const receipt = buildReceipt(
      {
        receipt_kind: 'agent_decision',
        task_id: 't1',
        workflow_id: 'w1',
      },
      privateKey,
    );

    // Add extra metadata that the old verifier would have included in hash
    (receipt as any).receipt_id = 'extra-field';
    (receipt as any).created_at = '2026-04-08T10:00:00Z';

    // New behavior: still valid (extra fields ignored)
    const result = await verifyReceipt(receipt, publicKey);
    expect(result.valid).toBe(true);
  });
});
