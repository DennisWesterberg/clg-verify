import { describe, expect, it } from 'vitest';
import { verifyChain } from '../src/verifyChain.js';
import { buildReceipt, generateTestKeyPair } from './helpers.js';

describe('verifyChain', () => {
  const { publicKey, privateKey } = generateTestKeyPair();

  function buildChain(length: number) {
    const receipts = [];
    for (let i = 0; i < length; i++) {
      const prevHashes = i > 0 ? [receipts[i - 1].receipt_hash] : [];
      const receipt = buildReceipt(
        {
          task_id: `t${i}`,
          chain_position: i + 1,
          previous_receipt_hashes: prevHashes,
        },
        privateKey,
      );
      receipts.push(receipt);
    }
    return receipts;
  }

  it('verifies a valid 3-receipt chain', async () => {
    const chain = buildChain(3);
    const result = await verifyChain(chain, publicKey);
    expect(result.valid).toBe(true);
    expect(result.length).toBe(3);
    expect(result.chainErrors).toEqual([]);
    expect(result.receipts.every((r) => r.valid)).toBe(true);
  });

  it('handles empty chain', async () => {
    const result = await verifyChain([], publicKey);
    expect(result.valid).toBe(true);
    expect(result.length).toBe(0);
  });

  it('handles single receipt chain', async () => {
    const chain = buildChain(1);
    const result = await verifyChain(chain, publicKey);
    expect(result.valid).toBe(true);
    expect(result.length).toBe(1);
  });

  it('detects broken chain link in middle', async () => {
    const chain = buildChain(3);
    // Break the link: receipt[1] should reference receipt[0], but we change it
    chain[1].previous_receipt_hashes = ['wrong-hash'];
    // Re-sign receipt[1] so it's individually valid but chain-broken
    const resigned = buildReceipt(
      {
        task_id: 't1',
        chain_position: 2,
        previous_receipt_hashes: ['wrong-hash'],
      },
      privateKey,
    );
    chain[1] = resigned;

    const result = await verifyChain(chain, publicKey);
    expect(result.valid).toBe(false);
    expect(result.chainErrors.length).toBeGreaterThan(0);
    expect(result.chainErrors[0]).toContain('chain link broken at position 1');
    // Individual receipts should still be valid
    expect(result.receipts[0].valid).toBe(true);
    expect(result.receipts[1].valid).toBe(true);
  });

  it('detects tampered receipt in chain', async () => {
    const chain = buildChain(3);
    // Tamper with the middle receipt content
    chain[1].task_id = 'tampered';

    const result = await verifyChain(chain, publicKey);
    expect(result.valid).toBe(false);
    expect(result.receipts[1].valid).toBe(false);
    expect(result.receipts[1].checks.hashMatchesContent).toBe(false);
  });

  it('detects reordered receipts', async () => {
    const chain = buildChain(3);
    // Swap positions 1 and 2
    const tmp = chain[1];
    chain[1] = chain[2];
    chain[2] = tmp;

    const result = await verifyChain(chain, publicKey);
    expect(result.valid).toBe(false);
    expect(result.chainErrors.length).toBeGreaterThan(0);
  });
});
