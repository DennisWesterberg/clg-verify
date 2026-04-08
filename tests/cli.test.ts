import { describe, expect, it, beforeAll, afterAll } from 'vitest';
import { execSync } from 'node:child_process';
import { writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { generateTestKeyPair } from './helpers.js';
import { buildReceipt } from './helpers.js';

describe('CLI', () => {
  const dir = join(tmpdir(), 'clg-verify-cli-test');
  const { publicKey, privateKey } = generateTestKeyPair();
  const cliPath = join(process.cwd(), 'dist', 'cli.js');
  let receiptFile: string;
  let chainFile: string;
  let keyFile: string;

  beforeAll(() => {
    mkdirSync(dir, { recursive: true });

    keyFile = join(dir, 'test.pem');
    writeFileSync(keyFile, publicKey);

    const receipt = buildReceipt(
      { receipt_kind: 'mandate_evaluation', task_id: 't1', decision_outcome: 'approve' },
      privateKey,
    );
    receiptFile = join(dir, 'receipt.json');
    writeFileSync(receiptFile, JSON.stringify(receipt));

    const r1 = buildReceipt(
      { task_id: 't1', chain_position: 1, previous_receipt_hashes: [] },
      privateKey,
    );
    const r2 = buildReceipt(
      { task_id: 't2', chain_position: 2, previous_receipt_hashes: [r1.receipt_hash] },
      privateKey,
    );
    chainFile = join(dir, 'chain.json');
    writeFileSync(chainFile, JSON.stringify([r1, r2]));
  });

  afterAll(() => {
    try {
      unlinkSync(receiptFile);
      unlinkSync(chainFile);
      unlinkSync(keyFile);
    } catch {
      // ignore
    }
  });

  it('--version returns version', () => {
    const out = execSync(`node ${cliPath} --version`).toString().trim();
    expect(out).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('--help returns usage', () => {
    const out = execSync(`node ${cliPath} --help`).toString();
    expect(out).toContain('clg-verify');
    expect(out).toContain('receipt');
    expect(out).toContain('chain');
  });

  it('verifies valid receipt with --public-key', () => {
    const out = execSync(`node ${cliPath} --public-key ${keyFile} receipt ${receiptFile}`).toString();
    const result = JSON.parse(out);
    expect(result.valid).toBe(true);
  });

  it('verifies valid chain with --public-key', () => {
    const out = execSync(`node ${cliPath} --public-key ${keyFile} chain ${chainFile}`).toString();
    const result = JSON.parse(out);
    expect(result.valid).toBe(true);
    expect(result.length).toBe(2);
  });

  it('exits 1 for invalid receipt', () => {
    const badFile = join(dir, 'bad.json');
    writeFileSync(badFile, JSON.stringify({
      receipt_hash: 'wrong',
      signature_value: 'wrong',
      signing_key_id: 'k1',
      task_id: 'bad',
    }));

    try {
      execSync(`node ${cliPath} --public-key ${keyFile} receipt ${badFile}`, { stdio: 'pipe' });
      expect.fail('should have exited with code 1');
    } catch (e: unknown) {
      const err = e as { status: number; stdout: Buffer };
      expect(err.status).toBe(1);
      const result = JSON.parse(err.stdout.toString());
      expect(result.valid).toBe(false);
    } finally {
      try { unlinkSync(badFile); } catch { /* */ }
    }
  });

  it('exits 2 for missing file', () => {
    try {
      execSync(`node ${cliPath} --public-key ${keyFile} receipt /nonexistent.json`, { stdio: 'pipe' });
      expect.fail('should have exited');
    } catch (e: unknown) {
      expect((e as { status: number }).status).toBe(2);
    }
  });
});
