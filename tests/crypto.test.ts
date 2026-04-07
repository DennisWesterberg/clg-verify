import { describe, expect, it } from 'vitest';
import { sha256, verifySignature } from '../src/crypto.js';
import { generateTestKeyPair, sign } from './helpers.js';

describe('sha256', () => {
  it('produces deterministic hex hash', () => {
    expect(sha256('hello')).toBe(sha256('hello'));
    expect(sha256('hello')).not.toBe(sha256('world'));
  });

  it('produces 64-char hex string', () => {
    expect(sha256('test')).toHaveLength(64);
    expect(sha256('test')).toMatch(/^[a-f0-9]{64}$/);
  });

  it('handles Buffer input', () => {
    const buf = Buffer.from('hello');
    expect(sha256(buf)).toBe(sha256('hello'));
  });
});

describe('verifySignature', () => {
  const { publicKey, privateKey } = generateTestKeyPair();

  it('returns true for valid signature', () => {
    const hash = sha256('test-data');
    const sig = sign(hash, privateKey);
    expect(verifySignature(hash, sig, publicKey)).toBe(true);
  });

  it('returns false for corrupted signature', () => {
    const hash = sha256('test-data');
    const sig = sign(hash, privateKey);
    const corrupted = 'AAA' + sig.slice(3);
    expect(verifySignature(hash, corrupted, publicKey)).toBe(false);
  });

  it('returns false for wrong key', () => {
    const other = generateTestKeyPair();
    const hash = sha256('test-data');
    const sig = sign(hash, privateKey);
    expect(verifySignature(hash, sig, other.publicKey)).toBe(false);
  });

  it('returns false for invalid PEM (does not throw)', () => {
    expect(verifySignature('abc', 'def', 'not-a-key')).toBe(false);
  });
});
