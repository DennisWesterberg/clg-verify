import { describe, expect, it } from 'vitest';
import { canonicalize } from '../src/canonicalizer.js';

describe('canonicalizer', () => {
  it('sorts object keys deterministically', () => {
    const a = canonicalize({ z: 1, a: 2, m: 3 });
    const b = canonicalize({ m: 3, z: 1, a: 2 });
    expect(a.toString()).toBe(b.toString());
    expect(JSON.parse(a.toString())).toEqual({ a: 2, m: 3, z: 1 });
  });

  it('handles nested objects', () => {
    const result = canonicalize({ b: { d: 1, c: 2 }, a: 0 });
    expect(JSON.parse(result.toString())).toEqual({ a: 0, b: { c: 2, d: 1 } });
  });

  it('handles arrays (preserves order)', () => {
    const result = canonicalize([3, 1, 2]);
    expect(JSON.parse(result.toString())).toEqual([3, 1, 2]);
  });

  it('normalizes null and undefined to null', () => {
    const a = canonicalize({ x: null });
    const b = canonicalize({ x: undefined });
    expect(a.toString()).toBe(b.toString());
  });

  it('normalizes -0 to 0', () => {
    const result = canonicalize({ val: -0 });
    expect(result.toString()).toBe('{"val":0}');
  });

  it('throws on NaN', () => {
    expect(() => canonicalize({ val: NaN })).toThrow('forbidden');
  });

  it('throws on Infinity', () => {
    expect(() => canonicalize({ val: Infinity })).toThrow('forbidden');
  });

  it('handles unicode strings (NFC normalization)', () => {
    // é as e + combining accent vs precomposed
    const a = canonicalize({ text: 'caf\u0065\u0301' });
    const b = canonicalize({ text: 'caf\u00e9' });
    expect(a.toString()).toBe(b.toString());
  });

  it('normalizes ISO timestamps to seconds precision', () => {
    const a = canonicalize({ ts: '2026-01-01T12:00:00.123Z' });
    const b = canonicalize({ ts: '2026-01-01T12:00:00.999Z' });
    expect(a.toString()).toBe(b.toString());
    expect(JSON.parse(a.toString()).ts).toBe('2026-01-01T12:00:00Z');
  });

  it('returns Buffer', () => {
    const result = canonicalize('hello');
    expect(Buffer.isBuffer(result)).toBe(true);
  });

  it('handles deeply nested structures', () => {
    const input = { a: [{ z: 1, a: { c: 3, b: 2 } }] };
    const result = JSON.parse(canonicalize(input).toString());
    expect(Object.keys(result.a[0].a)).toEqual(['b', 'c']);
  });
});
