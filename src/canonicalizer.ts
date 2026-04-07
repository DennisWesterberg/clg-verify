/**
 * Canonical form for CLG receipt hashing.
 * Must match @clgplatform/sdk canonicalizer exactly.
 * If the SDK implementation changes, this must be updated in sync.
 */

function toIsoSecond(v: string): string {
  const d = new Date(v);
  if (isNaN(d.getTime())) return v;
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function normalizeValue(value: unknown): unknown {
  if (value === undefined) return null;
  if (value === null) return null;

  if (typeof value === 'string') {
    const trimmed = value.normalize('NFC').trim().replace(/\r\n/g, '\n');
    if (
      /^\d{4}-\d{2}-\d{2}T/.test(trimmed) &&
      (trimmed.endsWith('Z') || /[+-]\d{2}:?\d{2}$/.test(trimmed))
    ) {
      return toIsoSecond(trimmed);
    }
    return trimmed;
  }

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error(
        `Canonicalization error: ${value} is forbidden (NaN and Infinity not allowed)`,
      );
    }
    if (Object.is(value, -0)) return 0;
    return value;
  }

  if (typeof value === 'boolean') return value;

  if (Array.isArray(value)) return value.map(normalizeValue);

  if (typeof value === 'object') {
    const input = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(input).sort()) out[key] = normalizeValue(input[key]);
    return out;
  }

  return String(value);
}

export function canonicalize(data: unknown): Buffer {
  const normalized = normalizeValue(data);
  return Buffer.from(JSON.stringify(normalized), 'utf-8');
}
