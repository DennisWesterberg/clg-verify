/**
 * Canonical form for CLG receipt hashing.
 *
 * Delegates to the shared implementation in @clgplatform/sdk.
 * This re-export preserves the public API of @clgplatform/verify
 * while ensuring a single source of truth for canonicalization logic.
 */
import { Canonicalizer } from '@clgplatform/sdk';

export function canonicalize(data: unknown): string {
  return Canonicalizer.canonicalize(data);
}
