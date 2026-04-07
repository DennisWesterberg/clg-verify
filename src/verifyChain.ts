import { verifyReceipt } from './verifyReceipt.js';
import type { Receipt, ChainVerificationResult, PublicKeyResolver } from './types.js';

/**
 * Verify a chain of CLG decision receipts.
 * Checks each receipt individually and verifies that `previous_receipt_hashes`
 * in receipt N contains the `receipt_hash` of receipt N-1 (linear chain).
 *
 * @param receipts Array of receipts in chain order (oldest first)
 * @param publicKey Either a PEM string or a resolver function
 */
export async function verifyChain(
  receipts: Receipt[],
  publicKey: string | PublicKeyResolver,
): Promise<ChainVerificationResult> {
  const chainErrors: string[] = [];

  if (receipts.length === 0) {
    return { valid: true, length: 0, receipts: [], chainErrors };
  }

  const results = await Promise.all(
    receipts.map((r) => verifyReceipt(r, publicKey)),
  );

  // Verify chain links: receipt[i].previous_receipt_hashes must contain receipt[i-1].receipt_hash
  for (let i = 1; i < receipts.length; i++) {
    const prev = receipts[i - 1];
    const curr = receipts[i];
    const prevHashes = curr.previous_receipt_hashes ?? [];

    if (!prevHashes.includes(prev.receipt_hash)) {
      chainErrors.push(
        `chain link broken at position ${i}: receipt ${curr.receipt_hash} does not reference previous receipt ${prev.receipt_hash}`,
      );
    }
  }

  const allReceiptsValid = results.every((r) => r.valid);
  const valid = allReceiptsValid && chainErrors.length === 0;

  return {
    valid,
    length: receipts.length,
    receipts: results,
    chainErrors,
  };
}
