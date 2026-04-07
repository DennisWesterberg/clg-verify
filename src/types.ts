/**
 * A CLG decision receipt as returned by the platform.
 * Only the fields relevant for verification are typed here.
 */
export interface Receipt {
  receipt_hash: string;
  signature_value: string;
  signing_key_id: string;
  algorithm?: string;
  previous_receipt_hashes?: string[];
  /** All other fields are part of the signed content */
  [key: string]: unknown;
}

/**
 * Result of verifying a single receipt.
 */
export interface VerificationResult {
  valid: boolean;
  receipt_id: string | undefined;
  receipt_hash: string;
  checks: {
    hashMatchesContent: boolean;
    signatureValid: boolean;
    requiredFieldsPresent: boolean;
  };
  errors: string[];
}

/**
 * Result of verifying a chain of receipts.
 */
export interface ChainVerificationResult {
  valid: boolean;
  length: number;
  receipts: VerificationResult[];
  chainErrors: string[];
}

/**
 * Resolves a signing key ID to its PEM-encoded public key.
 */
export type PublicKeyResolver = (signing_key_id: string) => Promise<string>;
