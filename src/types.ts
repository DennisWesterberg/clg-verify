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
    /** Key binding check for receipt 1.3.0+. null for older versions or non-JWKS verification. */
    keyBindingValid?: boolean | null;
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

/**
 * A JSON Web Key (JWK) for ECDSA-P256, per RFC 7517.
 */
export interface JsonWebKey {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
  kid: string;
  use?: 'sig';
  alg?: 'ES256';
}

/**
 * A JWKS response per RFC 7517.
 */
export interface JwksResponse {
  keys: JsonWebKey[];
}

/**
 * Options for JWKS-based verification.
 */
export interface JwksVerifyOptions {
  /** CLG platform base URL, e.g. https://clgplatform.com */
  baseUrl: string;
}
