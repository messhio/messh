/**
 * Client-side error: invalid_identity, invalid_key, invalid_option,
 * sign_failed; from whoami(): not_published, registry_unreachable.
 */
export class MesshError extends Error {
  constructor(readonly code: string, message: string) {
    super(`${code}: ${message}`);
    this.name = "MesshError";
  }
}

/**
 * Verification failure. Codes follow the messh spec: missing_signature,
 * bad_signature, digest_mismatch, clock_skew, nonce_replayed, unknown_key
 * (401); untrusted (403); body_too_large (413).
 */
export class VerifyError extends Error {
  constructor(readonly code: string, readonly detail: string, readonly status = 401) {
    super(`${code}: ${detail}`);
    this.name = "VerifyError";
  }
  toJSON() {
    return { error: this.code, message: this.detail };
  }
}
