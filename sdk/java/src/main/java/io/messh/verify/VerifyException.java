package io.messh.verify;

import io.messh.Json;

/**
 * Verification failure. {@link #code()} and {@link #status()} follow the messh spec:
 * missing_signature, bad_signature, digest_mismatch, clock_skew, nonce_replayed,
 * unknown_key (401); untrusted (403); body_too_large (413).
 */
public class VerifyException extends RuntimeException {
  private static final long serialVersionUID = 1L;
  private final String code;
  private final int status;
  private final String detail;

  public VerifyException(String code, String detail) {
    super(code + ": " + detail);
    this.code = code;
    this.detail = detail;
    this.status = switch (code) {
      case "untrusted" -> 403;
      case "body_too_large" -> 413;
      default -> 401;
    };
  }

  public String code() {
    return code;
  }

  public int status() {
    return status;
  }

  public String detail() {
    return detail;
  }

  /** JSON error body: {"error": code, "message": …}. */
  public String toJson() {
    return "{\"error\":" + Json.quote(code) + ",\"message\":" + Json.quote(detail) + "}";
  }
}
