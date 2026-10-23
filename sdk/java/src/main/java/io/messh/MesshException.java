package io.messh;

/**
 * Client-side error. {@link #code()}: invalid_identity, invalid_key, invalid_option, sign_failed;
 * from {@link MesshClient#whoami()}: not_published, registry_unreachable.
 */
public class MesshException extends RuntimeException {
  private static final long serialVersionUID = 1L;
  private final String code;

  public MesshException(String code, String message) {
    super(code + ": " + message);
    this.code = code;
  }

  public String code() {
    return code;
  }
}
