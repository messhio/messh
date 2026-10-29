package io.messh.verify;

/**
 * A verified caller.
 *
 * @param identity messh username, e.g. "mukul"; for other agents, their origin or jwk:&lt;thumbprint&gt;
 * @param keyName key name on messh, e.g. "laptop"
 * @param keyId RFC 7638 thumbprint
 * @param fingerprint SHA256:… of the SSH key
 * @param agentUrl Signature-Agent
 * @param created signature creation time, seconds since epoch
 * @param external not a messh identity: an agent origin you trust, or inline keys
 * @param signedDirectory the key's directory response carried a valid signature by that key
 */
public record Agent(String identity, String keyName, String keyId, String fingerprint, String agentUrl, long created, boolean external,
    boolean signedDirectory) {
  /** A messh identity, as in 0.1.0. */
  public Agent(String identity, String keyName, String keyId, String fingerprint, String agentUrl, long created) {
    this(identity, keyName, keyId, fingerprint, agentUrl, created, false, false);
  }
}
