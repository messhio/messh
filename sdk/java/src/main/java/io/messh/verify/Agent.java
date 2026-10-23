package io.messh.verify;

/**
 * A verified caller.
 *
 * @param identity messh username, e.g. "mukul"
 * @param keyName key name on messh, e.g. "laptop"
 * @param keyId RFC 7638 thumbprint
 * @param fingerprint SHA256:… of the SSH key
 * @param agentUrl Signature-Agent
 * @param created signature creation time, seconds since epoch
 */
public record Agent(String identity, String keyName, String keyId, String fingerprint, String agentUrl, long created) {}
