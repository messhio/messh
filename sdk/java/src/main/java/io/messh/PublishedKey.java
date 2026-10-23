package io.messh;

/**
 * This client's key as messh lists it: what an API will see. See {@link MesshClient#whoami()}.
 *
 * @param identity messh username, e.g. "mukul"
 * @param keyName the key's name on messh, e.g. "build-bot"
 * @param keyId RFC 7638 thumbprint, sent as keyid
 * @param fingerprint SHA256:… of the SSH key
 * @param agentUrl Signature-Agent: &lt;registry&gt;/&lt;identity&gt;
 */
public record PublishedKey(String identity, String keyName, String keyId, String fingerprint, String agentUrl) {}
