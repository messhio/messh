package io.messh;

/** Implement to sign in a KMS, HSM or ssh-agent; the SDK never needs the key bytes. */
public interface Signer {
  /** Raw 32-byte Ed25519 public key. */
  byte[] publicKey();

  /** 64-byte Ed25519 signature over message. */
  byte[] sign(byte[] message);
}
