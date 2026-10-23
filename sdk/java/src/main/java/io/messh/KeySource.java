package io.messh;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.Base64;

/** Where the signing key comes from. Keys are used locally; they never go to messh. */
public abstract class KeySource {
  KeySource() {}

  abstract Signer load();

  /** Unencrypted ssh-ed25519 OpenSSH key or PKCS#8 PEM, e.g. ~/.ssh/id_ed25519. */
  public static KeySource file(Path path) {
    return new KeySource() {
      @Override
      Signer load() {
        Path p = path.startsWith("~") ? Path.of(System.getProperty("user.home")).resolve(path.subpath(1, path.getNameCount())) : path;
        try {
          return parse(Files.readAllBytes(p));
        } catch (java.nio.file.NoSuchFileException e) {
          throw new MesshException("invalid_key", "read " + path + ": no such file; create one with ssh-keygen -t ed25519, then messh publish");
        } catch (java.io.IOException e) {
          throw new MesshException("invalid_key", "read " + path + ": " + e.getMessage());
        }
      }
    };
  }

  /** Environment variable: PEM text, or base64 of PEM or PKCS#8 DER. */
  public static KeySource env(String name) {
    return new KeySource() {
      @Override
      Signer load() {
        String v = System.getenv(name);
        if (v == null || v.isBlank()) throw new MesshException("invalid_key", "environment variable " + name + " is empty");
        v = v.trim();
        if (v.contains("-----BEGIN")) return parse(v.getBytes(StandardCharsets.UTF_8));
        try {
          return parse(Base64.getDecoder().decode(v));
        } catch (IllegalArgumentException e) {
          throw new MesshException("invalid_key", name + " is neither PEM nor base64");
        }
      }
    };
  }

  /** Raw 32-byte Ed25519 seed. */
  public static KeySource seed(byte[] seed) {
    byte[] copy = seed.clone();
    return new KeySource() {
      @Override
      Signer load() {
        return fromSeed(copy);
      }
    };
  }

  /**
   * A key held by ssh-agent (SSH_AUTH_SOCK), such as a passphrase-protected key you added with
   * ssh-add. The private key stays in the agent. Uses the only Ed25519 key it holds.
   */
  public static KeySource sshAgent() {
    return sshAgent(null, null);
  }

  /** Like {@link #sshAgent()}, choosing by fingerprint (SHA256:…) when several Ed25519 keys are loaded. */
  public static KeySource sshAgent(String fingerprint) {
    return sshAgent(fingerprint, null);
  }

  /** Like {@link #sshAgent(String)}, at an explicit agent socket (null: SSH_AUTH_SOCK). */
  public static KeySource sshAgent(String fingerprint, Path socket) {
    return new KeySource() {
      @Override
      Signer load() {
        return SshAgent.load(fingerprint, socket);
      }
    };
  }

  /** Your own signer (KMS, HSM). */
  public static KeySource signer(Signer signer) {
    return new KeySource() {
      @Override
      Signer load() {
        if (signer == null || signer.publicKey().length != 32) throw new MesshException("invalid_key", "signer has no Ed25519 public key");
        return signer;
      }
    };
  }

  static Signer parse(byte[] data) {
    String text = new String(data, StandardCharsets.UTF_8);
    if (text.contains("OPENSSH PRIVATE KEY")) return fromSeed(openssh(text));
    if (text.contains("ENCRYPTED PRIVATE KEY")) throw new MesshException("invalid_key", "encrypted keys aren't supported; load the key into ssh-agent and use KeySource.sshAgent()");
    byte[] der = text.contains("-----BEGIN") ? pem(text) : data;
    return fromSeed(pkcs8Seed(der));
  }

  private static byte[] pem(String text) {
    String b64 = text.replaceAll("-----[^-]+-----", "").replaceAll("\\s+", "");
    try {
      return Base64.getDecoder().decode(b64);
    } catch (IllegalArgumentException e) {
      throw new MesshException("invalid_key", "bad PEM");
    }
  }

  /** Seed from an Ed25519 PKCS#8 (v1 or v2): OID 1.3.101.112, then OCTET STRING { OCTET STRING(32) }. */
  private static byte[] pkcs8Seed(byte[] der) {
    byte[] oid = {0x06, 0x03, 0x2b, 0x65, 0x70};
    int at = indexOf(der, oid, 0);
    if (at < 0) throw new MesshException("invalid_key", "PKCS#8 key is not Ed25519");
    int inner = indexOf(der, new byte[] {0x04, 0x22, 0x04, 0x20}, at + oid.length);
    if (inner < 0 || inner + 4 + 32 > der.length) throw new MesshException("invalid_key", "malformed Ed25519 PKCS#8");
    return Arrays.copyOfRange(der, inner + 4, inner + 36);
  }

  private static int indexOf(byte[] hay, byte[] needle, int from) {
    outer:
    for (int i = from; i <= hay.length - needle.length; i++) {
      for (int j = 0; j < needle.length; j++) if (hay[i + j] != needle[j]) continue outer;
      return i;
    }
    return -1;
  }

  /** Unpack the openssh-key-v1 container (PROTOCOL.key) to the Ed25519 seed. */
  private static byte[] openssh(String text) {
    ByteBuffer b = ByteBuffer.wrap(pem(text));
    byte[] magic = "openssh-key-v1\0".getBytes(StandardCharsets.ISO_8859_1);
    byte[] head = new byte[magic.length];
    try {
      b.get(head);
      if (!Arrays.equals(head, magic)) throw new MesshException("invalid_key", "not an OpenSSH private key");
      String cipher = new String(str(b), StandardCharsets.UTF_8);
      str(b);
      str(b);
      if (!cipher.equals("none")) throw new MesshException("invalid_key", "passphrase-protected key; load it into ssh-agent (ssh-add) and use KeySource.sshAgent()");
      if (b.getInt() != 1) throw new MesshException("invalid_key", "expected one key");
      str(b);
      ByteBuffer p = ByteBuffer.wrap(str(b));
      if (p.getInt() != p.getInt()) throw new MesshException("invalid_key", "OpenSSH check bytes differ");
      if (!new String(str(p), StandardCharsets.UTF_8).equals("ssh-ed25519")) throw new MesshException("invalid_key", "need an ssh-ed25519 key");
      byte[] pub = str(p), sk = str(p);
      if (sk.length != 64 || !Arrays.equals(Arrays.copyOfRange(sk, 32, 64), pub)) throw new MesshException("invalid_key", "malformed ssh-ed25519 key");
      return Arrays.copyOfRange(sk, 0, 32);
    } catch (java.nio.BufferUnderflowException | NegativeArraySizeException e) {
      throw new MesshException("invalid_key", "truncated OpenSSH key");
    }
  }

  private static byte[] str(ByteBuffer b) {
    byte[] out = new byte[b.getInt()];
    b.get(out);
    return out;
  }

  /**
   * The JDK can't derive an Ed25519 public key from a private one, so key
   * generation is fed the seed as its "randomness" (RFC 8032 keygen reads
   * exactly 32 bytes), which yields the matching key pair.
   */
  static Signer fromSeed(byte[] seed) {
    if (seed.length != 32) throw new MesshException("invalid_key", "seed must be 32 bytes");
    try {
      KeyPairGenerator g = KeyPairGenerator.getInstance("Ed25519");
      g.initialize(NamedParameterSpec.ED25519, new FixedRandom(seed));
      KeyPair kp = g.generateKeyPair();
      byte[] spki = kp.getPublic().getEncoded();
      return new LocalSigner(kp.getPrivate(), Arrays.copyOfRange(spki, spki.length - 32, spki.length));
    } catch (GeneralSecurityException e) {
      throw new MesshException("invalid_key", "Ed25519 unavailable: " + e.getMessage());
    }
  }

  private static final class FixedRandom extends SecureRandom {
    private static final long serialVersionUID = 1L;
    private final byte[] seed;

    FixedRandom(byte[] seed) {
      this.seed = seed;
    }

    @Override
    public void nextBytes(byte[] bytes) {
      if (bytes.length != seed.length) throw new IllegalStateException("unexpected key generation request");
      System.arraycopy(seed, 0, bytes, 0, seed.length);
    }
  }

  private record LocalSigner(PrivateKey key, byte[] pub) implements Signer {
    @Override
    public byte[] publicKey() {
      return pub.clone();
    }

    @Override
    public byte[] sign(byte[] message) {
      try {
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(key);
        s.update(message);
        return s.sign();
      } catch (GeneralSecurityException e) {
        throw new MesshException("sign_failed", e.getMessage());
      }
    }

    @Override
    public String toString() {
      return "messh.Signer(ed25519)";
    }
  }
}
