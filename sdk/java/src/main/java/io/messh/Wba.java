package io.messh;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Web Bot Auth wire format shared by the client and verifier: RFC 9421
 * signature base, structured-field parsing, RFC 7638 thumbprints and RFC
 * 9530 Content-Digest. Internal API; may change between versions.
 */
public final class Wba {
  public static final String TAG = "web-bot-auth";
  public static final String LABEL = "sig1";
  public static final String DIRECTORY_PATH = "/.well-known/http-message-signatures-directory";
  public static final long MAX_LIFETIME = 300;

  private Wba() {}

  static String b64url(byte[] b) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }

  static byte[] sha256(byte[] b) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(b);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  /** RFC 7638 JWK thumbprint of a raw 32-byte Ed25519 public key. */
  public static String thumbprint(byte[] publicKey) {
    String canon = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + b64url(publicKey) + "\"}";
    return b64url(sha256(canon.getBytes(StandardCharsets.UTF_8)));
  }

  /** SSH wire-format string: uint32 length, then the bytes. */
  public static byte[] sshString(byte[] b) {
    return ByteBuffer.allocate(4 + b.length).putInt(b.length).put(b).array();
  }

  /** The key's SSH fingerprint, as ssh-keygen -l and messh print it: SHA256:… */
  public static String fingerprint(byte[] publicKey) {
    byte[] type = sshString("ssh-ed25519".getBytes(StandardCharsets.US_ASCII)), key = sshString(publicKey);
    byte[] blob = ByteBuffer.allocate(type.length + key.length).put(type).put(key).array();
    return "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(sha256(blob));
  }

  public static String contentDigest(byte[] body) {
    return "sha-256=:" + Base64.getEncoder().encodeToString(sha256(body)) + ":";
  }

  public static String quote(String s) {
    return Json.quote(s);
  }

  public static String params(List<String> names, long created, long expires, String keyid, String nonce) {
    List<String> q = new ArrayList<>();
    for (String n : names) q.add(quote(n));
    return "(" + String.join(" ", q) + ");created=" + created + ";expires=" + expires + ";keyid=" + quote(keyid)
        + ";alg=\"ed25519\";nonce=" + quote(nonce) + ";tag=\"" + TAG + "\"";
  }

  /** RFC 9421 §2.5 signature base. */
  public static byte[] base(List<String[]> components, String sigParams) {
    StringBuilder b = new StringBuilder();
    for (String[] c : components) b.append(quote(c[0])).append(": ").append(c[1]).append('\n');
    b.append("\"@signature-params\": ").append(sigParams);
    return b.toString().getBytes(StandardCharsets.UTF_8);
  }

  /** One parsed Signature-Input member. */
  public record SigParams(String label, List<String> components, Map<String, String> params, String raw) {
    public boolean covers(String c) {
      return components.contains(c);
    }
  }

  static List<String> splitTop(String s) {
    List<String> out = new ArrayList<>();
    int depth = 0, start = 0;
    boolean inStr = false;
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (inStr && c == '\\') { i++; continue; }
      if (c == '"') inStr = !inStr;
      else if (!inStr) {
        if (c == '(') depth++;
        else if (c == ')') depth--;
        else if (c == ',' && depth == 0) { out.add(s.substring(start, i).trim()); start = i + 1; }
      }
    }
    out.add(s.substring(start).trim());
    return out;
  }

  private static String unquote(String v) {
    return v.length() >= 2 && v.startsWith("\"") && v.endsWith("\"") ? (String) Json.parse(v) : v;
  }

  private static SigParams member(String label, String raw) {
    if (!raw.startsWith("(")) throw new IllegalArgumentException("Signature-Input member is not an inner list");
    int end = raw.indexOf(')');
    if (end < 0) throw new IllegalArgumentException("unterminated inner list");
    List<String> comps = new ArrayList<>();
    for (String item : raw.substring(1, end).trim().split("\\s+")) {
      if (item.isEmpty()) continue;
      if (!item.startsWith("\"") || !item.endsWith("\"")) throw new IllegalArgumentException("bad component " + item);
      comps.add(unquote(item));
    }
    Map<String, String> ps = new LinkedHashMap<>();
    String[] parts = raw.substring(end + 1).split(";", -1);
    for (int i = 1; i < parts.length; i++) {
      int eq = parts[i].indexOf('=');
      String k = eq < 0 ? parts[i] : parts[i].substring(0, eq);
      String v = eq < 0 ? "" : parts[i].substring(eq + 1);
      ps.put(k.trim(), unquote(v));
    }
    return new SigParams(label, List.copyOf(comps), ps, raw);
  }

  public static SigParams pickWebBotAuth(String header) {
    for (String m : splitTop(header)) {
      int eq = m.indexOf('=');
      if (eq < 0) continue;
      SigParams sp = member(m.substring(0, eq), m.substring(eq + 1));
      if (TAG.equals(sp.params().get("tag"))) return sp;
    }
    throw new IllegalArgumentException("no signature with tag=\"web-bot-auth\"");
  }

  public static byte[] signatureBytes(String header, String label) {
    for (String m : splitTop(header)) {
      int eq = m.indexOf('=');
      if (eq < 0) continue;
      String l = m.substring(0, eq), v = m.substring(eq + 1);
      if (l.equals(label) && v.length() > 2 && v.startsWith(":") && v.endsWith(":")) {
        return Base64.getDecoder().decode(v.substring(1, v.length() - 1));
      }
    }
    throw new IllegalArgumentException("no Signature for " + label);
  }

  public static String parseAgent(String header, String label) {
    String h = header.trim();
    if (h.startsWith("\"")) return unquote(h);
    for (String m : splitTop(h)) {
      int eq = m.indexOf('=');
      if (eq > 0 && m.substring(0, eq).equals(label)) return unquote(m.substring(eq + 1));
    }
    throw new IllegalArgumentException("Signature-Agent has no value for " + label);
  }

  /** Raw public key from an Ed25519 JWK, or null if malformed or kid isn't its thumbprint. */
  public static byte[] jwkPublicKey(Map<?, ?> jwk) {
    if (!"OKP".equals(jwk.get("kty")) || !"Ed25519".equals(jwk.get("crv")) || !(jwk.get("x") instanceof String x)) return null;
    byte[] pub;
    try {
      pub = Base64.getUrlDecoder().decode(x);
    } catch (IllegalArgumentException e) {
      return null;
    }
    Object kid = jwk.get("kid");
    if (pub.length != 32 || (kid instanceof String k && !k.isEmpty() && !k.equals(thumbprint(pub)))) return null;
    return pub;
  }
}
