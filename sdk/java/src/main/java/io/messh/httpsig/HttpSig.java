package io.messh.httpsig;

import io.messh.Signer;
import io.messh.verify.NonceStore;
import io.messh.verify.VerifyException;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * HTTP message signatures (RFC 9421) with Ed25519 for any request or response:
 * any label, tag and key ID, every derived component, and every field
 * parameter (sf, key, bs, req, tr).
 *
 * <pre>{@code
 * HttpMessage m = HttpMessage.request("POST", "https://example.com/foo", headers, body);
 * HttpSig.Signed s = HttpSig.sign(m, signer, HttpSig.SignOptions.of("@method", "@authority").keyid("k1"));
 * HttpSig.Verified v = HttpSig.verify(signedMessage, HttpSig.VerifyOptions.keys(keyid -> publicKey));
 * }</pre>
 *
 * Web Bot Auth, built on this, is {@link io.messh.MesshClient} and {@link io.messh.verify.MesshVerifier}.
 */
public final class HttpSig {
  private HttpSig() {}

  private static final Map<String, String> KNOWN_TYPES = Map.ofEntries(
      Map.entry("accept-signature", "dictionary"), Map.entry("cache-status", "list"), Map.entry("content-digest", "dictionary"),
      Map.entry("priority", "dictionary"), Map.entry("proxy-status", "list"), Map.entry("repr-digest", "dictionary"),
      Map.entry("signature", "dictionary"), Map.entry("signature-input", "dictionary"), Map.entry("signature-agent", "dictionary-or-item"),
      Map.entry("want-content-digest", "dictionary"), Map.entry("want-repr-digest", "dictionary"));
  private static final byte[] SPKI_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");
  private static final Pattern DERIVED = Pattern.compile("@[a-z][a-z-]*");
  private static final Pattern FIELD = Pattern.compile("[a-z0-9!#$%&'*+\\-.^_`|~]+");
  private static final Pattern OBS_FOLD = Pattern.compile("[ \\t]*\\r?\\n[ \\t]+");

  private static VerifyException fail(String code, String msg) {
    return new VerifyException(code, msg);
  }

  // --- messages ---

  private static final class Msg {
    String method = "", scheme = "", authority = "", path = "", query = "", requestTarget = "";
    int status;
    Map<String, List<String>> headers, trailers;
    byte[] body;
    Msg request;
  }

  private static Map<String, List<String>> fields(Map<String, List<String>> h) {
    Map<String, List<String>> out = new LinkedHashMap<>();
    if (h != null) h.forEach((k, vs) -> out.computeIfAbsent(k.toLowerCase(Locale.ROOT), x -> new ArrayList<>()).addAll(vs));
    return out;
  }

  private static Msg normalize(HttpMessage m) {
    Msg n = new Msg();
    n.method = m.method() == null ? "" : m.method();
    n.requestTarget = m.requestTarget() == null ? "" : m.requestTarget();
    n.status = m.status();
    n.headers = fields(m.headers());
    n.trailers = fields(m.trailers());
    n.body = m.body();
    n.request = m.request() == null ? null : normalize(m.request());
    if (m.url() != null && !m.url().isEmpty()) {
      try {
        URI u = new URI(m.url());
        n.scheme = u.getScheme() == null ? "" : u.getScheme();
        n.authority = u.getRawAuthority() == null ? "" : u.getRawAuthority();
        n.path = u.getRawPath() == null ? "" : u.getRawPath();
        n.query = u.getRawQuery() == null ? "" : u.getRawQuery();
      } catch (URISyntaxException e) {
        throw new IllegalArgumentException(m.url() + " is not a URL");
      }
    }
    List<String> host = n.headers.get("host");
    if (host != null && !host.isEmpty()) n.authority = host.get(0).trim();
    return n;
  }

  // --- component identifiers ---

  private record Comp(String name, Map<String, Sf.Bare> params) {
    String id() {
      return Sf.ser(new Sf.Str(name)) + Sf.ser(params);
    }
  }

  private static Comp checked(Comp c) {
    if (DERIVED.matcher(c.name()).matches() || FIELD.matcher(c.name()).matches()) return c;
    throw new IllegalArgumentException("bad component name \"" + c.name() + "\" (lowercase field names, or @derived)");
  }

  private static Comp parseComponent(String s) {
    if (!s.startsWith("\"")) return checked(new Comp(s.toLowerCase(Locale.ROOT), Map.of()));
    Sf.Item it;
    try {
      it = Sf.parseItem(s);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("bad component identifier " + s);
    }
    if (!(it.bare() instanceof Sf.Str name)) throw new IllegalArgumentException("bad component identifier " + s);
    return checked(new Comp(name.v(), it.params()));
  }

  // --- component values (RFC 9421 §2) ---

  /** The identifier and signature-base value of one component: [identifier, value]. Throws IllegalArgumentException. */
  public static String[] componentValue(HttpMessage message, String component, Map<String, String> fieldTypes) {
    Comp c = parseComponent(component);
    return new String[] {c.id(), value(normalize(message), c, fieldTypes == null ? Map.of() : fieldTypes)};
  }

  private static String value(Msg m, Comp c, Map<String, String> types) {
    String id = c.id();
    boolean req = false, strict = false, bs = false, tr = false;
    String key = null, name = null;
    for (Map.Entry<String, Sf.Bare> p : c.params().entrySet()) {
      String k = p.getKey();
      Sf.Bare v = p.getValue();
      switch (k) {
        case "req", "sf", "bs", "tr" -> {
          if (!Sf.TRUE.equals(v)) throw new IllegalArgumentException(id + ": parameter " + k + " must be true");
          req |= k.equals("req");
          strict |= k.equals("sf");
          bs |= k.equals("bs");
          tr |= k.equals("tr");
        }
        case "key", "name" -> {
          if (!(v instanceof Sf.Str s)) throw new IllegalArgumentException(id + ": parameter " + k + " must be a string");
          if (k.equals("key")) key = s.v();
          else name = s.v();
        }
        default -> throw new IllegalArgumentException(id + ": unknown parameter " + k);
      }
    }
    boolean derived = c.name().startsWith("@");
    if (derived && (strict || bs || tr || key != null)) throw new IllegalArgumentException(id + ": sf, bs, tr and key apply to fields only");
    if (name != null && !c.name().equals("@query-param")) throw new IllegalArgumentException(id + ": name applies to @query-param only");
    if (bs && (strict || key != null)) throw new IllegalArgumentException(id + ": bs can't be combined with sf or key");
    Msg ctx = m;
    if (req) {
      if (m.status == 0 || m.request == null) throw new IllegalArgumentException(id + ": req needs a response and the request it answers");
      ctx = m.request;
    }
    if (derived) {
      if (c.name().equals("@query-param") && name == null) throw new IllegalArgumentException("@query-param needs a name parameter");
      return derivedValue(ctx, c.name(), name == null ? "" : name);
    }
    return fieldValue(tr ? ctx.trailers : ctx.headers, c.name(), strict, bs, key, types);
  }

  private static String path(Msg m) {
    return m.path.isEmpty() ? "/" : m.path;
  }

  private static String pathQuery(Msg m) {
    return m.query.isEmpty() ? path(m) : path(m) + "?" + m.query;
  }

  private static String derivedValue(Msg m, String name, String param) {
    if (name.equals("@status")) {
      if (m.status == 0) throw new IllegalArgumentException("@status applies to responses only");
      return Integer.toString(m.status);
    }
    if (m.authority.isEmpty() && m.method.isEmpty()) throw new IllegalArgumentException(name + " needs the request (use req in a response signature)");
    switch (name) {
      case "@method":
        if (m.method.isEmpty()) throw new IllegalArgumentException("@method needs a request method");
        return m.method;
      case "@target-uri":
        if (m.scheme.isEmpty() || m.authority.isEmpty()) throw new IllegalArgumentException("@target-uri needs a scheme and an authority");
        return m.scheme.toLowerCase(Locale.ROOT) + "://" + m.authority.toLowerCase(Locale.ROOT) + pathQuery(m);
      case "@authority":
        if (m.authority.isEmpty()) throw new IllegalArgumentException("@authority needs an authority");
        return m.authority.toLowerCase(Locale.ROOT);
      case "@scheme":
        if (m.scheme.isEmpty()) throw new IllegalArgumentException("@scheme needs a scheme");
        return m.scheme.toLowerCase(Locale.ROOT);
      case "@request-target":
        return m.requestTarget.isEmpty() ? pathQuery(m) : m.requestTarget;
      case "@path":
        return path(m);
      case "@query":
        return "?" + m.query;
      case "@query-param":
        return queryParam(m.query, param);
      default:
        throw new IllegalArgumentException("unknown derived component " + name);
    }
  }

  private static String clean(String v) {
    return OBS_FOLD.matcher(v.replaceAll("^[ \\t]+|[ \\t]+$", "")).replaceAll(" ");
  }

  private static String fieldValue(Map<String, List<String>> h, String name, boolean strict, boolean bs, String key, Map<String, String> types) {
    List<String> vals = h.get(name);
    if (vals == null || vals.isEmpty()) throw new IllegalArgumentException("covered field " + name + " is missing");
    List<String> parts = new ArrayList<>();
    for (String v : vals) parts.add(bs ? Sf.ser(new Sf.Bin(clean(v).getBytes(StandardCharsets.ISO_8859_1))) : clean(v));
    String v = String.join(", ", parts);
    if (key != null) {
      Sf.Dict d;
      try {
        d = Sf.parseDictionary(v);
      } catch (IllegalArgumentException e) {
        throw new IllegalArgumentException(name + " is not a dictionary: " + e.getMessage());
      }
      Sf.Member m = d.members().get(key);
      if (m == null) throw new IllegalArgumentException(name + " has no member \"" + key + "\"");
      return Sf.ser(m);
    }
    return strict ? strictValue(name, v, types) : v;
  }

  private static String strictValue(String name, String v, Map<String, String> types) {
    String t = types.getOrDefault(name, KNOWN_TYPES.get(name));
    if ("dictionary".equals(t) || "dictionary-or-item".equals(t)) {
      try {
        return Sf.serDict(Sf.parseDictionary(v).members());
      } catch (IllegalArgumentException e) {
        if ("dictionary".equals(t)) throw new IllegalArgumentException(name + ": " + e.getMessage());
      }
    }
    if ("item".equals(t) || "dictionary-or-item".equals(t)) return Sf.ser(Sf.parseItem(v));
    if ("list".equals(t)) return Sf.serList(Sf.parseList(v));
    throw new IllegalArgumentException("can't serialize " + name + " strictly: its structured-field type is unknown");
  }

  private static byte[] formDecode(String s) {
    byte[] b = s.replace('+', ' ').getBytes(StandardCharsets.UTF_8);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (int i = 0; i < b.length; i++) {
      if (b[i] == '%' && i + 2 < b.length) {
        int hi = Character.digit(b[i + 1], 16), lo = Character.digit(b[i + 2], 16);
        if (hi >= 0 && lo >= 0) {
          out.write(hi << 4 | lo);
          i += 2;
          continue;
        }
      }
      out.write(b[i]);
    }
    return out.toByteArray();
  }

  private static String formEncode(byte[] b) {
    StringBuilder sb = new StringBuilder();
    for (byte x : b) {
      char c = (char) (x & 0xff);
      if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || "*-._".indexOf(c) >= 0) sb.append(c);
      else sb.append(String.format("%%%02X", x & 0xff));
    }
    return sb.toString();
  }

  /** The encoded value of one query parameter (RFC 9421 §2.2.8). */
  private static String queryParam(String raw, String name) {
    List<String> vals = new ArrayList<>();
    for (String part : raw.split("&", -1)) {
      if (part.isEmpty()) continue;
      int eq = part.indexOf('=');
      String k = eq < 0 ? part : part.substring(0, eq), v = eq < 0 ? "" : part.substring(eq + 1);
      if (formEncode(formDecode(k)).equals(name)) vals.add(formEncode(formDecode(v)));
    }
    if (vals.isEmpty()) throw new IllegalArgumentException("query parameter \"" + name + "\" is missing");
    if (vals.size() > 1) throw new IllegalArgumentException("query parameter \"" + name + "\" occurs more than once");
    return vals.get(0);
  }

  // --- signature base (RFC 9421 §2.5) ---

  private static String base(Msg m, List<Comp> comps, String params, Map<String, String> types) {
    Set<String> seen = new HashSet<>();
    List<String> lines = new ArrayList<>();
    for (Comp c : comps) {
      String id = c.id();
      if (!seen.add(id)) throw new IllegalArgumentException("component " + id + " is covered twice");
      lines.add(id + ": " + value(m, c, types));
    }
    lines.add("\"@signature-params\": " + params);
    String b = String.join("\n", lines);
    if (!b.chars().allMatch(ch -> ch == '\n' || (ch >= 0x20 && ch <= 0x7e))) {
      throw new IllegalArgumentException("signature base must be printable ASCII (wrap such fields with bs)");
    }
    return b;
  }

  // --- signing ---

  /** One signature to make; parameters left null are omitted. */
  public static final class SignOptions {
    String label = "sig1";
    List<String> components = List.of();
    Long created, expires;
    String keyid, alg, nonce, tag;
    Map<String, String> fieldTypes = Map.of();

    /** Covered components, in order: plain names (@method, content-type) or identifiers with parameters ("example-dict";key="a"). */
    public static SignOptions of(String... components) {
      SignOptions o = new SignOptions();
      o.components = List.of(components);
      return o;
    }

    public SignOptions components(List<String> c) {
      components = List.copyOf(c);
      return this;
    }

    public SignOptions label(String l) {
      label = l;
      return this;
    }

    public SignOptions created(long c) {
      created = c;
      return this;
    }

    public SignOptions expires(long e) {
      expires = e;
      return this;
    }

    public SignOptions keyid(String k) {
      keyid = k;
      return this;
    }

    /** "ed25519", or null to leave it out. */
    public SignOptions alg(String a) {
      alg = a;
      return this;
    }

    public SignOptions nonce(String n) {
      nonce = n;
      return this;
    }

    public SignOptions tag(String t) {
      tag = t;
      return this;
    }

    /** Structured-field types ("dictionary", "list" or "item") of fields covered with sf. */
    public SignOptions fieldTypes(Map<String, String> t) {
      fieldTypes = Map.copyOf(t);
      return this;
    }
  }

  /**
   * A signature ready to send.
   *
   * @param label the label
   * @param input the Signature-Input member value: covered components and parameters
   * @param signature the Signature member value: :base64:
   * @param base the signature base that was signed
   */
  public record Signed(String label, String input, String signature, String base) {
    /** Signature-Input and Signature with only this signature. */
    public Map<String, String> headers() {
      Map<String, String> h = new LinkedHashMap<>();
      h.put("Signature-Input", label + "=" + input);
      h.put("Signature", label + "=" + signature);
      return h;
    }
  }

  /** Sign a message. Throws IllegalArgumentException for a bad option or a component that can't be derived. */
  public static Signed sign(HttpMessage message, Signer signer, SignOptions o) {
    if (!Sf.validKey(o.label)) throw new IllegalArgumentException("bad label \"" + o.label + "\"");
    List<Comp> comps = new ArrayList<>();
    List<Sf.Item> items = new ArrayList<>();
    for (String s : o.components) {
      Comp c = parseComponent(s);
      comps.add(c);
      items.add(new Sf.Item(new Sf.Str(c.name()), c.params()));
    }
    Map<String, Sf.Bare> params = new LinkedHashMap<>();
    if (o.created != null) params.put("created", new Sf.Int(o.created));
    if (o.expires != null) params.put("expires", new Sf.Int(o.expires));
    String[][] strs = {{"keyid", o.keyid}, {"alg", o.alg}, {"nonce", o.nonce}, {"tag", o.tag}};
    for (String[] kv : strs) {
      if (kv[1] == null) continue;
      if (!Sf.validString(kv[1])) throw new IllegalArgumentException(kv[0] + " must be printable ASCII");
      params.put(kv[0], new Sf.Str(kv[1]));
    }
    String input = Sf.ser(new Sf.Member(null, items, params));
    String b = base(normalize(message), comps, input, o.fieldTypes);
    return new Signed(o.label, input, Sf.ser(new Sf.Bin(signer.sign(b.getBytes(StandardCharsets.US_ASCII)))), b);
  }

  // --- parsing signatures ---

  /**
   * One covered component of a signature.
   *
   * @param id serialized identifier, e.g. "signature-agent";key="sig1"
   * @param name component name
   * @param key its key parameter, or null
   */
  public record Covered(String id, String name, String key) {}

  /** One signature of a message, parsed but not verified. */
  public static final class Signature {
    private final String label;
    private final List<Covered> covered = new ArrayList<>();
    private Long created, expires;
    private String keyid, alg, nonce, tag;
    private byte[] value;
    private final List<Comp> comps = new ArrayList<>();
    private final String params;

    private Signature(String label, String params) {
      this.label = label;
      this.params = params;
    }

    public String label() {
      return label;
    }

    public List<Covered> covered() {
      return List.copyOf(covered);
    }

    /** null when absent. */
    public Long created() {
      return created;
    }

    public Long expires() {
      return expires;
    }

    public String keyid() {
      return keyid;
    }

    public String alg() {
      return alg;
    }

    public String nonce() {
      return nonce;
    }

    public String tag() {
      return tag;
    }

    public byte[] value() {
      return value.clone();
    }

    /** Whether a component with this name is covered, with any parameters. */
    public boolean covers(String name) {
      return covered.stream().anyMatch(c -> c.name().equals(name));
    }
  }

  private static Map<String, Sf.Member> dictionary(Map<String, List<String>> h, String name) {
    Sf.Dict d;
    try {
      d = Sf.parseDictionary(String.join(", ", h.getOrDefault(name.toLowerCase(Locale.ROOT), List.of())));
    } catch (IllegalArgumentException e) {
      throw fail("bad_signature", name + ": " + e.getMessage());
    }
    if (!d.duplicates().isEmpty()) throw fail("bad_signature", name + " repeats the label " + d.duplicates().get(0));
    return d.members();
  }

  private static List<Signature> parseSignatures(Msg m) {
    if (m.headers.getOrDefault("signature-input", List.of()).isEmpty() || m.headers.getOrDefault("signature", List.of()).isEmpty()) {
      throw fail("missing_signature", "send Signature-Input and Signature (RFC 9421)");
    }
    Map<String, Sf.Member> inputs = dictionary(m.headers, "Signature-Input");
    Map<String, Sf.Member> values = dictionary(m.headers, "Signature");
    List<Signature> out = new ArrayList<>();
    for (Map.Entry<String, Sf.Member> e : inputs.entrySet()) {
      String label = e.getKey();
      Sf.Member mem = e.getValue();
      if (!mem.inner()) throw fail("bad_signature", "Signature-Input " + label + " is not an inner list");
      Signature s = new Signature(label, Sf.ser(mem));
      Set<String> seen = new HashSet<>();
      for (Sf.Item it : mem.items()) {
        if (!(it.bare() instanceof Sf.Str name)) throw fail("bad_signature", "Signature-Input " + label + ": a component is not a string");
        Comp c;
        try {
          c = checked(new Comp(name.v(), it.params()));
        } catch (IllegalArgumentException x) {
          throw fail("bad_signature", "Signature-Input " + label + ": " + x.getMessage());
        }
        String id = c.id();
        if (!seen.add(id)) throw fail("bad_signature", "Signature-Input " + label + " covers " + id + " twice");
        s.comps.add(c);
        s.covered.add(new Covered(id, c.name(), c.params().get("key") instanceof Sf.Str k ? k.v() : null));
      }
      for (Map.Entry<String, Sf.Bare> p : mem.params().entrySet()) {
        String k = p.getKey();
        Sf.Bare v = p.getValue();
        switch (k) {
          case "created", "expires" -> {
            if (!(v instanceof Sf.Int n)) throw fail("bad_signature", k + " must be an integer");
            if (k.equals("created")) s.created = n.v();
            else s.expires = n.v();
          }
          case "keyid", "alg", "nonce", "tag" -> {
            if (!(v instanceof Sf.Str str)) throw fail("bad_signature", k + " must be a string");
            switch (k) {
              case "keyid" -> s.keyid = str.v();
              case "alg" -> s.alg = str.v();
              case "nonce" -> s.nonce = str.v();
              default -> s.tag = str.v();
            }
          }
          default -> {}
        }
      }
      Sf.Member sig = values.get(label);
      if (sig == null || sig.inner() || !(sig.bare() instanceof Sf.Bin bin)) throw fail("bad_signature", "no Signature for " + label);
      s.value = bin.v();
      out.add(s);
    }
    if (out.isEmpty()) throw fail("missing_signature", "Signature-Input has no signatures");
    return out;
  }

  /** Parse Signature-Input and Signature. Labels and covered components must not repeat (RFC 9421 §4.1, §2.5). */
  public static List<Signature> signatures(HttpMessage message) {
    return parseSignatures(normalize(message));
  }

  /** Choose a signature by label, else by tag, else the only one. label and tag may be null. */
  public static Signature pickSignature(List<Signature> sigs, String label, String tag) {
    for (Signature s : sigs) {
      if ((label != null && s.label.equals(label)) || (label == null && tag != null && tag.equals(s.tag))) return s;
    }
    if (label != null) throw fail("bad_signature", "no signature labeled " + label);
    if (tag != null) throw fail("bad_signature", "no signature with tag=\"" + tag + "\"");
    if (sigs.size() == 1) return sigs.get(0);
    throw fail("bad_signature", "the message has " + sigs.size() + " signatures: choose one by label or tag");
  }

  /** The value of a structured field that is a String item, or null (e.g. Signature-Agent: "https://messh.io/mukul"). */
  public static String stringItem(String field) {
    try {
      return Sf.parseItem(field).bare() instanceof Sf.Str s ? s.v() : null;
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  /** The String value of one member of a dictionary field, or null (e.g. Signature-Agent: sig1="https://messh.io/mukul"). */
  public static String stringMember(String field, String key) {
    try {
      Sf.Member m = Sf.parseDictionary(field).members().get(key);
      return m != null && !m.inner() && m.bare() instanceof Sf.Str s ? s.v() : null;
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  /** The RFC 9530 Content-Digest field for a body (sha-256). */
  public static String contentDigest(byte[] body) {
    return "sha-256=" + Sf.ser(new Sf.Bin(digest("SHA-256", body)));
  }

  private static byte[] digest(String alg, byte[] body) {
    try {
      return MessageDigest.getInstance(alg).digest(body);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Check a body against a Content-Digest field (sha-256 or sha-512); throws digest_mismatch. */
  public static void checkDigest(String field, byte[] body) {
    int known = 0;
    Map<String, Sf.Member> d;
    try {
      d = Sf.parseDictionary(field).members();
    } catch (IllegalArgumentException e) {
      d = Map.of();
    }
    for (Map.Entry<String, Sf.Member> e : d.entrySet()) {
      String alg = switch (e.getKey()) {
        case "sha-256" -> "SHA-256";
        case "sha-512" -> "SHA-512";
        default -> null;
      };
      if (alg == null) continue;
      known++;
      Sf.Member m = e.getValue();
      if (m.inner() || !(m.bare() instanceof Sf.Bin bin) || !Arrays.equals(bin.v(), digest(alg, body))) {
        throw fail("digest_mismatch", "the body doesn't match Content-Digest");
      }
    }
    if (known == 0) throw fail("digest_mismatch", "Content-Digest has no sha-256 or sha-512 digest");
  }

  // --- verifying ---

  /** Which signature to verify and how. */
  public static final class VerifyOptions {
    String label, tag;
    final Function<String, byte[]> keys;
    Long now;
    long maxSkew = 60;
    Long maxAge;
    List<String> required = List.of();
    NonceStore nonces;
    Map<String, String> fieldTypes = Map.of();

    private VerifyOptions(Function<String, byte[]> keys) {
      this.keys = keys;
    }

    /** Options with this key resolver: a keyid to a raw 32-byte Ed25519 public key, or null for unknown_key. */
    public static VerifyOptions keys(Function<String, byte[]> keys) {
      return new VerifyOptions(keys);
    }

    /** Verify the signature with this label. */
    public VerifyOptions label(String l) {
      label = l;
      return this;
    }

    /** Or the first one with this tag (else the only one). */
    public VerifyOptions tag(String t) {
      tag = t;
      return this;
    }

    /** Seconds since epoch. Default now. */
    public VerifyOptions now(long n) {
      now = n;
      return this;
    }

    /** How far created may be ahead of now. Default 60 s. */
    public VerifyOptions maxSkew(Duration d) {
      maxSkew = d.getSeconds();
      return this;
    }

    /** How old created may be. Default: no limit. */
    public VerifyOptions maxAge(Duration d) {
      maxAge = d.getSeconds();
      return this;
    }

    /** Component names that must be covered. */
    public VerifyOptions required(String... names) {
      required = List.of(names);
      return this;
    }

    /** Reject a nonce seen before (signatures with a nonce). */
    public VerifyOptions nonceStore(NonceStore n) {
      nonces = n;
      return this;
    }

    public VerifyOptions fieldTypes(Map<String, String> t) {
      fieldTypes = Map.copyOf(t);
      return this;
    }
  }

  /**
   * A verified signature.
   *
   * @param label the label
   * @param components covered component identifiers
   * @param keyid keyid, or null
   * @param alg alg, or null
   * @param nonce nonce, or null
   * @param tag tag, or null
   * @param created created, or null
   * @param expires expires, or null
   * @param base the signature base
   */
  public record Verified(String label, List<String> components, String keyid, String alg, String nonce, String tag, Long created,
      Long expires, String base) {}

  /** Verify one signature of a message: content digest, time, key, then the signature. Throws VerifyException. */
  public static Verified verify(HttpMessage message, VerifyOptions o) {
    Msg m = normalize(message);
    return verify(m, pickSignature(parseSignatures(m), o.label, o.tag), o);
  }

  /** Verify a signature from {@link #signatures}; label and tag are ignored. */
  public static Verified verifySignature(HttpMessage message, Signature s, VerifyOptions o) {
    return verify(normalize(message), s, o);
  }

  private static Verified verify(Msg m, Signature s, VerifyOptions o) {
    for (String name : o.required) if (!s.covers(name)) throw fail("bad_signature", name + " must be covered");
    if (s.alg != null && !s.alg.equals("ed25519")) throw fail("bad_signature", "alg \"" + s.alg + "\" is not supported (ed25519 only)");
    for (Comp c : s.comps) {
      if (!c.name().equals("content-digest")) continue;
      Msg ctx = c.params().containsKey("req") && m.request != null ? m.request : m;
      if (ctx.body != null) checkDigest(String.join(", ", ctx.headers.getOrDefault("content-digest", List.of())), ctx.body);
    }
    long now = o.now != null ? o.now : System.currentTimeMillis() / 1000;
    if (s.created != null) {
      if (s.created > now + o.maxSkew) throw fail("clock_skew", "created is " + (s.created - now) + "s ahead of the clock");
      if (o.maxAge != null && s.created < now - o.maxAge) throw fail("clock_skew", "the signature is " + (now - s.created) + "s old");
    }
    if (s.expires != null && now > s.expires) throw fail("clock_skew", "the signature expired");
    byte[] pub;
    try {
      pub = o.keys.apply(s.keyid == null ? "" : s.keyid);
    } catch (VerifyException e) {
      throw e;
    } catch (RuntimeException e) {
      throw fail("unknown_key", "keyid \"" + s.keyid + "\": " + e.getMessage());
    }
    if (pub == null || pub.length != 32) throw fail("unknown_key", "keyid \"" + (s.keyid == null ? "" : s.keyid) + "\" is not a known Ed25519 key");
    String b;
    try {
      b = base(m, s.comps, s.params, o.fieldTypes);
    } catch (IllegalArgumentException e) {
      throw fail("bad_signature", e.getMessage());
    }
    if (!verifyEd25519(pub, b.getBytes(StandardCharsets.US_ASCII), s.value)) throw fail("bad_signature", "the signature doesn't match the message");
    if (o.nonces != null && s.nonce != null) {
      long ttl = o.maxAge != null ? o.maxAge + o.maxSkew : 2 * o.maxSkew;
      if (s.expires != null) ttl = Math.max(ttl, s.expires - now + o.maxSkew);
      if (!o.nonces.add((s.keyid == null ? "" : s.keyid) + " " + s.nonce, Duration.ofSeconds(Math.max(ttl, 0)))) {
        throw fail("nonce_replayed", "this signature was already accepted once");
      }
    }
    List<String> ids = new ArrayList<>();
    for (Covered c : s.covered) ids.add(c.id());
    return new Verified(s.label, List.copyOf(ids), s.keyid, s.alg, s.nonce, s.tag, s.created, s.expires, b);
  }

  private static boolean verifyEd25519(byte[] pub, byte[] message, byte[] sig) {
    try {
      byte[] spki = new byte[SPKI_PREFIX.length + 32];
      System.arraycopy(SPKI_PREFIX, 0, spki, 0, SPKI_PREFIX.length);
      System.arraycopy(pub, 0, spki, SPKI_PREFIX.length, 32);
      PublicKey pk = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
      java.security.Signature v = java.security.Signature.getInstance("Ed25519");
      v.initVerify(pk);
      v.update(message);
      return v.verify(sig);
    } catch (GeneralSecurityException e) {
      return false;
    }
  }
}
