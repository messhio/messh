package io.messh.verify;

import io.messh.Json;
import io.messh.MesshClient;
import io.messh.Wba;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiFunction;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;

/**
 * Verifies Web Bot Auth signatures with keys from messh. Thread-safe; create
 * once and reuse (it caches key directories).
 *
 * <pre>{@code
 * MesshVerifier v = MesshVerifier.builder().trust("mukul").build();
 * Agent agent = v.verify("GET", URI.create("https://api.example.com/hello"), headers, body);
 * }</pre>
 */
public final class MesshVerifier {
  public static final String ACCEPT_SIGNATURE =
      "sig1=(\"@method\" \"@authority\" \"@path\" \"signature-agent\");keyid;created;expires;nonce;alg=\"ed25519\";tag=\"web-bot-auth\"";
  private static final Pattern IDENTITY = Pattern.compile("^[a-z0-9](?:[a-z0-9-]{1,28}[a-z0-9])$");
  private static final byte[] SPKI_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");
  /** Default limit on request bodies {@link MesshHttpFilter} reads (bytes). */
  public static final long MAX_BODY_BYTES = 1 << 20;
  // Directory cache policy, the same in every messh SDK.
  private static final long MIN_REFRESH = 30; // an unknown keyid refetches its signer's directory at most this often (s)
  private static final long RETRY_AFTER = 5; // while messh is unreachable, retry a directory at most this often (s)
  private static final int MAX_ENTRIES = 10_000; // directories kept at most
  private static final int FETCH_STRIPES = 64; // fetch locks: one fetch per directory at a time

  private final List<String> trust;
  private final Map<String, String> registries;
  private final long maxSkew;
  private final long cacheTtl;
  private final long staleIfError;
  private final long maxBodyBytes;
  private final NonceStore nonces;
  private final HttpClient http;
  private final Duration timeout;
  private final LongSupplier clock;
  private final BiFunction<String, String, List<Map<String, Object>>> directory;
  private final Map<String, Entry> cache = new ConcurrentHashMap<>();
  private final AtomicLong seq = new AtomicLong();
  private final Object[] fetching = new Object[FETCH_STRIPES];

  /** A key directory: keys is the last good answer (null: no such identity), fetched at {@code at} (-1: none yet); failedAt is the last failed fetch. */
  private record Entry(List<Map<String, Object>> keys, long at, long failedAt, long seq) {}

  private record Found(Map<String, Object> key, byte[] pub) {}

  private record Fetched(List<Map<String, Object>> keys, boolean known) {}

  private MesshVerifier(Builder b) {
    this.trust = List.copyOf(b.trust);
    this.registries = b.registries.isEmpty() ? Map.of("https://messh.io", "https://messh.io") : Map.copyOf(b.registries);
    this.maxSkew = b.maxSkew.getSeconds();
    this.cacheTtl = b.cacheTtl.getSeconds();
    this.staleIfError = b.staleIfError.getSeconds();
    this.maxBodyBytes = b.maxBodyBytes;
    for (int i = 0; i < FETCH_STRIPES; i++) fetching[i] = new Object();
    this.nonces = b.nonces != null ? b.nonces : NonceStore.memory();
    this.http = b.http != null ? b.http : HttpClient.newBuilder().connectTimeout(b.timeout).build();
    this.timeout = b.timeout;
    this.clock = b.clock != null ? b.clock : () -> System.currentTimeMillis() / 1000;
    this.directory = b.directory;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** The largest request body {@link MesshHttpFilter} reads; bigger ones get 413 body_too_large. */
  public long maxBodyBytes() {
    return maxBodyBytes;
  }

  private static VerifyException fail(String code, String msg) {
    return new VerifyException(code, msg);
  }

  /**
   * Verify one request. uri is the full request URL; the authority is the
   * Host header if present, else the URI's. Header names are case-insensitive.
   * body may be null. Throws {@link VerifyException}.
   */
  public Agent verify(String method, URI uri, Map<String, List<String>> headers, byte[] body) {
    Map<String, String> h = new LinkedHashMap<>();
    headers.forEach((k, vs) -> {
      for (String v : vs) h.merge(k.toLowerCase(Locale.ROOT), v.trim(), (a, c) -> a + ", " + c);
    });
    long now = clock.getAsLong();
    String input = h.get("signature-input"), sigHeader = h.get("signature");
    if (input == null || input.isEmpty() || sigHeader == null || sigHeader.isEmpty()) {
      throw fail("missing_signature", "send Signature, Signature-Input and Signature-Agent (Web Bot Auth)");
    }
    Wba.SigParams sp;
    byte[] sig;
    try {
      sp = Wba.pickWebBotAuth(input);
      sig = Wba.signatureBytes(sigHeader, sp.label());
    } catch (IllegalArgumentException e) {
      throw fail("bad_signature", e.getMessage());
    }
    for (String c : List.of("@method", "@authority", "@path", "signature-agent")) {
      if (!sp.covers(c)) throw fail("bad_signature", c + " must be covered");
    }
    String query = uri.getRawQuery();
    if (query != null && !query.isEmpty() && !sp.covers("@query")) throw fail("bad_signature", "@query must be covered when the URL has a query");
    if (!h.containsKey("signature-agent")) throw fail("bad_signature", "Signature-Agent header is missing");
    String agentUrl;
    try {
      agentUrl = Wba.parseAgent(h.get("signature-agent"), sp.label());
    } catch (IllegalArgumentException e) {
      throw fail("bad_signature", e.getMessage());
    }
    if (!sp.params().getOrDefault("alg", "ed25519").equals("ed25519")) throw fail("bad_signature", "alg is not supported");

    byte[] b = body == null ? new byte[0] : body;
    if (sp.covers("content-digest")) {
      if (!Wba.contentDigest(b).equals(h.get("content-digest"))) throw fail("digest_mismatch", "the body doesn't match Content-Digest");
    } else if (b.length > 0) {
      throw fail("bad_signature", "a request body must be covered by content-digest");
    }

    long created;
    try {
      created = Long.parseLong(sp.params().getOrDefault("created", ""));
    } catch (NumberFormatException e) {
      throw fail("bad_signature", "created is required");
    }
    if (Math.abs(now - created) > maxSkew) throw fail("clock_skew", "created is " + (now - created) + "s from the server clock");
    if (sp.params().containsKey("expires")) {
      long exp;
      try {
        exp = Long.parseLong(sp.params().get("expires"));
      } catch (NumberFormatException e) {
        throw fail("clock_skew", "signature expired");
      }
      if (now > exp || exp - created > Wba.MAX_LIFETIME) throw fail("clock_skew", "signature expired");
    }
    String nonce = sp.params().get("nonce");
    if (nonce == null || nonce.isEmpty()) throw fail("bad_signature", "nonce is required");

    String identity = identityOf(agentUrl);
    // Before any fetch: callers outside the trust list can't make this API fetch directories.
    if (!trust.contains("*") && !trust.contains(identity)) throw fail("untrusted", identity + " is not in this API's trust list");
    String kid = sp.params().getOrDefault("keyid", "");
    Found found = lookup(agentUrl, identity, kid);
    Map<String, Object> key = found.key();
    byte[] pub = found.pub();

    String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
    List<String[]> comps = new ArrayList<>();
    for (String c : sp.components()) {
      String v = switch (c) {
        case "@method" -> method.toUpperCase(Locale.ROOT);
        case "@authority" -> h.getOrDefault("host", uri.getRawAuthority()).toLowerCase(Locale.ROOT);
        case "@path" -> path;
        case "@query" -> "?" + (query == null ? "" : query);
        default -> {
          if (c.startsWith("@")) throw fail("bad_signature", "unsupported component " + c);
          String hv = h.get(c);
          if (hv == null) throw fail("bad_signature", "covered header " + c + " is missing");
          yield hv;
        }
      };
      comps.add(new String[] {c, v});
    }
    if (!verifyEd25519(pub, Wba.base(comps, sp.raw()), sig)) throw fail("bad_signature", "the signature doesn't match the request");
    if (!nonces.add(agentUrl + " " + nonce, Duration.ofSeconds(2 * maxSkew))) throw fail("nonce_replayed", "this signature was already accepted once");
    return new Agent(identity, str(key.get("messh_name")), kid, str(key.get("messh_fingerprint")), agentUrl, created);
  }

  private static String str(Object o) {
    return o instanceof String s ? s : "";
  }

  private static boolean verifyEd25519(byte[] pub, byte[] message, byte[] sig) {
    try {
      byte[] spki = new byte[SPKI_PREFIX.length + 32];
      System.arraycopy(SPKI_PREFIX, 0, spki, 0, SPKI_PREFIX.length);
      System.arraycopy(pub, 0, spki, SPKI_PREFIX.length, 32);
      PublicKey pk = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
      Signature s = Signature.getInstance("Ed25519");
      s.initVerify(pk);
      s.update(message);
      return s.verify(sig);
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  private static String origin(URI u) {
    return u.getScheme().toLowerCase(Locale.ROOT) + "://" + u.getRawAuthority();
  }

  private String identityOf(String agentUrl) {
    URI u;
    try {
      u = new URI(agentUrl);
    } catch (URISyntaxException e) {
      throw fail("bad_signature", "Signature-Agent is not a URL");
    }
    if (u.getScheme() == null || u.getRawAuthority() == null) throw fail("bad_signature", "Signature-Agent is not a URL");
    if (!registries.containsKey(origin(u))) throw fail("untrusted", "Signature-Agent " + agentUrl + " is not a messh registry this API accepts");
    String id = u.getPath() == null ? "" : u.getPath().replaceAll("^/+|/+$", "");
    if (!IDENTITY.matcher(id).matches()) throw fail("unknown_key", "Signature-Agent must be <registry>/<user>");
    return id;
  }

  /**
   * The signer's key for kid. Directories are cached for cacheTtl; an unknown kid refetches at most
   * every 30 s (so a key published a moment ago works), unknown identities are remembered the same
   * way, one fetch per directory runs at a time, and while messh is unreachable cached keys keep
   * working for staleIfError.
   */
  private Found lookup(String agentUrl, String identity, String kid) {
    if (directory != null) return found(directory.apply(agentUrl, identity), agentUrl, kid);
    long now = clock.getAsLong();
    Entry e = cache.get(agentUrl);
    if (e != null && e.at() >= 0 && now - e.at() < cacheTtl) {
      Found hit = find(e.keys(), kid);
      if (hit != null) return hit;
      if (now - e.at() < MIN_REFRESH) return found(e.keys(), agentUrl, kid);
    }
    synchronized (fetching[Math.floorMod(agentUrl.hashCode(), FETCH_STRIPES)]) {
      e = cache.get(agentUrl);
      if (e != null && e.at() >= 0 && now - e.at() < Math.min(cacheTtl, MIN_REFRESH)) {
        return found(e.keys(), agentUrl, kid); // fetched by another thread while this one waited
      }
      if (e == null || e.failedAt() < 0 || now - e.failedAt() >= RETRY_AFTER) {
        Fetched r = fetch(agentUrl, identity);
        if (r.known()) {
          store(agentUrl, new Entry(r.keys(), now, -1, 0));
          return found(r.keys(), agentUrl, kid);
        }
        e = store(agentUrl, new Entry(e == null ? null : e.keys(), e == null ? -1 : e.at(), now, 0));
      }
    }
    // messh is unreachable: keep verifying with the cached directory for a while.
    if (e.at() >= 0 && now - e.at() < staleIfError) return found(e.keys(), agentUrl, kid);
    throw fail("unknown_key", "key directory for " + agentUrl + " is unavailable");
  }

  private static Found find(List<Map<String, Object>> keys, String kid) {
    if (keys == null) return null;
    for (Map<String, Object> k : keys) {
      if (kid.equals(k.get("kid"))) {
        byte[] p = Wba.jwkPublicKey(k);
        if (p != null) return new Found(k, p);
      }
    }
    return null;
  }

  private static Found found(List<Map<String, Object>> keys, String agentUrl, String kid) {
    Found f = find(keys, kid);
    if (f != null) return f;
    if (keys == null) throw fail("unknown_key", "there's no messh identity at " + agentUrl);
    throw fail("unknown_key", "keyid " + kid + " is not an active key of " + agentUrl + "; publish it with messh publish");
  }

  private Entry store(String agentUrl, Entry e) {
    Entry stored = new Entry(e.keys(), e.at(), e.failedAt(), seq.incrementAndGet());
    cache.put(agentUrl, stored);
    if (cache.size() > MAX_ENTRIES) {
      cache.entrySet().stream().min(Comparator.comparingLong(x -> x.getValue().seq())).ifPresent(x -> cache.remove(x.getKey(), x.getValue()));
    }
    return stored;
  }

  /** A directory's keys, known=true with null keys for no such identity; known=false if messh couldn't answer. */
  @SuppressWarnings("unchecked")
  private Fetched fetch(String agentUrl, String identity) {
    String url = registries.get(origin(URI.create(agentUrl))) + "/" + identity + Wba.DIRECTORY_PATH;
    try {
      HttpResponse<String> r = http.send(
          HttpRequest.newBuilder(URI.create(url)).timeout(timeout)
              .header("Accept", "application/http-message-signatures-directory+json, application/json")
              .header("User-Agent", "messh-java/" + MesshClient.VERSION).build(),
          HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
      if (r.statusCode() == 404) return new Fetched(null, true);
      if (r.statusCode() == 200 && Json.parse(r.body()) instanceof Map<?, ?> m && m.get("keys") instanceof List<?> l) {
        return new Fetched((List<Map<String, Object>>) l, true);
      }
    } catch (IOException | IllegalArgumentException e) {
      // messh is unreachable or didn't answer with a directory
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
    return new Fetched(null, false);
  }

  /** Builds a {@link MesshVerifier}. */
  public static final class Builder {
    private final List<String> trust = new ArrayList<>();
    private final Map<String, String> registries = new LinkedHashMap<>();
    private Duration maxSkew = Duration.ofSeconds(60);
    private Duration cacheTtl = Duration.ofMinutes(5);
    private Duration staleIfError = Duration.ofHours(1);
    private Duration timeout = Duration.ofSeconds(5);
    private long maxBodyBytes = MAX_BODY_BYTES;
    private NonceStore nonces;
    private HttpClient http;
    private LongSupplier clock;
    private BiFunction<String, String, List<Map<String, Object>>> directory;

    private Builder() {}

    /** Who may call: messh usernames, or "*". Required. */
    public Builder trust(String... patterns) {
      trust.addAll(List.of(patterns));
      return this;
    }

    /** Accept Signature-Agent URLs under origin; fetch directories from fetchBase (null = origin). Default https://messh.io. */
    public Builder registry(String origin, String fetchBase) {
      String o = origin.replaceAll("/+$", "");
      registries.put(o, fetchBase == null || fetchBase.isEmpty() ? o : fetchBase.replaceAll("/+$", ""));
      return this;
    }

    public Builder maxSkew(Duration d) {
      maxSkew = d;
      return this;
    }

    public Builder cacheTtl(Duration d) {
      cacheTtl = d;
      return this;
    }

    public Builder staleIfError(Duration d) {
      staleIfError = d;
      return this;
    }

    public Builder timeout(Duration d) {
      timeout = d;
      return this;
    }

    /** Largest request body {@link MesshHttpFilter} reads; bigger ones get 413 body_too_large. Default 1 MiB. */
    public Builder maxBodyBytes(long n) {
      maxBodyBytes = n;
      return this;
    }

    public Builder nonceStore(NonceStore s) {
      nonces = s;
      return this;
    }

    public Builder httpClient(HttpClient h) {
      http = h;
      return this;
    }

    /** Seconds since epoch (tests). */
    public Builder clock(LongSupplier c) {
      clock = c;
      return this;
    }

    /** Resolve directory keys yourself (tests, air-gapped setups): (agentUrl, identity) → JWK maps. */
    public Builder directory(BiFunction<String, String, List<Map<String, Object>>> d) {
      directory = d;
      return this;
    }

    public MesshVerifier build() {
      if (trust.isEmpty()) throw new IllegalStateException("trust(...) is required, e.g. trust(\"mukul\") or trust(\"*\")");
      return new MesshVerifier(this);
    }
  }
}
