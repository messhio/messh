package io.messh.verify;

import io.messh.Directories;
import io.messh.Json;
import io.messh.MesshClient;
import io.messh.Wba;
import io.messh.httpsig.HttpMessage;
import io.messh.httpsig.HttpSig;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiFunction;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;

/**
 * Verifies Web Bot Auth signatures with keys from messh, or from the key
 * directories of other agents you trust. Thread-safe; create once and reuse
 * (it caches key directories).
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
  private static final List<String> DEFAULT_REQUIRED = List.of("@method", "@authority", "@path", "signature-agent");
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
  private final List<String> required;
  private final boolean requireSigned;
  private final Map<String, Entry> cache = new ConcurrentHashMap<>();
  private final AtomicLong seq = new AtomicLong();
  private final Object[] fetching = new Object[FETCH_STRIPES];

  /**
   * A key directory: keys is the last good answer (null: no such identity), fetched at {@code at}
   * (-1: none yet); failedAt is the last failed fetch; signed holds the key IDs the response signed.
   */
  private record Entry(List<Map<String, Object>> keys, Set<String> signed, long at, long failedAt, long seq) {}

  private record Found(Map<String, Object> key, byte[] pub, boolean signed) {}

  private record Fetched(List<Map<String, Object>> keys, Set<String> signed, boolean known) {}

  /** Who a Signature-Agent names. */
  private record Who(String identity, boolean external, String fetchUrl, List<Map<String, Object>> inline) {}

  /**
   * A key directory response, checked.
   *
   * @param keys its keys (JWK maps)
   * @param signed the key IDs a valid directory signature covers
   */
  public record DirectoryCheck(List<Map<String, Object>> keys, Set<String> signed) {}

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
    this.required = b.required == null ? null : List.copyOf(b.required);
    this.requireSigned = b.requireSigned;
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
    byte[] b = body == null ? new byte[0] : body;
    HttpMessage msg = HttpMessage.request(method, uri.toString(), headers, b);
    HttpSig.Signature sig = null;
    for (HttpSig.Signature s : HttpSig.signatures(msg)) {
      if (Wba.TAG.equals(s.tag())) {
        sig = s;
        break;
      }
    }
    if (sig == null) throw fail("bad_signature", "no signature with tag=\"web-bot-auth\"");
    String query = uri.getRawQuery();
    coverage(sig, query != null && !query.isEmpty());
    String agentUrl = agentOf(h.get("signature-agent"), sig);
    if (sig.alg() != null && !sig.alg().equals("ed25519")) throw fail("bad_signature", "alg is not supported");

    if (sig.covers("content-digest")) HttpSig.checkDigest(h.getOrDefault("content-digest", ""), b);
    else if (b.length > 0) throw fail("bad_signature", "a request body must be covered by content-digest");

    Long created = sig.created();
    if (created == null) throw fail("bad_signature", "created is required");
    if (Math.abs(now - created) > maxSkew) throw fail("clock_skew", "created is " + (now - created) + "s from the server clock");
    if (sig.expires() != null && (now > sig.expires() || sig.expires() - created > Wba.MAX_LIFETIME)) throw fail("clock_skew", "signature expired");
    String nonce = sig.nonce();
    if (nonce == null || nonce.isEmpty()) throw fail("bad_signature", "nonce is required");

    String kid = sig.keyid() == null ? "" : sig.keyid();
    Who who = classify(agentUrl, kid);
    // Before any fetch: callers outside the trust list can't make this API fetch directories.
    if (trust.stream().noneMatch(t -> t.equals(who.identity()) || (t.equals("*") && !who.external()))) {
      throw fail("untrusted", who.identity() + " is not in this API's trust list");
    }
    Found found = lookup(agentUrl, who, kid);
    HttpSig.verifySignature(msg, sig, HttpSig.VerifyOptions.keys(k -> found.pub()).now(now).maxSkew(Duration.ofSeconds(maxSkew))
        .maxAge(Duration.ofSeconds(maxSkew)));
    if (!nonces.add(agentUrl + " " + nonce, Duration.ofSeconds(2 * maxSkew))) throw fail("nonce_replayed", "this signature was already accepted once");
    String fp = str(found.key().get("messh_fingerprint"));
    return new Agent(who.identity(), str(found.key().get("messh_name")), kid, fp.isEmpty() ? Wba.fingerprint(found.pub()) : fp, agentUrl,
        created, who.external(), found.signed());
  }

  private void coverage(HttpSig.Signature s, boolean hasQuery) {
    List<String> need = new ArrayList<>(required != null ? required : DEFAULT_REQUIRED);
    need.add("signature-agent");
    for (String c : need) if (!has(s, c)) throw fail("bad_signature", c + " must be covered");
    if (hasQuery && !has(s, "@query")) throw fail("bad_signature", "@query must be covered when the URL has a query");
  }

  private static boolean has(HttpSig.Signature s, String name) {
    return s.covers(name)
        || (name.equals("@authority") && s.covers("@target-uri"))
        || ((name.equals("@path") || name.equals("@query")) && (s.covers("@target-uri") || s.covers("@request-target")));
  }

  /** Signature-Agent: the member named by the covered component's key parameter, else a string, else the member named like the label. */
  private static String agentOf(String header, HttpSig.Signature s) {
    if (header == null || header.isEmpty()) throw fail("bad_signature", "Signature-Agent header is missing");
    String key = null;
    for (HttpSig.Covered c : s.covered()) {
      if (c.name().equals("signature-agent") && c.key() != null) {
        key = c.key();
        break;
      }
    }
    if (key != null) {
      String v = HttpSig.stringMember(header, key);
      if (v == null) throw fail("bad_signature", "Signature-Agent has no member " + key);
      return v;
    }
    String v = HttpSig.stringItem(header);
    if (v == null) v = HttpSig.stringMember(header, s.label());
    if (v == null) throw fail("bad_signature", "Signature-Agent has no value for " + s.label());
    return v;
  }

  private static String str(Object o) {
    return o instanceof String s ? s : "";
  }

  private static String origin(URI u) {
    return u.getScheme().toLowerCase(Locale.ROOT) + "://" + u.getRawAuthority();
  }

  /** Map Signature-Agent to a messh identity (registry/user), an agent origin, or inline keys, refusing anything else. */
  private Who classify(String agentUrl, String kid) {
    if (agentUrl.startsWith("data:")) return new Who("jwk:" + kid, true, null, parseDataUri(agentUrl));
    URI u;
    try {
      u = new URI(agentUrl);
    } catch (URISyntaxException e) {
      throw fail("bad_signature", "Signature-Agent is not a URL");
    }
    if (u.getScheme() == null || u.getRawAuthority() == null || !(u.getScheme().equals("https") || u.getScheme().equals("http"))) {
      throw fail("bad_signature", "Signature-Agent is not a URL");
    }
    String base = registries.get(origin(u));
    if (base != null) {
      String id = u.getPath() == null ? "" : u.getPath().replaceAll("^/+|/+$", "");
      if (!IDENTITY.matcher(id).matches()) throw fail("unknown_key", "Signature-Agent must be <registry>/<user>");
      return new Who(id, false, base + "/" + id + Wba.DIRECTORY_PATH, null);
    }
    String o = origin(u).toLowerCase(Locale.ROOT);
    if (trust.contains(o)) {
      String path = u.getRawPath() == null ? "" : u.getRawPath();
      if (!(path.isEmpty() || path.equals("/")) || u.getRawQuery() != null) {
        throw fail("untrusted", "Signature-Agent " + agentUrl + ": an agent outside messh is an origin, like " + o);
      }
      return new Who(o, true, o + Wba.DIRECTORY_PATH, null);
    }
    throw fail("untrusted", "Signature-Agent " + agentUrl + " is not a messh registry or an agent this API trusts");
  }

  /** An inline key directory: data:application/http-message-signatures-directory[+json][;base64],… */
  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> parseDataUri(String s) {
    int comma = s.indexOf(',');
    String meta = comma < 0 ? "" : s.substring(5, comma);
    boolean b64 = meta.endsWith(";base64");
    String media = (b64 ? meta.substring(0, meta.length() - 7) : meta).split(";")[0].trim().toLowerCase(Locale.ROOT);
    if (comma < 0 || !List.of("application/http-message-signatures-directory", "application/http-message-signatures-directory+json", "application/json").contains(media)) {
      throw fail("bad_signature", "Signature-Agent: the data URI isn't a key directory");
    }
    try {
      String data = s.substring(comma + 1);
      String json = b64 ? new String(Base64.getDecoder().decode(data.replaceAll("=+$", "")), StandardCharsets.UTF_8)
          : URLDecoder.decode(data.replace("+", "%2B"), StandardCharsets.UTF_8);
      if (Json.parse(json) instanceof Map<?, ?> m && m.get("keys") instanceof List<?> keys) return (List<Map<String, Object>>) keys;
    } catch (IllegalArgumentException e) {
      // below
    }
    throw fail("bad_signature", "Signature-Agent: the data URI isn't a key directory");
  }

  /**
   * The signer's key for kid, and whether its directory response signed it. Directories are cached
   * for cacheTtl; an unknown kid refetches at most every 30 s (so a key published a moment ago
   * works), unknown identities are remembered the same way, one fetch per directory runs at a time,
   * and while the directory is unreachable cached keys keep working for staleIfError.
   */
  private Found lookup(String agentUrl, Who who, String kid) {
    if (who.inline() != null) return found(who.inline(), null, agentUrl, kid);
    if (directory != null) return found(directory.apply(agentUrl, who.identity()), null, agentUrl, kid);
    long now = clock.getAsLong();
    Entry e = cache.get(agentUrl);
    if (e != null && e.at() >= 0 && now - e.at() < cacheTtl) {
      if (find(e.keys(), kid) != null) return found(e.keys(), e.signed(), agentUrl, kid);
      if (now - e.at() < MIN_REFRESH) return found(e.keys(), null, agentUrl, kid);
    }
    synchronized (fetching[Math.floorMod(agentUrl.hashCode(), FETCH_STRIPES)]) {
      e = cache.get(agentUrl);
      if (e != null && e.at() >= 0 && now - e.at() < Math.min(cacheTtl, MIN_REFRESH)) {
        return found(e.keys(), e.signed(), agentUrl, kid); // fetched by another thread while this one waited
      }
      if (e == null || e.failedAt() < 0 || now - e.failedAt() >= RETRY_AFTER) {
        Fetched r = fetch(who.fetchUrl());
        if (r.known()) {
          store(agentUrl, new Entry(r.keys(), r.signed(), now, -1, 0));
          return found(r.keys(), r.signed(), agentUrl, kid);
        }
        e = store(agentUrl, new Entry(e == null ? null : e.keys(), e == null ? Set.of() : e.signed(), e == null ? -1 : e.at(), now, 0));
      }
    }
    // The directory is unreachable: keep verifying with the cached one for a while.
    if (e.at() >= 0 && now - e.at() < staleIfError) return found(e.keys(), e.signed(), agentUrl, kid);
    throw fail("unknown_key", "key directory for " + agentUrl + " is unavailable");
  }

  private static Found find(List<Map<String, Object>> keys, String kid) {
    if (keys == null) return null;
    for (Map<String, Object> k : keys) {
      byte[] p = Wba.jwkPublicKey(k);
      if (p != null && (kid.equals(k.get("kid")) || (k.get("kid") == null && Wba.thumbprint(p).equals(kid)))) return new Found(k, p, false);
    }
    return null;
  }

  private static Found found(List<Map<String, Object>> keys, Set<String> signed, String agentUrl, String kid) {
    Found f = find(keys, kid);
    if (f != null) return new Found(f.key(), f.pub(), signed != null && signed.contains(kid));
    if (keys == null) throw fail("unknown_key", "there's no messh identity at " + agentUrl);
    throw fail("unknown_key", "keyid " + kid + " is not an active key of " + agentUrl + "; publish it with messh publish");
  }

  private Entry store(String agentUrl, Entry e) {
    Entry stored = new Entry(e.keys(), e.signed(), e.at(), e.failedAt(), seq.incrementAndGet());
    cache.put(agentUrl, stored);
    if (cache.size() > MAX_ENTRIES) {
      cache.entrySet().stream().min(Comparator.comparingLong(x -> x.getValue().seq())).ifPresent(x -> cache.remove(x.getKey(), x.getValue()));
    }
    return stored;
  }

  /** A directory's keys, known=true with null keys for no such identity; known=false if it couldn't be fetched. */
  private Fetched fetch(String url) {
    try {
      HttpResponse<byte[]> r = http.send(
          HttpRequest.newBuilder(URI.create(url)).timeout(timeout)
              .header("Accept", "application/http-message-signatures-directory+json, application/json")
              .header("User-Agent", "messh-java/" + MesshClient.VERSION).build(),
          HttpResponse.BodyHandlers.ofByteArray());
      if (r.statusCode() == 404) return new Fetched(null, Set.of(), true);
      if (r.statusCode() == 200) {
        DirectoryCheck d = verifyDirectory(url, r.headers().map(), r.body(), clock.getAsLong());
        List<Map<String, Object>> keys = d.keys();
        if (requireSigned) keys = keys.stream().filter(k -> d.signed().contains(str(k.get("kid")))).toList();
        return new Fetched(keys, d.signed(), true);
      }
    } catch (IOException | IllegalArgumentException e) {
      // the directory is unreachable or isn't a directory
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
    return new Fetched(null, Set.of(), false);
  }

  /**
   * Read a key directory response fetched from url: its keys, and the key IDs a valid directory
   * signature covers (tag http-message-signatures-directory, signed by that key, binding the response
   * to the authority it came from; draft-meunier-http-message-signatures-directory §5). Throws
   * IllegalArgumentException if the body isn't a key directory. now is seconds since epoch.
   */
  @SuppressWarnings("unchecked")
  public static DirectoryCheck verifyDirectory(String url, Map<String, List<String>> headers, byte[] body, long now) {
    if (!(Json.parse(new String(body, StandardCharsets.UTF_8)) instanceof Map<?, ?> m) || !(m.get("keys") instanceof List<?> l)) {
      throw new IllegalArgumentException("not a key directory");
    }
    List<Map<String, Object>> keys = (List<Map<String, Object>>) l;
    // The response carries the request's URL too, for directories signed over a plain "@authority".
    HttpMessage msg = HttpMessage.response(200, headers, body, HttpMessage.request("GET", url, Map.of(), null)).withUrl(url);
    Set<String> signed = new HashSet<>();
    List<HttpSig.Signature> sigs;
    try {
      sigs = HttpSig.signatures(msg);
    } catch (VerifyException e) {
      return new DirectoryCheck(keys, signed);
    }
    for (HttpSig.Signature s : sigs) {
      if (!Directories.TAG.equals(s.tag()) || s.keyid() == null) continue;
      Found f = find(keys, s.keyid());
      if (f == null) continue;
      try {
        HttpSig.verifySignature(msg, s, HttpSig.VerifyOptions.keys(k -> f.pub()).now(now));
        signed.add(s.keyid());
      } catch (VerifyException e) {
        // not signed
      }
    }
    return new DirectoryCheck(keys, signed);
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
    private List<String> required;
    private boolean requireSigned;

    private Builder() {}

    /**
     * Who may call. Required: messh usernames, "*" for any messh identity, the origin of another Web
     * Bot Auth agent ("https://agent.example", whose key directory is at
     * &lt;origin&gt;/.well-known/http-message-signatures-directory), or jwk:&lt;thumbprint&gt; for a key
     * sent inline in Signature-Agent.
     */
    public Builder trust(String... patterns) {
      for (String p : patterns) {
        trust.add(p.startsWith("https://") || p.startsWith("http://") ? p.toLowerCase(Locale.ROOT).replaceAll("/+$", "") : p);
      }
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

    /** Resolve directory keys yourself (tests, air-gapped setups): (agentUrl, identity) → JWK maps, null for no such identity. */
    public Builder directory(BiFunction<String, String, List<Map<String, Object>>> d) {
      directory = d;
      return this;
    }

    /**
     * Replace the components every signature must cover (default @method, @authority, @path,
     * signature-agent), for agents that sign less. @target-uri counts for @authority, @path and
     * @query, @request-target for @path and @query. Signature-Agent, a query and a body (through
     * content-digest) must be covered regardless.
     */
    public Builder requireComponents(String... names) {
      required = List.of(names);
      return this;
    }

    /** Ignore keys a fetched key directory doesn't sign (draft §5). messh.io doesn't sign its directories yet. */
    public Builder requireSignedDirectory(boolean on) {
      requireSigned = on;
      return this;
    }

    public MesshVerifier build() {
      if (trust.isEmpty()) throw new IllegalStateException("trust(...) is required, e.g. trust(\"mukul\") or trust(\"*\")");
      return new MesshVerifier(this);
    }
  }
}
