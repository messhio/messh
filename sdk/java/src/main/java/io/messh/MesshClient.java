package io.messh;

import io.messh.httpsig.HttpMessage;
import io.messh.httpsig.HttpSig;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * Signs HTTP requests as a messh identity with Web Bot Auth (RFC 9421,
 * Ed25519, tag="web-bot-auth"). Thread-safe; create once and reuse.
 *
 * <pre>{@code
 * MesshClient client = MesshClient.builder("mukul")
 *     .key(KeySource.file(Path.of("~/.ssh/id_ed25519")))
 *     .build();
 * HttpResponse<String> r = client.send("GET", URI.create("https://api.example.com/hello"), null,
 *     HttpResponse.BodyHandlers.ofString());
 * }</pre>
 */
public final class MesshClient {
  public static final String VERSION = "0.2.0";
  public static final String DEFAULT_REGISTRY = "https://messh.io";
  private static final Pattern IDENTITY = Pattern.compile("^[a-z0-9](?:[a-z0-9-]{1,28}[a-z0-9])$");
  private static final SecureRandom RANDOM = new SecureRandom();

  private final String identity;
  private final String registry;
  private final Signer signer;
  private final String keyId;
  private final long expiresIn;
  private final HttpClient http;
  private final LongSupplier clock;
  private final Supplier<String> nonce;
  private final String label;
  private final String tag;
  private final List<String> components;
  private final boolean agentDictionary;

  private MesshClient(Builder b, Signer signer) {
    this.identity = b.identity;
    this.registry = b.registry.replaceAll("/+$", "");
    this.signer = signer;
    this.keyId = Wba.thumbprint(signer.publicKey());
    this.expiresIn = b.expiresIn.getSeconds();
    this.http = b.http != null ? b.http : HttpClient.newHttpClient();
    this.clock = b.clock != null ? b.clock : () -> System.currentTimeMillis() / 1000;
    this.nonce = b.nonce != null ? b.nonce : MesshClient::randomNonce;
    this.label = b.label;
    this.tag = b.tag;
    this.components = List.copyOf(b.components);
    this.agentDictionary = b.agentDictionary;
  }

  /** Start building a client for identity, a messh username such as "mukul". */
  public static Builder builder(String identity) {
    return new Builder(identity);
  }

  /**
   * A client from the environment, for agents and CI: MESSH_IDENTITY (required), MESSH_KEY (PEM,
   * or base64 of PEM or PKCS#8 DER) or MESSH_KEY_FILE (default ~/.ssh/id_ed25519), and
   * MESSH_REGISTRY.
   */
  public static MesshClient fromEnv() {
    return builderFromEnv().build();
  }

  /** Like {@link #fromEnv()}, as a builder you can adjust before {@code build()}. */
  public static Builder builderFromEnv() {
    String identity = env("MESSH_IDENTITY");
    if (identity == null) throw new MesshException("invalid_identity", "set MESSH_IDENTITY to your messh username");
    Builder b = new Builder(identity);
    if (env("MESSH_KEY") != null) b.key(KeySource.env("MESSH_KEY"));
    else if (env("MESSH_KEY_FILE") != null) b.key(KeySource.file(Path.of(env("MESSH_KEY_FILE"))));
    if (env("MESSH_REGISTRY") != null) b.registry(env("MESSH_REGISTRY"));
    return b;
  }

  private static String env(String name) {
    String v = System.getenv(name);
    return v == null || v.isBlank() ? null : v.trim();
  }

  private static String randomNonce() {
    byte[] b = new byte[16];
    RANDOM.nextBytes(b);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }

  public String identity() {
    return identity;
  }

  /** keyid sent in Signature-Input (RFC 7638 JWK thumbprint). */
  public String keyId() {
    return keyId;
  }

  /** SSH fingerprint of the signing key (SHA256:…), as {@code messh keys} and ssh-keygen -l print it. */
  public String fingerprint() {
    return Wba.fingerprint(signer.publicKey());
  }

  /**
   * Check that this client's key is published and active on messh, and how APIs will see it. Run
   * it once at startup: it turns the most common setup mistake (an unpublished key, so every API
   * answers 401 unknown_key) into a clear error. Throws {@link MesshException} not_published or
   * registry_unreachable.
   */
  @SuppressWarnings("unchecked")
  public PublishedKey whoami() {
    String url = agent() + Wba.DIRECTORY_PATH;
    HttpResponse<String> r;
    try {
      r = http.send(
          HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10))
              .header("Accept", "application/http-message-signatures-directory+json, application/json")
              .header("User-Agent", "messh-java/" + VERSION).build(),
          HttpResponse.BodyHandlers.ofString());
    } catch (IOException e) {
      throw new MesshException("registry_unreachable", "can't reach " + registry + ": " + e.getMessage());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new MesshException("registry_unreachable", "interrupted");
    }
    if (r.statusCode() == 404) {
      throw new MesshException("not_published", registry + " has no user " + identity + "; sign up, then publish this key (" + fingerprint() + ") with messh publish");
    }
    Object dir = r.statusCode() == 200 ? parseJson(r.body()) : null;
    if (!(dir instanceof Map<?, ?> m) || !(m.get("keys") instanceof List<?> keys)) {
      throw new MesshException("registry_unreachable", url + " answered HTTP " + r.statusCode() + " without a key directory");
    }
    for (Object o : keys) {
      if (o instanceof Map<?, ?> k && keyId.equals(k.get("kid"))) {
        String name = k.get("messh_name") instanceof String n ? n : "";
        String fp = k.get("messh_fingerprint") instanceof String f && !f.isEmpty() ? f : fingerprint();
        return new PublishedKey(identity, name, keyId, fp, agent());
      }
    }
    throw new MesshException("not_published", "this key (" + fingerprint() + ") isn't an active key of " + agent() + "; publish it with messh publish --key <key>.pub --name <name>");
  }

  private static Object parseJson(String s) {
    try {
      return Json.parse(s);
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  /** Signature-Agent URL: {@code <registry>/<identity>}. */
  public String agent() {
    return registry + "/" + identity;
  }

  /** Headers to add for a request to uri. body may be null. */
  public Map<String, String> sign(String method, URI uri, byte[] body) {
    return sign(method, uri, body, null);
  }

  /**
   * Headers to add: Signature-Agent, Signature-Input, Signature and, with a
   * body, Content-Digest. host overrides the authority if you send a
   * different Host header. Sign last; don't change the request afterwards.
   */
  public Map<String, String> sign(String method, URI uri, byte[] body, String host) {
    return sign(method, uri, body, host, Map.of());
  }

  /**
   * Like {@link #sign(String, URI, byte[], String)}, with the request's headers, for covered
   * components beyond the defaults.
   */
  public Map<String, String> sign(String method, URI uri, byte[] body, String host, Map<String, String> requestHeaders) {
    if (uri.getRawAuthority() == null) throw new MesshException("sign_failed", "uri must be absolute");
    String agentValue = "\"" + agent().replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    Map<String, String> headers = new LinkedHashMap<>();
    headers.put("Signature-Agent", agentDictionary ? label + "=" + agentValue : agentValue);
    List<String> comps = new ArrayList<>(List.of("@method", "@authority", "@path"));
    if (uri.getRawQuery() != null && !uri.getRawQuery().isEmpty()) comps.add("@query");
    if (body != null && body.length > 0) {
      headers.put("Content-Digest", Wba.contentDigest(body));
      comps.add("content-digest");
    }
    comps.addAll(components);
    comps.add(agentDictionary ? "\"signature-agent\";key=\"" + label + "\"" : "signature-agent");
    List<String> own = List.of("signature-agent", "content-digest", "signature-input", "signature");
    Map<String, List<String>> fields = new LinkedHashMap<>();
    requestHeaders.forEach((k, v) -> {
      String n = k.toLowerCase(Locale.ROOT);
      if (!own.contains(n) && !(host != null && n.equals("host"))) fields.computeIfAbsent(n, x -> new ArrayList<>()).add(v);
    });
    headers.forEach((k, v) -> fields.put(k.toLowerCase(Locale.ROOT), List.of(v)));
    if (host != null) fields.put("host", List.of(host));
    long created = clock.getAsLong();
    HttpSig.Signed signed;
    try {
      signed = HttpSig.sign(HttpMessage.request(method.toUpperCase(Locale.ROOT), uri.toString(), fields, null), signer,
          HttpSig.SignOptions.of().components(comps).label(label).created(created).expires(created + expiresIn).keyid(keyId)
              .alg("ed25519").nonce(nonce.get()).tag(tag));
    } catch (RuntimeException e) {
      throw new MesshException("sign_failed", String.valueOf(e.getMessage()));
    }
    headers.putAll(signed.headers());
    return headers;
  }

  /** A signed java.net.http request builder; add more (unsigned) headers if you like. */
  public HttpRequest.Builder newRequest(String method, URI uri, byte[] body) {
    HttpRequest.Builder b = HttpRequest.newBuilder(uri)
        .method(method.toUpperCase(Locale.ROOT), body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body))
        .header("User-Agent", "messh-java/" + VERSION);
    if (body != null) b.header("Content-Type", "application/json");
    sign(method, uri, body).forEach(b::header);
    return b;
  }

  /** Sign and send. */
  public <T> HttpResponse<T> send(String method, URI uri, byte[] body, HttpResponse.BodyHandler<T> handler)
      throws IOException, InterruptedException {
    return http.send(newRequest(method, uri, body).build(), handler);
  }

  /** Sign and send asynchronously. */
  public <T> CompletableFuture<HttpResponse<T>> sendAsync(String method, URI uri, byte[] body, HttpResponse.BodyHandler<T> handler) {
    return http.sendAsync(newRequest(method, uri, body).build(), handler);
  }

  /** Builds a {@link MesshClient}. */
  public static final class Builder {
    private final String identity;
    private KeySource key;
    private String registry = DEFAULT_REGISTRY;
    private Duration expiresIn = Duration.ofSeconds(60);
    private HttpClient http;
    private LongSupplier clock;
    private Supplier<String> nonce;
    private String label = Wba.LABEL;
    private String tag = Wba.TAG;
    private final List<String> components = new ArrayList<>();
    private boolean agentDictionary;

    private Builder(String identity) {
      this.identity = identity;
    }

    /** Signing key. Default: KeySource.file(~/.ssh/id_ed25519). */
    public Builder key(KeySource key) {
      this.key = key;
      return this;
    }

    /** messh registry base URL. Default: https://messh.io. */
    public Builder registry(String url) {
      this.registry = url;
      return this;
    }

    /** Signature lifetime. Default 60 s, max 300 s. */
    public Builder expiresIn(Duration d) {
      this.expiresIn = d;
      return this;
    }

    /** HTTP client for send/sendAsync. Default: HttpClient.newHttpClient(). */
    public Builder httpClient(HttpClient http) {
      this.http = http;
      return this;
    }

    /** Seconds since epoch (tests). */
    public Builder clock(LongSupplier clock) {
      this.clock = clock;
      return this;
    }

    /** Nonce generator (tests). */
    public Builder nonce(Supplier<String> nonce) {
      this.nonce = nonce;
      return this;
    }

    /**
     * Cover more components than the defaults, after them: "content-type", "@target-uri",
     * "\"@query-param\";name=\"id\"". Header values come from {@link MesshClient#sign(String, URI, byte[], String, Map)}.
     */
    public Builder components(String... c) {
      components.addAll(List.of(c));
      return this;
    }

    /** Signature label. Default "sig1". */
    public Builder label(String l) {
      label = l;
      return this;
    }

    /** Signature tag. Default "web-bot-auth"; with any other tag it isn't a Web Bot Auth signature. */
    public Builder tag(String t) {
      tag = t;
      return this;
    }

    /**
     * Send Signature-Agent in the dictionary form of newer drafts, keyed by the label
     * (sig1="https://messh.io/mukul"), covered as "signature-agent";key="sig1". The default string
     * form is what messh verifiers before 0.2.0 require.
     */
    public Builder agentDictionary(boolean on) {
      agentDictionary = on;
      return this;
    }

    public MesshClient build() {
      if (label == null || !label.matches("[a-z*][a-z0-9_\\-.*]*")) throw new MesshException("invalid_option", "a label is lowercase letters, digits and _-.*, starting with a letter");
      if (tag == null || tag.isEmpty() || !tag.chars().allMatch(ch -> ch >= 0x20 && ch <= 0x7e)) throw new MesshException("invalid_option", "a tag is printable ASCII");
      if (identity == null || !IDENTITY.matcher(identity).matches()) throw new MesshException("invalid_identity", identity + " is not a messh username");
      if (!registry.startsWith("https://") && !registry.startsWith("http://")) throw new MesshException("invalid_option", "registry must be an http(s) URL");
      long s = expiresIn.getSeconds();
      if (s < 1 || s > Wba.MAX_LIFETIME) throw new MesshException("invalid_option", "expiresIn must be 1..300 seconds");
      KeySource k = key != null ? key : KeySource.file(Path.of(System.getProperty("user.home"), ".ssh", "id_ed25519"));
      return new MesshClient(this, k.load());
    }
  }
}
