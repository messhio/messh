package io.messh;

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
  public static final String VERSION = "0.1.0";
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

  private MesshClient(Builder b, Signer signer) {
    this.identity = b.identity;
    this.registry = b.registry.replaceAll("/+$", "");
    this.signer = signer;
    this.keyId = Wba.thumbprint(signer.publicKey());
    this.expiresIn = b.expiresIn.getSeconds();
    this.http = b.http != null ? b.http : HttpClient.newHttpClient();
    this.clock = b.clock != null ? b.clock : () -> System.currentTimeMillis() / 1000;
    this.nonce = b.nonce != null ? b.nonce : MesshClient::randomNonce;
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
    if (uri.getRawAuthority() == null) throw new MesshException("sign_failed", "uri must be absolute");
    String agentHeader = Wba.quote(agent());
    List<String[]> comps = new ArrayList<>();
    comps.add(new String[] {"@method", method.toUpperCase(Locale.ROOT)});
    comps.add(new String[] {"@authority", (host != null ? host : uri.getRawAuthority()).toLowerCase(Locale.ROOT)});
    String path = uri.getRawPath();
    comps.add(new String[] {"@path", path == null || path.isEmpty() ? "/" : path});
    if (uri.getRawQuery() != null && !uri.getRawQuery().isEmpty()) comps.add(new String[] {"@query", "?" + uri.getRawQuery()});
    Map<String, String> headers = new LinkedHashMap<>();
    headers.put("Signature-Agent", agentHeader);
    if (body != null && body.length > 0) {
      String d = Wba.contentDigest(body);
      headers.put("Content-Digest", d);
      comps.add(new String[] {"content-digest", d});
    }
    comps.add(new String[] {"signature-agent", agentHeader});
    List<String> names = new ArrayList<>();
    for (String[] c : comps) names.add(c[0]);
    long created = clock.getAsLong();
    String params = Wba.params(names, created, created + expiresIn, keyId, nonce.get());
    byte[] sig;
    try {
      sig = signer.sign(Wba.base(comps, params));
    } catch (RuntimeException e) {
      throw new MesshException("sign_failed", String.valueOf(e.getMessage()));
    }
    headers.put("Signature-Input", Wba.LABEL + "=" + params);
    headers.put("Signature", Wba.LABEL + "=:" + Base64.getEncoder().encodeToString(sig) + ":");
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

    public MesshClient build() {
      if (identity == null || !IDENTITY.matcher(identity).matches()) throw new MesshException("invalid_identity", identity + " is not a messh username");
      if (!registry.startsWith("https://") && !registry.startsWith("http://")) throw new MesshException("invalid_option", "registry must be an http(s) URL");
      long s = expiresIn.getSeconds();
      if (s < 1 || s > Wba.MAX_LIFETIME) throw new MesshException("invalid_option", "expiresIn must be 1..300 seconds");
      KeySource k = key != null ? key : KeySource.file(Path.of(System.getProperty("user.home"), ".ssh", "id_ed25519"));
      return new MesshClient(this, k.load());
    }
  }
}
