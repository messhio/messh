package io.messh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.sun.net.httpserver.HttpServer;
import io.messh.verify.MesshVerifier;
import io.messh.verify.VerifyException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

/** Production behavior: whoami, ssh-agent, the verifier's directory cache policy. Runs against a local fake registry. */
@SuppressWarnings("unchecked")
class ProductionTest {
  static final Map<String, Object> JWK = (Map<String, Object>) VectorsTest.key().get("jwk");
  static final String FP = (String) JWK.get("messh_fingerprint");
  static final String KEYS = "{\"keys\":[" + toJson(JWK) + "]}";

  static String toJson(Map<String, Object> m) {
    StringBuilder b = new StringBuilder("{");
    m.forEach((k, v) -> b.append(b.length() > 1 ? "," : "").append(Json.quote(k)).append(':').append(Json.quote((String) v)));
    return b.append('}').toString();
  }

  /** A fake registry: dirs[identity] is a directory, absent for 404, "error" for 500. */
  static final class Registry implements AutoCloseable {
    final Map<String, String> dirs = new ConcurrentHashMap<>();
    final AtomicInteger hits = new AtomicInteger();
    final HttpServer server;
    final String url;

    Registry(Map<String, String> initial) throws IOException {
      dirs.putAll(initial);
      server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
      server.setExecutor(Executors.newCachedThreadPool());
      server.createContext("/", ex -> {
        hits.incrementAndGet();
        try {
          Thread.sleep(50); // let concurrent misses overlap
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
        String d = dirs.get(ex.getRequestURI().getPath().split("/")[1]);
        if (d == null || d.equals("error")) {
          ex.sendResponseHeaders(d == null ? 404 : 500, -1);
        } else {
          byte[] b = d.getBytes(StandardCharsets.UTF_8);
          ex.sendResponseHeaders(200, b.length);
          ex.getResponseBody().write(b);
        }
        ex.close();
      });
      server.start();
      url = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @Override
    public void close() {
      server.stop(0);
    }
  }

  static final class Setup implements AutoCloseable {
    final Registry reg;
    final AtomicLong clock = new AtomicLong(1_800_000_000L);
    final MesshVerifier verifier;

    Setup(Map<String, String> dirs, String... trust) throws IOException {
      reg = new Registry(dirs);
      verifier = MesshVerifier.builder().trust(trust.length == 0 ? new String[] {"*"} : trust).registry(reg.url, null).clock(clock::get).build();
    }

    String send(String identity) {
      MesshClient c = MesshClient.builder(identity).key(KeySource.file(VectorsTest.file("openssh"))).registry(reg.url).clock(clock::get).build();
      URI uri = URI.create("https://api.example/hello");
      Map<String, List<String>> headers = new LinkedHashMap<>();
      c.sign("GET", uri, null).forEach((k, v) -> headers.put(k, List.of(v)));
      try {
        verifier.verify("GET", uri, headers, null);
        return "ok";
      } catch (VerifyException e) {
        return e.code();
      }
    }

    @Override
    public void close() {
      reg.close();
    }
  }

  MesshClient as(String identity, String registry) {
    return MesshClient.builder(identity).key(KeySource.file(VectorsTest.file("openssh"))).registry(registry).build();
  }

  @Test
  void fingerprintAndWhoami() throws IOException {
    try (Registry reg = new Registry(Map.of("mukul", KEYS, "empty", "{\"keys\":[]}"))) {
      assertEquals(FP, as("mukul", reg.url).fingerprint());
      assertEquals(new PublishedKey("mukul", "sdk-test", (String) JWK.get("kid"), FP, reg.url + "/mukul"), as("mukul", reg.url).whoami());
      MesshException e = assertThrows(MesshException.class, () -> as("nobody", reg.url).whoami());
      assertEquals("not_published", e.code());
      assertTrue(e.getMessage().contains("no user nobody"), e.getMessage());
      e = assertThrows(MesshException.class, () -> as("empty", reg.url).whoami());
      assertTrue(e.code().equals("not_published") && e.getMessage().contains(FP), e.getMessage());
    }
    assertEquals("registry_unreachable", assertThrows(MesshException.class, () -> as("mukul", "http://127.0.0.1:1").whoami()).code());
  }

  @Test
  void fromEnvNeedsAnIdentity() {
    assumeTrue(System.getenv("MESSH_IDENTITY") == null);
    MesshException e = assertThrows(MesshException.class, MesshClient::fromEnv);
    assertEquals("invalid_identity", e.code());
    assertTrue(e.getMessage().contains("MESSH_IDENTITY"));
  }

  @Test
  void missingKeyFileSaysHowToFixIt() {
    MesshException e = assertThrows(MesshException.class, () -> MesshClient.builder("mukul").key(KeySource.file(Path.of("/nonexistent/id_ed25519"))).build());
    assertTrue(e.getMessage().contains("ssh-keygen -t ed25519"), e.getMessage());
  }

  @Test
  void untrustedCallersNeverTriggerAFetch() throws IOException {
    try (Setup s = new Setup(Map.of("mukul", KEYS), "alice")) {
      assertEquals("untrusted", s.send("mukul"));
      assertEquals(0, s.reg.hits.get());
    }
  }

  @Test
  void unknownIdentitiesAreRememberedFor30s() throws IOException {
    try (Setup s = new Setup(Map.of())) {
      assertEquals("unknown_key", s.send("ghost"));
      s.clock.addAndGet(10);
      assertEquals("unknown_key", s.send("ghost"));
      assertEquals(1, s.reg.hits.get());
      s.clock.addAndGet(21);
      s.send("ghost");
      assertEquals(2, s.reg.hits.get());
    }
  }

  @Test
  void newKeysWorkWithin30s() throws IOException {
    try (Setup s = new Setup(Map.of("mukul", "{\"keys\":[]}"))) {
      assertEquals("unknown_key", s.send("mukul"));
      s.reg.dirs.put("mukul", KEYS);
      s.clock.addAndGet(10);
      assertEquals("unknown_key", s.send("mukul"));
      s.clock.addAndGet(21);
      assertEquals("ok", s.send("mukul"));
      s.clock.addAndGet(60);
      assertEquals("ok", s.send("mukul"));
      assertEquals(2, s.reg.hits.get());
    }
  }

  @Test
  void notFoundIsNeverStaleButAnOutageIs() throws IOException {
    try (Setup s = new Setup(Map.of("mukul", KEYS))) {
      assertEquals("ok", s.send("mukul"));
      s.reg.dirs.put("mukul", "error");
      s.clock.addAndGet(301);
      assertEquals("ok", s.send("mukul"));
      s.clock.addAndGet(2);
      assertEquals("ok", s.send("mukul"));
      assertEquals(2, s.reg.hits.get(), "no retry within 5 s of a failure");
      s.reg.dirs.remove("mukul");
      s.clock.addAndGet(5);
      assertEquals("unknown_key", s.send("mukul"));
    }
  }

  @Test
  void concurrentMissesShareOneFetch() throws Exception {
    try (Setup s = new Setup(Map.of("mukul", KEYS))) {
      ExecutorService pool = Executors.newFixedThreadPool(4);
      List<Future<String>> got = new ArrayList<>();
      for (int i = 0; i < 4; i++) got.add(pool.submit(() -> s.send("mukul")));
      for (Future<String> f : got) assertEquals("ok", f.get());
      pool.shutdown();
      assertEquals(1, s.reg.hits.get());
    }
  }

  @Test
  void bodiesOverTheLimitGet413() throws Exception {
    MesshVerifier v = MesshVerifier.builder().trust("*").maxBodyBytes(8).directory((a, i) -> List.of(JWK)).build();
    HttpServer api = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    api.createContext("/", ex -> {
      ex.sendResponseHeaders(200, -1);
      ex.close();
    }).getFilters().add(new io.messh.verify.MesshHttpFilter(v));
    api.start();
    try {
      var r = java.net.http.HttpClient.newHttpClient().send(
          java.net.http.HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + api.getAddress().getPort() + "/x"))
              .POST(java.net.http.HttpRequest.BodyPublishers.ofString("0123456789")).build(),
          java.net.http.HttpResponse.BodyHandlers.ofString());
      assertEquals(413, r.statusCode());
      assertTrue(r.body().contains("body_too_large"), r.body());
    } finally {
      api.stop(0);
    }
  }

  /** A real ssh-agent holding the conformance key signs byte-identically to the file. */
  @Test
  void sshAgentSignsLikeTheKeyFile() throws Exception {
    String bin = List.of("/usr/bin/ssh-agent", "/opt/homebrew/bin/ssh-agent", "/usr/local/bin/ssh-agent").stream()
        .filter(p -> Files.exists(Path.of(p))).findFirst().orElse(null);
    assumeTrue(bin != null, "ssh-agent not installed");
    Path dir = Files.createTempDirectory("messh-agent-");
    Path sock = dir.resolve("agent.sock"), copy = dir.resolve("id");
    Files.copy(VectorsTest.file("openssh"), copy);
    Files.setPosixFilePermissions(copy, PosixFilePermissions.fromString("rw-------"));
    Process agent = new ProcessBuilder(bin, "-D", "-a", sock.toString()).redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
    try {
      for (int i = 0; i < 50 && !Files.exists(sock); i++) Thread.sleep(50);
      ProcessBuilder add = new ProcessBuilder("ssh-add", copy.toString()).redirectErrorStream(true);
      add.environment().put("SSH_AUTH_SOCK", sock.toString());
      assertEquals(0, add.start().waitFor());
      URI uri = URI.create("https://api.acme.dev/deployments");
      byte[] body = "{\"env\":\"staging\"}".getBytes(StandardCharsets.UTF_8);
      var sign = (java.util.function.Function<KeySource, Map<String, String>>) k -> MesshClient.builder("mukul").key(k)
          .clock(() -> 1760882531L).nonce(() -> "b3k2pUe8Qz1").build().sign("POST", uri, body);
      assertEquals(sign.apply(KeySource.file(VectorsTest.file("openssh"))), sign.apply(KeySource.sshAgent(null, sock)));
      MesshException e = assertThrows(MesshException.class, () -> MesshClient.builder("mukul").key(KeySource.sshAgent("SHA256:nope", sock)).build());
      assertTrue(e.getMessage().contains(FP), e.getMessage());
    } finally {
      agent.destroy();
      agent.waitFor();
    }
  }
}
