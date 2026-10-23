package io.messh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sun.net.httpserver.HttpServer;
import io.messh.verify.Agent;
import io.messh.verify.MesshHttpFilter;
import io.messh.verify.MesshVerifier;
import io.messh.verify.VerifyException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

@SuppressWarnings("unchecked")
class VectorsTest {
  static final Path VEC = Path.of("../../spec/vectors");
  static final Map<String, Object> DOC = load();

  static Map<String, Object> load() {
    try {
      return (Map<String, Object>) Json.parse(Files.readString(VEC.resolve("web-bot-auth.json")));
    } catch (java.io.IOException e) {
      throw new RuntimeException(e);
    }
  }

  static Map<String, Object> key() {
    return (Map<String, Object>) DOC.get("key");
  }

  static Path file(String kind) {
    return VEC.resolve((String) ((Map<String, Object>) key().get("files")).get(kind));
  }

  static List<Map<String, Object>> cases(String kind) {
    return (List<Map<String, Object>>) DOC.get(kind);
  }

  static byte[] body(Map<String, Object> c) {
    Object b = c.get("body");
    return b == null ? null : ((String) b).getBytes(StandardCharsets.UTF_8);
  }

  @Test
  void signVectors() {
    for (Map<String, Object> c : cases("sign")) {
      long created = (Long) c.get("created");
      MesshClient client = MesshClient.builder("mukul").key(KeySource.file(file("openssh")))
          .registry("https://registry.example").clock(() -> created).nonce(() -> (String) c.get("nonce")).build();
      Map<String, String> got = client.sign((String) c.get("method"), URI.create((String) c.get("url")), body(c));
      assertEquals(c.get("expected_headers"), new LinkedHashMap<String, Object>(got), (String) c.get("name"));
    }
  }

  @Test
  void keySources() throws Exception {
    String want = (String) ((Map<String, Object>) key().get("jwk")).get("kid");
    byte[] seed = HexFormat.of().parseHex((String) key().get("seed_hex"));
    for (KeySource k : List.of(KeySource.file(file("openssh")), KeySource.file(file("pkcs8")), KeySource.seed(seed),
        KeySource.signer(KeySource.parse(Files.readAllBytes(file("pkcs8")))))) {
      assertEquals(want, MesshClient.builder("mukul").key(k).build().keyId());
    }
    assertEquals("invalid_key", assertThrows(MesshException.class, () -> MesshClient.builder("mukul").key(KeySource.file(file("public"))).build()).code());
    assertEquals("invalid_identity", assertThrows(MesshException.class, () -> MesshClient.builder("Not A User").key(KeySource.seed(seed)).build()).code());
  }

  static MesshVerifier verifier(Map<String, Object> c, String trust, boolean registry) {
    List<Map<String, Object>> keys = (List<Map<String, Object>>) c.get("directory_keys");
    MesshVerifier.Builder b = MesshVerifier.builder().trust(trust).clock(() -> (Long) c.get("now")).directory((a, i) -> keys);
    if (registry) b.registry("https://registry.example", null);
    return b.build();
  }

  static Map<String, List<String>> headers(Map<String, Object> c) {
    Map<String, List<String>> h = new LinkedHashMap<>();
    ((Map<String, Object>) c.get("headers")).forEach((k, v) -> h.put(k, List.of((String) v)));
    return h;
  }

  @Test
  void verifyVectors() {
    for (Map<String, Object> c : cases("verify")) {
      MesshVerifier v = verifier(c, "*", true);
      URI uri = URI.create((String) c.get("url"));
      String got;
      try {
        Agent a = v.verify((String) c.get("method"), uri, headers(c), body(c));
        assertEquals("mukul", a.identity());
        assertEquals("sdk-test", a.keyName());
        assertEquals("nonce_replayed", assertThrows(VerifyException.class, () -> v.verify((String) c.get("method"), uri, headers(c), body(c))).code());
        got = "ok";
      } catch (VerifyException e) {
        got = e.code();
      }
      assertEquals(c.get("expect"), got, (String) c.get("name"));
    }
  }

  @Test
  void trustAndRegistry() {
    Map<String, Object> c = cases("verify").get(0);
    URI uri = URI.create((String) c.get("url"));
    VerifyException e = assertThrows(VerifyException.class, () -> verifier(c, "alice", true).verify("GET", uri, headers(c), null));
    assertEquals("untrusted", e.code());
    assertEquals(403, e.status());
    assertEquals("untrusted", assertThrows(VerifyException.class, () -> verifier(c, "*", false).verify("GET", uri, headers(c), null)).code());
    assertThrows(IllegalStateException.class, () -> MesshVerifier.builder().build());
  }

  @Test
  void httpServerFilter() throws Exception {
    // Sign live with the vector key and the real clock, verify through the JDK HttpServer filter.
    Map<String, Object> jwk = (Map<String, Object>) key().get("jwk");
    MesshVerifier v = MesshVerifier.builder().trust("mukul").registry("https://registry.example", null).directory((a, i) -> List.of(jwk)).build();
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/api", ex -> {
      Agent a = (Agent) ex.getAttribute(MesshHttpFilter.AGENT);
      byte[] out = (a.identity() + ":" + new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8);
      ex.sendResponseHeaders(200, out.length);
      ex.getResponseBody().write(out);
      ex.close();
    }).getFilters().add(new MesshHttpFilter(v));
    server.start();
    try {
      URI uri = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/api/deploy?dry=1");
      MesshClient client = MesshClient.builder("mukul").key(KeySource.file(file("openssh"))).registry("https://registry.example").build();
      HttpResponse<String> ok = client.send("POST", uri, "{\"env\":\"staging\"}".getBytes(StandardCharsets.UTF_8), HttpResponse.BodyHandlers.ofString());
      assertEquals(200, ok.statusCode(), ok.body());
      assertEquals("mukul:{\"env\":\"staging\"}", ok.body());
      HttpResponse<String> bad = HttpClient.newHttpClient().send(HttpRequest.newBuilder(uri).build(), HttpResponse.BodyHandlers.ofString());
      assertEquals(401, bad.statusCode());
      assertEquals(MesshVerifier.ACCEPT_SIGNATURE, bad.headers().firstValue("Accept-Signature").orElse(""));
    } finally {
      server.stop(0);
    }
  }
}
