package io.messh;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.messh.verify.Agent;
import io.messh.verify.MesshVerifier;
import io.messh.verify.VerifyException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

@SuppressWarnings("unchecked")
class MessageSignaturesVectorsTest {
  static final Map<String, Object> DOC = load();

  static Map<String, Object> load() {
    try {
      return (Map<String, Object>) Json.parse(Files.readString(Path.of("../../spec/vectors/http-message-signatures.json")));
    } catch (java.io.IOException e) {
      throw new RuntimeException(e);
    }
  }

  static Map<String, Object> key(String name) {
    return (Map<String, Object>) ((Map<String, Object>) DOC.get("keys")).get(name);
  }

  static KeySource seed(String name) {
    return KeySource.seed(HexFormat.of().parseHex((String) key(name).get("seed_hex")));
  }

  @Test
  void webBotAuth() {
    Map<String, Object> wba = (Map<String, Object>) DOC.get("web_bot_auth");
    for (Map<String, Object> c : (List<Map<String, Object>>) wba.get("cases")) {
      String name = (String) c.get("name");
      long now = ((Number) c.get("now")).longValue();
      Map<String, List<String>> dirs = (Map<String, List<String>>) c.get("directories");
      MesshVerifier.Builder b = MesshVerifier.builder().trust(((List<String>) c.get("trust")).toArray(String[]::new))
          .registry((String) wba.get("registry"), null).clock(() -> now)
          .directory((agentUrl, identity) -> {
            List<String> names = dirs.get(agentUrl);
            if (names == null) return null;
            List<Map<String, Object>> keys = new ArrayList<>();
            for (String n : names) keys.add(Map.of("kty", "OKP", "crv", "Ed25519", "x", key(n).get("x"), "kid", key(n).get("thumbprint")));
            return keys;
          });
      if (c.get("require") instanceof List<?> r) b.requireComponents(((List<String>) r).toArray(String[]::new));
      Map<String, Object> m = (Map<String, Object>) c.get("message");
      Map<String, List<String>> headers = new LinkedHashMap<>();
      for (Object p : (List<Object>) m.get("headers")) {
        List<String> kv = (List<String>) p;
        headers.computeIfAbsent(kv.get(0), k -> new ArrayList<>()).add(kv.get(1));
      }
      byte[] body = m.get("body") instanceof String s ? s.getBytes(StandardCharsets.UTF_8) : null;
      try {
        Agent a = b.build().verify((String) m.get("method"), URI.create((String) m.get("url")), headers, body);
        assertEquals("ok", c.get("expect"), name);
        assertEquals(c.get("identity"), a.identity(), name);
        assertEquals(Boolean.TRUE.equals(c.get("external")), a.external(), name);
      } catch (VerifyException e) {
        assertEquals(c.get("expect"), e.code(), name + ": " + e.getMessage());
      }
    }
  }

  @Test
  void clientDictionaryAgent() {
    for (Map<String, Object> c : (List<Map<String, Object>>) DOC.get("sign")) {
      if (!(c.get("client") instanceof Map<?, ?> cm)) continue;
      Map<String, Object> cl = (Map<String, Object>) cm;
      long created = ((Number) cl.get("created")).longValue();
      MesshClient client = MesshClient.builder((String) cl.get("identity")).key(seed((String) c.get("key"))).registry((String) cl.get("registry"))
          .clock(() -> created).nonce(() -> (String) cl.get("nonce")).agentDictionary(true).build();
      Map<String, Object> m = (Map<String, Object>) c.get("message");
      assertEquals(c.get("expected_headers"), client.sign((String) m.get("method"), URI.create((String) m.get("url")), null));
    }
  }

  @Test
  void directories() {
    Map<String, Object> d = (Map<String, Object>) ((Map<String, Object>) DOC.get("directory")).get("sign");
    List<KeySource> keys = new ArrayList<>();
    for (String n : (List<String>) d.get("keys")) keys.add(seed(n));
    Directories.Response r = Directories.response((String) d.get("authority"), keys, ((Number) d.get("created")).longValue(),
        Duration.ofSeconds(((Number) d.get("expires_in")).longValue()));
    assertEquals(d.get("expected_body"), new String(r.body(), StandardCharsets.UTF_8));
    ((Map<String, String>) d.get("expected_headers")).forEach((k, v) -> assertEquals(v, r.headers().get(k), k));
    for (Map<String, Object> c : (List<Map<String, Object>>) ((Map<String, Object>) DOC.get("directory")).get("verify")) {
      Map<String, List<String>> headers = new LinkedHashMap<>();
      ((Map<String, String>) c.get("headers")).forEach((k, v) -> headers.put(k, List.of(v)));
      MesshVerifier.DirectoryCheck check = MesshVerifier.verifyDirectory((String) c.get("url"), headers,
          ((String) c.get("body")).getBytes(StandardCharsets.UTF_8), ((Number) c.get("now")).longValue());
      assertEquals(new TreeSet<>((List<String>) c.get("expect_signed")), new TreeSet<>(check.signed()), (String) c.get("name"));
    }
  }
}
