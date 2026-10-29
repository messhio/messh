package io.messh.httpsig;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.messh.Json;
import io.messh.Signer;
import io.messh.verify.VerifyException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

@SuppressWarnings("unchecked")
class HttpSigVectorsTest {
  static final Map<String, Object> DOC = load();

  static Map<String, Object> load() {
    try {
      return (Map<String, Object>) Json.parse(Files.readString(Path.of("../../spec/vectors/http-message-signatures.json")));
    } catch (java.io.IOException e) {
      throw new RuntimeException(e);
    }
  }

  static Map<String, List<String>> fields(Object pairs) {
    Map<String, List<String>> h = new LinkedHashMap<>();
    if (pairs instanceof List<?> l) {
      for (Object p : l) {
        List<String> kv = (List<String>) p;
        h.computeIfAbsent(kv.get(0), k -> new ArrayList<>()).add(kv.get(1));
      }
    }
    return h;
  }

  static HttpMessage message(Map<String, Object> m) {
    byte[] body = m.get("body") instanceof String b ? b.getBytes(StandardCharsets.UTF_8) : null;
    HttpMessage req = m.get("request") instanceof Map<?, ?> r ? message((Map<String, Object>) r) : null;
    int status = m.get("status") instanceof Number n ? n.intValue() : 0;
    return new HttpMessage((String) m.getOrDefault("method", ""), (String) m.getOrDefault("url", ""), fields(m.get("headers")), body, status, req,
        fields(m.get("trailers")), (String) m.getOrDefault("request_target", ""));
  }

  static Map<String, Object> key(String name) {
    return (Map<String, Object>) ((Map<String, Object>) DOC.get("keys")).get(name);
  }

  static byte[] pub(String name) {
    return Base64.getUrlDecoder().decode((String) key(name).get("x"));
  }

  /** Signs with a raw seed through the JDK. */
  static Signer signer(String name) {
    byte[] seed = HexFormat.of().parseHex((String) key(name).get("seed_hex"));
    byte[] der = HexFormat.of().parseHex("302e020100300506032b657004220420" + HexFormat.of().formatHex(seed));
    return new Signer() {
      public byte[] publicKey() {
        return pub(name);
      }

      public byte[] sign(byte[] message) {
        try {
          Signature s = Signature.getInstance("Ed25519");
          s.initSign(KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der)));
          s.update(message);
          return s.sign();
        } catch (java.security.GeneralSecurityException e) {
          throw new IllegalStateException(e);
        }
      }
    };
  }

  static Map<String, String> types() {
    return (Map<String, String>) (Map<?, ?>) DOC.get("field_types");
  }

  @Test
  void structuredFields() {
    for (Map<String, Object> c : (List<Map<String, Object>>) DOC.get("structured_fields")) {
      String input = (String) c.get("input");
      java.util.function.Supplier<String> run = switch ((String) c.get("type")) {
        case "dictionary" -> () -> Sf.serDict(Sf.parseDictionary(input).members());
        case "list" -> () -> Sf.serList(Sf.parseList(input));
        default -> () -> Sf.ser(Sf.parseItem(input));
      };
      if (Boolean.TRUE.equals(c.get("error"))) assertThrows(IllegalArgumentException.class, run::get, (String) c.get("name"));
      else assertEquals(c.get("canonical"), run.get(), (String) c.get("name"));
    }
  }

  @Test
  void components() {
    Map<String, Object> messages = (Map<String, Object>) DOC.get("messages");
    for (Map<String, Object> c : (List<Map<String, Object>>) DOC.get("components")) {
      HttpMessage m = message((Map<String, Object>) messages.get(c.get("message")));
      if (Boolean.TRUE.equals(c.get("error"))) {
        assertThrows(IllegalArgumentException.class, () -> HttpSig.componentValue(m, (String) c.get("component"), types()), (String) c.get("name"));
      } else {
        assertArrayEquals(new String[] {(String) c.get("identifier"), (String) c.get("value")},
            HttpSig.componentValue(m, (String) c.get("component"), types()), (String) c.get("name"));
      }
    }
  }

  @Test
  void sign() {
    for (Map<String, Object> c : (List<Map<String, Object>>) DOC.get("sign")) {
      Map<String, Object> p = (Map<String, Object>) c.get("params");
      HttpSig.SignOptions o = HttpSig.SignOptions.of().components((List<String>) c.get("components")).label((String) c.get("label"))
          .fieldTypes(types());
      if (p.get("created") instanceof Number n) o.created(n.longValue());
      if (p.get("expires") instanceof Number n) o.expires(n.longValue());
      o.keyid((String) p.get("keyid")).alg((String) p.get("alg")).nonce((String) p.get("nonce")).tag((String) p.get("tag"));
      HttpSig.Signed s = HttpSig.sign(message((Map<String, Object>) c.get("message")), signer((String) c.get("key")), o);
      assertEquals(c.get("expected_base"), s.base(), (String) c.get("name"));
      Map<String, String> want = (Map<String, String>) c.get("expected_headers");
      assertEquals(want.get("Signature-Input"), s.headers().get("Signature-Input"), (String) c.get("name"));
      assertEquals(want.get("Signature"), s.headers().get("Signature"), (String) c.get("name"));
    }
  }

  @Test
  void verify() {
    for (Map<String, Object> c : (List<Map<String, Object>>) DOC.get("verify")) {
      Map<String, String> keys = (Map<String, String>) c.get("keys");
      HttpSig.VerifyOptions o = HttpSig.VerifyOptions.keys(kid -> keys.containsKey(kid) ? pub(keys.get(kid)) : null)
          .label((String) c.get("label")).tag((String) c.get("tag")).now(((Number) c.get("now")).longValue()).fieldTypes(types());
      if (c.get("max_age") instanceof Number n) o.maxAge(Duration.ofSeconds(n.longValue()));
      String got;
      HttpSig.Verified v = null;
      try {
        v = HttpSig.verify(message((Map<String, Object>) c.get("message")), o);
        got = "ok";
      } catch (VerifyException e) {
        got = e.code();
      }
      assertEquals(c.get("expect"), got, (String) c.get("name"));
      if (v != null) assertEquals(c.get("expect_label"), v.label(), (String) c.get("name"));
    }
  }
}
