package io.messh.examples;

import io.messh.KeySource;
import io.messh.MesshClient;
import io.messh.verify.Agent;
import io.messh.verify.MesshVerifier;
import io.messh.verify.VerifyException;
import java.net.URI;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Live check against the running stack (run with the test classpath). */
public final class Interop {
  private Interop() {}

  static void check(boolean ok, String step, Object detail) {
    System.out.println((ok ? "PASS" : "FAIL") + " java " + step + (ok ? "" : ": " + detail));
    if (!ok) System.exit(1);
  }

  static Map<String, List<String>> asHeaders(Map<String, String> m) {
    Map<String, List<String>> h = new LinkedHashMap<>();
    m.forEach((k, v) -> h.put(k, List.of(v)));
    return h;
  }

  public static void main(String[] args) throws Exception {
    String app = System.getenv("APP"), registry = System.getenv("REGISTRY");
    MesshClient client = MesshClient.builder("mukul").key(KeySource.file(Path.of(System.getenv("KEY")))).registry(registry).build();

    HttpResponse<String> r = client.send("GET", URI.create(app + "/api/hello"), null, HttpResponse.BodyHandlers.ofString());
    check(r.statusCode() == 200 && r.body().contains("\"key\":\"sdk-test\""), "GET /api/hello → 200 mukul · sdk-test", r.body());
    r = client.send("POST", URI.create(app + "/api/deploy"), "{\"env\":\"staging\"}".getBytes(StandardCharsets.UTF_8), HttpResponse.BodyHandlers.ofString());
    check(r.statusCode() == 200 && r.body().contains("\"method\":\"POST\""), "POST /api/deploy with body → 200", r.body());

    URI uri = URI.create("http://api.example/orders?id=7");
    byte[] body = "{\"qty\":1}".getBytes(StandardCharsets.UTF_8);
    Agent a = MesshVerifier.builder().trust("mukul").registry(registry, null).build().verify("POST", uri, asHeaders(client.sign("POST", uri, body)), body);
    check(a.identity().equals("mukul") && a.keyName().equals("sdk-test"), "verifier with live messh directory → mukul · sdk-test", a);
    try {
      URI x = URI.create("http://api.example/x");
      MesshVerifier.builder().trust("alice").registry(registry, null).build().verify("GET", x, asHeaders(client.sign("GET", x, null)), null);
      check(false, "identity outside trust list → 403 untrusted", "accepted");
    } catch (VerifyException e) {
      check(e.code().equals("untrusted") && e.status() == 403, "identity outside trust list → 403 untrusted", e);
    }
  }
}
