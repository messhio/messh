package io.messh;

import io.messh.httpsig.HttpMessage;
import io.messh.httpsig.HttpSig;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Key directories you host yourself (draft-meunier-http-message-signatures-directory). */
public final class Directories {
  /** Tags the signatures on a key directory response. */
  public static final String TAG = "http-message-signatures-directory";

  private Directories() {}

  /**
   * A key directory to serve, and the headers that sign it.
   *
   * @param body the JWKS to serve
   * @param headers Content-Type, Content-Digest, Signature-Input and Signature
   */
  public record Response(byte[] body, Map<String, String> headers) {}

  /**
   * A key directory for keys, to serve yourself at
   * https://&lt;authority&gt;/.well-known/http-message-signatures-directory, and the headers that sign
   * it: Content-Digest, and one signature per key binding the directory to authority (§5), the form
   * Cloudflare's tools check. Build it again before it expires. created is seconds since epoch.
   */
  public static Response response(String authority, List<KeySource> keys, long created, Duration ttl) {
    List<Signer> signers = new ArrayList<>();
    List<String> jwks = new ArrayList<>();
    for (KeySource k : keys) {
      Signer s = k.load();
      signers.add(s);
      byte[] p = s.publicKey();
      jwks.add("{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" + Base64.getUrlEncoder().withoutPadding().encodeToString(p)
          + "\",\"kid\":\"" + Wba.thumbprint(p) + "\"}");
    }
    byte[] body = ("{\"keys\":[" + String.join(",", jwks) + "]}").getBytes(StandardCharsets.UTF_8);
    Map<String, String> headers = new LinkedHashMap<>();
    headers.put("Content-Type", "application/http-message-signatures-directory+json");
    headers.put("Content-Digest", Wba.contentDigest(body));
    HttpMessage resp = HttpMessage.response(200, Map.of("content-digest", List.of(headers.get("Content-Digest"))), null,
        HttpMessage.request("GET", "https://" + authority + Wba.DIRECTORY_PATH, Map.of(), null));
    List<String> inputs = new ArrayList<>(), sigs = new ArrayList<>();
    for (int i = 0; i < signers.size(); i++) {
      Signer s = signers.get(i);
      HttpSig.Signed signed = HttpSig.sign(resp, s, HttpSig.SignOptions.of("\"@authority\";req", "content-digest").label("binding" + i)
          .created(created).expires(created + ttl.getSeconds()).keyid(Wba.thumbprint(s.publicKey())).alg("ed25519").tag(TAG));
      inputs.add(signed.headers().get("Signature-Input"));
      sigs.add(signed.headers().get("Signature"));
    }
    headers.put("Signature-Input", String.join(", ", inputs));
    headers.put("Signature", String.join(", ", sigs));
    return new Response(body, headers);
  }
}
