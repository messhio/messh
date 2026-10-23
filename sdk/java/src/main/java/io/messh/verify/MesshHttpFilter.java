package io.messh.verify;

import com.sun.net.httpserver.Filter;
import com.sun.net.httpserver.HttpExchange;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;

/**
 * Filter for the JDK's built-in {@code com.sun.net.httpserver.HttpServer}.
 * Verified callers are in {@code exchange.getAttribute(MesshHttpFilter.AGENT)}.
 *
 * <pre>{@code
 * server.createContext("/api", handler).getFilters().add(new MesshHttpFilter(verifier));
 * }</pre>
 *
 * For Servlet containers, call {@link MesshVerifier#verify} the same way from a jakarta.servlet.Filter.
 */
public final class MesshHttpFilter extends Filter {
  public static final String AGENT = "messh.agent";
  private final MesshVerifier verifier;

  public MesshHttpFilter(MesshVerifier verifier) {
    this.verifier = verifier;
  }

  @Override
  public void doFilter(HttpExchange ex, Chain chain) throws IOException {
    long max = verifier.maxBodyBytes();
    byte[] body = ex.getRequestBody().readNBytes((int) Math.min(max + 1, Integer.MAX_VALUE - 8));
    if (body.length > max) {
      reject(ex, new VerifyException("body_too_large", "the request body is over this API's limit of " + max + " bytes"));
      return;
    }
    String host = ex.getRequestHeaders().getFirst("Host");
    String scheme = ex.getHttpContext().getServer() instanceof com.sun.net.httpserver.HttpsServer ? "https" : "http";
    URI uri = URI.create(scheme + "://" + (host != null ? host : "localhost") + ex.getRequestURI().getRawPath()
        + (ex.getRequestURI().getRawQuery() != null ? "?" + ex.getRequestURI().getRawQuery() : ""));
    try {
      ex.setAttribute(AGENT, verifier.verify(ex.getRequestMethod(), uri, ex.getRequestHeaders(), body));
    } catch (VerifyException e) {
      reject(ex, e);
      return;
    }
    ex.setStreams(new ByteArrayInputStream(body), null);
    chain.doFilter(ex);
  }

  private static void reject(HttpExchange ex, VerifyException e) throws IOException {
    byte[] out = e.toJson().getBytes(StandardCharsets.UTF_8);
    ex.getResponseHeaders().set("Content-Type", "application/json");
    if (e.status() == 401) ex.getResponseHeaders().set("Accept-Signature", MesshVerifier.ACCEPT_SIGNATURE);
    ex.sendResponseHeaders(e.status(), out.length);
    try (OutputStream os = ex.getResponseBody()) {
      os.write(out);
    }
  }

  @Override
  public String description() {
    return "messh Web Bot Auth verification";
  }
}
