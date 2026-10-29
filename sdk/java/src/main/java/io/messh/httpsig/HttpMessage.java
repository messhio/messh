package io.messh.httpsig;

import java.util.List;
import java.util.Map;

/**
 * What a signature covers: a request, or a response ({@code status} &gt; 0) with
 * the request it answers. Header names are case-insensitive; each list keeps a
 * field's lines in order.
 *
 * @param method request method, exactly as sent
 * @param url absolute target URI of a request; a Host header, if any, is the authority
 * @param headers header fields
 * @param body checked against a covered Content-Digest; null skips the check
 * @param status response status code; 0 for a request
 * @param request for a response: the request it answers, for components with req
 * @param trailers trailer fields, for components with tr
 * @param requestTarget the request line's target, if known; else path and query
 */
public record HttpMessage(
    String method,
    String url,
    Map<String, List<String>> headers,
    byte[] body,
    int status,
    HttpMessage request,
    Map<String, List<String>> trailers,
    String requestTarget) {

  /** A request to an absolute URL. body may be null. */
  public static HttpMessage request(String method, String url, Map<String, List<String>> headers, byte[] body) {
    return new HttpMessage(method, url, headers, body, 0, null, Map.of(), "");
  }

  /** A response to request. body may be null. */
  public static HttpMessage response(int status, Map<String, List<String>> headers, byte[] body, HttpMessage request) {
    return new HttpMessage("", "", headers, body, status, request, Map.of(), "");
  }

  /** This message with trailer fields. */
  public HttpMessage withTrailers(Map<String, List<String>> t) {
    return new HttpMessage(method, url, headers, body, status, request, t, requestTarget);
  }

  /** This message with the request line's target, e.g. "*" for OPTIONS *. */
  public HttpMessage withRequestTarget(String target) {
    return new HttpMessage(method, url, headers, body, status, request, trailers, target);
  }

  /** This message with a (different) body. */
  public HttpMessage withBody(byte[] b) {
    return new HttpMessage(method, url, headers, b, status, request, trailers, requestTarget);
  }

  /** This message, a response, with the request URL too (for directories signed over a plain "@authority"). */
  public HttpMessage withUrl(String u) {
    return new HttpMessage(method, u, headers, body, status, request, trailers, requestTarget);
  }
}
