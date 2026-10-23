package io.messh;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON reader/writer (the JDK has none), enough for key
 * directories and test vectors. Objects become LinkedHashMap, arrays
 * ArrayList, numbers Long or Double. Internal API.
 */
public final class Json {
  private final String s;
  private int i;

  private Json(String s) {
    this.s = s;
  }

  public static Object parse(String text) {
    Json p = new Json(text);
    p.ws();
    Object v = p.value();
    p.ws();
    if (p.i != p.s.length()) throw p.err("trailing data");
    return v;
  }

  /** JSON string literal, matching Go's strconv.Quote for ASCII. */
  public static String quote(String v) {
    StringBuilder b = new StringBuilder("\"");
    for (char c : v.toCharArray()) {
      switch (c) {
        case '"' -> b.append("\\\"");
        case '\\' -> b.append("\\\\");
        case '\n' -> b.append("\\n");
        case '\r' -> b.append("\\r");
        case '\t' -> b.append("\\t");
        default -> {
          if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
          else b.append(c);
        }
      }
    }
    return b.append('"').toString();
  }

  private IllegalArgumentException err(String m) {
    return new IllegalArgumentException("JSON: " + m + " at " + i);
  }

  private void ws() {
    while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
  }

  private char peek() {
    if (i >= s.length()) throw err("unexpected end");
    return s.charAt(i);
  }

  private Object value() {
    char c = peek();
    switch (c) {
      case '{': return object();
      case '[': return array();
      case '"': return string();
      case 't': return lit("true", Boolean.TRUE);
      case 'f': return lit("false", Boolean.FALSE);
      case 'n': return lit("null", null);
      default: return number();
    }
  }

  private Object lit(String word, Object v) {
    if (!s.startsWith(word, i)) throw err("bad literal");
    i += word.length();
    return v;
  }

  private Map<String, Object> object() {
    Map<String, Object> m = new LinkedHashMap<>();
    i++;
    ws();
    if (peek() == '}') { i++; return m; }
    while (true) {
      ws();
      String k = string();
      ws();
      if (peek() != ':') throw err("expected :");
      i++;
      ws();
      m.put(k, value());
      ws();
      char c = peek();
      i++;
      if (c == '}') return m;
      if (c != ',') throw err("expected , or }");
    }
  }

  private List<Object> array() {
    List<Object> a = new ArrayList<>();
    i++;
    ws();
    if (peek() == ']') { i++; return a; }
    while (true) {
      ws();
      a.add(value());
      ws();
      char c = peek();
      i++;
      if (c == ']') return a;
      if (c != ',') throw err("expected , or ]");
    }
  }

  private String string() {
    if (peek() != '"') throw err("expected string");
    i++;
    StringBuilder b = new StringBuilder();
    while (true) {
      char c = peek();
      i++;
      if (c == '"') return b.toString();
      if (c != '\\') { b.append(c); continue; }
      char e = peek();
      i++;
      switch (e) {
        case '"', '\\', '/' -> b.append(e);
        case 'b' -> b.append('\b');
        case 'f' -> b.append('\f');
        case 'n' -> b.append('\n');
        case 'r' -> b.append('\r');
        case 't' -> b.append('\t');
        case 'u' -> {
          if (i + 4 > s.length()) throw err("bad \\u escape");
          b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
          i += 4;
        }
        default -> throw err("bad escape");
      }
    }
  }

  private Object number() {
    int start = i;
    while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
    String n = s.substring(start, i);
    if (n.isEmpty()) throw err("unexpected character");
    return n.contains(".") || n.contains("e") || n.contains("E") ? (Object) Double.parseDouble(n) : (Object) Long.parseLong(n);
  }
}
