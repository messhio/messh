package io.messh.httpsig;

import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * HTTP Structured Field Values (RFC 8941): Signature-Input, Signature,
 * Signature-Agent, component identifiers, and fields covered with sf or key.
 * Maps keep insertion order, so a repeated key keeps its first position and
 * its last value, as RFC 8941 says.
 */
final class Sf {
  private Sf() {}

  /** A bare item. A decimal is held in thousandths, so serializing it never depends on floating point. */
  sealed interface Bare permits Int, Dec, Str, Tok, Bin, Bool {}

  record Int(long v) implements Bare {}

  record Dec(long v) implements Bare {}

  record Str(String v) implements Bare {}

  record Tok(String v) implements Bare {}

  record Bin(byte[] v) implements Bare {}

  record Bool(boolean v) implements Bare {}

  static final Bool TRUE = new Bool(true);

  record Item(Bare bare, Map<String, Bare> params) {}

  /** A list or dictionary member: an item (items == null), or an inner list. */
  record Member(Bare bare, List<Item> items, Map<String, Bare> params) {
    boolean inner() {
      return items != null;
    }
  }

  /** A parsed dictionary and the keys that occurred more than once. */
  record Dict(Map<String, Member> members, List<String> duplicates) {}

  // --- parsing (RFC 8941 §4.2) ---

  private static final String TCHAR = "!#$%&'*+-.^_`|~";

  private static final class Parser {
    final String s;
    int i;

    Parser(String s) {
      for (int k = 0; k < s.length(); k++) {
        if (s.charAt(k) > 0x7f) throw new IllegalArgumentException("structured field is not ASCII");
      }
      this.s = s;
      skip(" ");
    }

    boolean eof() {
      return i >= s.length();
    }

    char peek() {
      return s.charAt(i);
    }

    void skip(String chars) {
      while (!eof() && chars.indexOf(peek()) >= 0) i++;
    }

    void end() {
      skip(" ");
      if (!eof()) throw new IllegalArgumentException("unexpected '" + peek() + "' at " + i);
    }

    /** Moves past the comma between members; true at the end. */
    boolean next() {
      skip(" \t");
      if (eof()) return true;
      if (peek() != ',') throw new IllegalArgumentException("expected a comma at " + i);
      i++;
      skip(" \t");
      if (eof()) throw new IllegalArgumentException("trailing comma");
      return false;
    }

    Member member() {
      if (!eof() && peek() == '(') return innerList();
      Item it = item();
      return new Member(it.bare(), null, it.params());
    }

    Member innerList() {
      i++;
      List<Item> items = new ArrayList<>();
      while (!eof()) {
        skip(" ");
        if (eof()) break;
        if (peek() == ')') {
          i++;
          return new Member(null, items, params());
        }
        items.add(item());
        if (!eof() && peek() != ' ' && peek() != ')') throw new IllegalArgumentException("expected a space or ) at " + i);
      }
      throw new IllegalArgumentException("unterminated inner list");
    }

    Item item() {
      Bare b = bare();
      return new Item(b, params());
    }

    Map<String, Bare> params() {
      Map<String, Bare> ps = new LinkedHashMap<>();
      while (!eof() && peek() == ';') {
        i++;
        skip(" ");
        String key = key();
        Bare v = TRUE;
        if (!eof() && peek() == '=') {
          i++;
          v = bare();
        }
        ps.put(key, v);
      }
      return ps;
    }

    String key() {
      if (eof() || !((peek() >= 'a' && peek() <= 'z') || peek() == '*')) throw new IllegalArgumentException("expected a key at " + i);
      int start = i;
      while (!eof() && ((peek() >= 'a' && peek() <= 'z') || (peek() >= '0' && peek() <= '9') || "_-.*".indexOf(peek()) >= 0)) i++;
      return s.substring(start, i);
    }

    Bare bare() {
      if (eof()) throw new IllegalArgumentException("expected an item");
      char c = peek();
      if (c == '-' || (c >= '0' && c <= '9')) return number();
      if (c == '"') return string();
      if (c == '*' || Character.isLetter(c)) return token();
      if (c == ':') return bytes();
      if (c == '?') {
        if (i + 1 < s.length() && (s.charAt(i + 1) == '0' || s.charAt(i + 1) == '1')) {
          i += 2;
          return new Bool(s.charAt(i - 1) == '1');
        }
        throw new IllegalArgumentException("bad boolean at " + i);
      }
      throw new IllegalArgumentException("unexpected '" + c + "' at " + i);
    }

    Bare number() {
      boolean neg = peek() == '-';
      if (neg) i++;
      if (eof() || !(peek() >= '0' && peek() <= '9')) throw new IllegalArgumentException("expected a digit at " + i);
      int start = i, dot = -1;
      while (!eof()) {
        char c = peek();
        if (c >= '0' && c <= '9') {
          i++;
        } else if (c == '.' && dot < 0) {
          if (i - start > 12) throw new IllegalArgumentException("decimal has too many integer digits");
          dot = i++;
        } else {
          break;
        }
        if (dot < 0 && i - start > 15) throw new IllegalArgumentException("integer has too many digits");
        if (dot >= 0 && i - start > 16) throw new IllegalArgumentException("decimal has too many digits");
      }
      String num = s.substring(start, i);
      long sign = neg ? -1 : 1;
      if (dot < 0) return new Int(sign * Long.parseLong(num));
      String whole = num.substring(0, dot - start), frac = num.substring(dot - start + 1);
      if (frac.isEmpty() || frac.length() > 3) throw new IllegalArgumentException("decimal needs 1 to 3 fractional digits");
      return new Dec(sign * (Long.parseLong(whole) * 1000 + Long.parseLong((frac + "00").substring(0, 3))));
    }

    Bare string() {
      i++;
      StringBuilder out = new StringBuilder();
      while (!eof()) {
        char c = s.charAt(i++);
        if (c == '\\') {
          if (eof() || (peek() != '"' && peek() != '\\')) throw new IllegalArgumentException("bad escape in string");
          out.append(s.charAt(i++));
        } else if (c == '"') {
          return new Str(out.toString());
        } else if (c < 0x20 || c == 0x7f) {
          throw new IllegalArgumentException("control character in string");
        } else {
          out.append(c);
        }
      }
      throw new IllegalArgumentException("unterminated string");
    }

    Bare token() {
      int start = i++;
      while (!eof() && (Character.isLetterOrDigit(peek()) || TCHAR.indexOf(peek()) >= 0 || peek() == ':' || peek() == '/')) i++;
      return new Tok(s.substring(start, i));
    }

    Bare bytes() {
      i++;
      int end = s.indexOf(':', i);
      if (end < 0) throw new IllegalArgumentException("unterminated byte sequence");
      String content = s.substring(i, end);
      i = end + 1;
      if (!content.matches("[A-Za-z0-9+/=]*")) throw new IllegalArgumentException("bad base64 in byte sequence");
      try {
        return new Bin(Base64.getDecoder().decode(content.replaceAll("=+$", "")));
      } catch (IllegalArgumentException e) {
        throw new IllegalArgumentException("bad base64 in byte sequence");
      }
    }
  }

  static Item parseItem(String s) {
    Parser p = new Parser(s);
    Item it = p.item();
    p.end();
    return it;
  }

  static List<Member> parseList(String s) {
    Parser p = new Parser(s);
    List<Member> out = new ArrayList<>();
    while (!p.eof()) {
      out.add(p.member());
      if (p.next()) break;
    }
    return out;
  }

  static Dict parseDictionary(String s) {
    Parser p = new Parser(s);
    Map<String, Member> d = new LinkedHashMap<>();
    List<String> dups = new ArrayList<>();
    while (!p.eof()) {
      String key = p.key();
      Member m;
      if (!p.eof() && p.peek() == '=') {
        p.i++;
        m = p.member();
      } else {
        m = new Member(TRUE, null, p.params());
      }
      if (d.put(key, m) != null) dups.add(key);
      if (p.next()) break;
    }
    return new Dict(d, dups);
  }

  // --- serializing (RFC 8941 §4.1) ---

  static boolean validKey(String s) {
    return s.matches("[a-z*][a-z0-9_\\-.*]*");
  }

  static boolean validString(String s) {
    return s.chars().allMatch(c -> c >= 0x20 && c <= 0x7e);
  }

  static String ser(Bare b) {
    if (b instanceof Int n) return Long.toString(n.v());
    if (b instanceof Dec d) {
      long a = Math.abs(d.v());
      String frac = String.format("%03d", a % 1000).replaceAll("0+$", "");
      return (d.v() < 0 ? "-" : "") + (a / 1000) + "." + (frac.isEmpty() ? "0" : frac);
    }
    if (b instanceof Str str) return "\"" + str.v().replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    if (b instanceof Tok t) return t.v();
    if (b instanceof Bin bin) return ":" + Base64.getEncoder().encodeToString(bin.v()) + ":";
    return ((Bool) b).v() ? "?1" : "?0";
  }

  static String ser(Map<String, Bare> params) {
    StringBuilder sb = new StringBuilder();
    params.forEach((k, v) -> sb.append(';').append(k).append(v.equals(TRUE) ? "" : "=" + ser(v)));
    return sb.toString();
  }

  static String ser(Item it) {
    return ser(it.bare()) + ser(it.params());
  }

  static String ser(Member m) {
    if (!m.inner()) return ser(m.bare()) + ser(m.params());
    List<String> parts = new ArrayList<>();
    for (Item it : m.items()) parts.add(ser(it));
    return "(" + String.join(" ", parts) + ")" + ser(m.params());
  }

  static String serList(List<Member> l) {
    List<String> parts = new ArrayList<>();
    for (Member m : l) parts.add(ser(m));
    return String.join(", ", parts);
  }

  static String serDict(Map<String, Member> d) {
    List<String> parts = new ArrayList<>();
    d.forEach((k, m) -> parts.add(!m.inner() && TRUE.equals(m.bare()) ? k + ser(m.params()) : k + "=" + ser(m)));
    return String.join(", ", parts);
  }
}
