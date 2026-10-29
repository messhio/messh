"""HTTP Structured Field Values (RFC 8941): Signature-Input, Signature,
Signature-Agent, component identifiers, and fields covered with sf or key."""

from __future__ import annotations

import base64
import re
from typing import List, Optional, Tuple, Union

# A bare item is (kind, value): ("int", n), ("dec", thousandths), ("str", s),
# ("tok", s), ("bin", bytes) or ("bool", b). Decimals are held in thousandths,
# so serializing them never depends on floating point.
Bare = Tuple[str, object]
Params = List[Tuple[str, Bare]]
TRUE: Bare = ("bool", True)


class Item:
    __slots__ = ("bare", "params")

    def __init__(self, bare: Bare, params: Params):
        self.bare, self.params = bare, params


class InnerList:
    __slots__ = ("items", "params")

    def __init__(self, items: List[Item], params: Params):
        self.items, self.params = items, params


Member = Union[Item, InnerList]
Dictionary = List[Tuple[str, Member]]  # keys are unique; a repeated key keeps its first position and its last value


def param(ps: Params, key: str) -> Optional[Bare]:
    for k, v in ps:
        if k == key:
            return v
    return None


def member(d: Dictionary, key: str) -> Optional[Member]:
    for k, m in d:
        if k == key:
            return m
    return None


def _set(pairs: list, key: str, value) -> bool:
    """Set key in an ordered pair list; True if it was already there."""
    for i, (k, _) in enumerate(pairs):
        if k == key:
            pairs[i] = (key, value)
            return True
    pairs.append((key, value))
    return False


# --- parsing (RFC 8941 §4.2) ---

class SFError(ValueError):
    pass


_TCHAR = set("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_KEYCHAR = set("abcdefghijklmnopqrstuvwxyz0123456789_-.*")


class _Parser:
    def __init__(self, s: str):
        if any(ord(c) > 0x7F for c in s):
            raise SFError("structured field is not ASCII")
        self.s, self.i = s, 0
        self.skip(" ")

    def eof(self) -> bool:
        return self.i >= len(self.s)

    def peek(self) -> str:
        return self.s[self.i]

    def skip(self, chars: str) -> None:
        while not self.eof() and self.peek() in chars:
            self.i += 1

    def end(self) -> None:
        self.skip(" ")
        if not self.eof():
            raise SFError("unexpected %r at %d" % (self.peek(), self.i))

    def next(self) -> bool:
        """Move past the comma between members; True at the end."""
        self.skip(" \t")
        if self.eof():
            return True
        if self.peek() != ",":
            raise SFError("expected a comma at %d" % self.i)
        self.i += 1
        self.skip(" \t")
        if self.eof():
            raise SFError("trailing comma")
        return False

    def member(self) -> Member:
        if not self.eof() and self.peek() == "(":
            return self.inner_list()
        return self.item()

    def inner_list(self) -> InnerList:
        self.i += 1
        items: List[Item] = []
        while not self.eof():
            self.skip(" ")
            if self.eof():
                break
            if self.peek() == ")":
                self.i += 1
                return InnerList(items, self.params())
            items.append(self.item())
            if not self.eof() and self.peek() not in " )":
                raise SFError("expected a space or ) at %d" % self.i)
        raise SFError("unterminated inner list")

    def item(self) -> Item:
        bare = self.bare()
        return Item(bare, self.params())

    def params(self) -> Params:
        ps: Params = []
        while not self.eof() and self.peek() == ";":
            self.i += 1
            self.skip(" ")
            key = self.key()
            value = TRUE
            if not self.eof() and self.peek() == "=":
                self.i += 1
                value = self.bare()
            _set(ps, key, value)
        return ps

    def key(self) -> str:
        if self.eof() or not ("a" <= self.peek() <= "z" or self.peek() == "*"):
            raise SFError("expected a key at %d" % self.i)
        start = self.i
        while not self.eof() and self.peek() in _KEYCHAR:
            self.i += 1
        return self.s[start:self.i]

    def bare(self) -> Bare:
        if self.eof():
            raise SFError("expected an item")
        c = self.peek()
        if c == "-" or c.isdigit():
            return self.number()
        if c == '"':
            return self.string()
        if c == "*" or c.isalpha():
            return self.token()
        if c == ":":
            return self.bytes()
        if c == "?":
            b = self.s[self.i + 1:self.i + 2]
            if b in ("0", "1"):
                self.i += 2
                return ("bool", b == "1")
            raise SFError("bad boolean at %d" % self.i)
        raise SFError("unexpected %r at %d" % (c, self.i))

    def number(self) -> Bare:
        neg = self.peek() == "-"
        if neg:
            self.i += 1
        if self.eof() or not self.peek().isdigit():
            raise SFError("expected a digit at %d" % self.i)
        start, dot = self.i, -1
        while not self.eof():
            c = self.peek()
            if c.isdigit():
                self.i += 1
            elif c == "." and dot < 0:
                if self.i - start > 12:
                    raise SFError("decimal has too many integer digits")
                dot = self.i
                self.i += 1
            else:
                break
            if dot < 0 and self.i - start > 15:
                raise SFError("integer has too many digits")
            if dot >= 0 and self.i - start > 16:
                raise SFError("decimal has too many digits")
        num = self.s[start:self.i]
        sign = -1 if neg else 1
        if dot < 0:
            return ("int", sign * int(num))
        whole, frac = num[:dot - start], num[dot - start + 1:]
        if not frac or len(frac) > 3:
            raise SFError("decimal needs 1 to 3 fractional digits")
        return ("dec", sign * (int(whole) * 1000 + int((frac + "00")[:3])))

    def string(self) -> Bare:
        self.i += 1
        out = []
        while not self.eof():
            c = self.s[self.i]
            self.i += 1
            if c == "\\":
                if self.eof() or self.peek() not in '"\\':
                    raise SFError("bad escape in string")
                out.append(self.peek())
                self.i += 1
            elif c == '"':
                return ("str", "".join(out))
            elif c < " " or c == "\x7f":
                raise SFError("control character in string")
            else:
                out.append(c)
        raise SFError("unterminated string")

    def token(self) -> Bare:
        start = self.i
        self.i += 1
        while not self.eof() and (self.peek() in _TCHAR or self.peek() in ":/"):
            self.i += 1
        return ("tok", self.s[start:self.i])

    def bytes(self) -> Bare:
        self.i += 1
        end = self.s.find(":", self.i)
        if end < 0:
            raise SFError("unterminated byte sequence")
        content = self.s[self.i:end]
        self.i = end + 1
        if not re.fullmatch(r"[A-Za-z0-9+/=]*", content):
            raise SFError("bad base64 in byte sequence")
        data = content.rstrip("=")
        try:
            return ("bin", base64.b64decode(data + "=" * (-len(data) % 4), validate=True))
        except ValueError:
            raise SFError("bad base64 in byte sequence") from None


def parse_item(s: str) -> Item:
    p = _Parser(s)
    it = p.item()
    p.end()
    return it


def parse_list(s: str) -> List[Member]:
    p = _Parser(s)
    out: List[Member] = []
    while not p.eof():
        out.append(p.member())
        if p.next():
            break
    return out


def parse_dictionary(s: str) -> Tuple[Dictionary, List[str]]:
    """Parse a dictionary; also return the keys that occurred more than once."""
    p = _Parser(s)
    d: Dictionary = []
    duplicates: List[str] = []
    while not p.eof():
        key = p.key()
        if not p.eof() and p.peek() == "=":
            p.i += 1
            m = p.member()
        else:
            m = Item(TRUE, p.params())
        if _set(d, key, m):
            duplicates.append(key)
        if p.next():
            break
    return d, duplicates


# --- serializing (RFC 8941 §4.1) ---

def valid_key(s: str) -> bool:
    return re.fullmatch(r"[a-z*][a-z0-9_\-.*]*", s) is not None


def valid_string(s: str) -> bool:
    return re.fullmatch(r"[\x20-\x7e]*", s) is not None


def serialize_bare(b: Bare) -> str:
    kind, v = b
    if kind == "int":
        return str(v)
    if kind == "dec":
        n = abs(v)
        frac = ("%03d" % (n % 1000)).rstrip("0") or "0"
        return "%s%d.%s" % ("-" if v < 0 else "", n // 1000, frac)
    if kind == "str":
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if kind == "tok":
        return v
    if kind == "bin":
        return ":" + base64.b64encode(v).decode() + ":"
    return "?1" if v else "?0"


def serialize_params(ps: Params) -> str:
    return "".join(";" + k if v == TRUE else ";%s=%s" % (k, serialize_bare(v)) for k, v in ps)


def serialize_item(it: Item) -> str:
    return serialize_bare(it.bare) + serialize_params(it.params)


def serialize_member(m: Member) -> str:
    if isinstance(m, InnerList):
        return "(" + " ".join(serialize_item(i) for i in m.items) + ")" + serialize_params(m.params)
    return serialize_item(m)


def serialize_list(ms: List[Member]) -> str:
    return ", ".join(serialize_member(m) for m in ms)


def serialize_dictionary(d: Dictionary) -> str:
    return ", ".join(k + serialize_params(m.params) if isinstance(m, Item) and m.bare == TRUE else "%s=%s" % (k, serialize_member(m))
                     for k, m in d)
