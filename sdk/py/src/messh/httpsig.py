"""HTTP message signatures (RFC 9421) with Ed25519 for any request or response:
any label, tag and key ID, every derived component, and every field parameter
(sf, key, bs, req, tr).

    from messh.httpsig import Message, sign_message, verify_message
    m = Message("POST", "https://example.com/foo", headers=[("Content-Type", "application/json")], body=b"{}")
    s = sign_message(m, signer, components=["@method", "@authority", "content-type"], keyid="k1")
    verify_message(m_with_s_headers, keys={"k1": public_key})

Web Bot Auth, built on this, is :class:`messh.Client` and :mod:`messh.verify`.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import _sf
from .errors import VerifyError

__all__ = ["Message", "Signed", "Signature", "Covered", "Verified", "component_value", "sign_message", "signatures",
           "pick_signature", "verify_message", "verify_signature", "content_digest", "check_digest", "VerifyError"]

Headers = Union[Mapping[str, Union[str, Sequence[str]]], Iterable[Tuple[str, str]]]

_KNOWN_TYPES = {
    "accept-signature": "dictionary", "cache-status": "list", "content-digest": "dictionary", "priority": "dictionary",
    "proxy-status": "list", "repr-digest": "dictionary", "signature": "dictionary", "signature-input": "dictionary",
    "signature-agent": "dictionary-or-item", "want-content-digest": "dictionary", "want-repr-digest": "dictionary",
}


def _fail(code: str, msg: str) -> VerifyError:
    return VerifyError(code, msg, 401)


@dataclass
class Message:
    """What a signature covers: a request, or a response (``status``) with the request it answers."""

    method: str = ""                        # request method, exactly as sent
    url: str = ""                           # absolute target URI; a Host header, if any, is the authority
    headers: Headers = ()                   # a mapping, or (name, value) pairs (which keep separate field lines)
    body: Optional[bytes] = None            # checked against a covered Content-Digest; None skips the check
    status: int = 0                         # response status code; 0 for a request
    request: Optional["Message"] = None     # for a response: the request it answers (components with req)
    trailers: Headers = ()                  # trailer fields, for components with tr
    request_target: str = ""                # the request line's target, if known; else path and query


class _Msg:
    __slots__ = ("method", "scheme", "authority", "path", "query", "request_target", "status", "headers", "trailers", "body", "request")


def _fields(h: Headers) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    items = h.items() if isinstance(h, Mapping) else h
    for k, v in items or ():
        k = (k.decode("latin-1") if isinstance(k, bytes) else k).lower()
        vals = [v] if isinstance(v, (str, bytes)) else list(v)
        for x in vals:
            out.setdefault(k, []).append(x.decode("latin-1") if isinstance(x, bytes) else x)
    return out


def _normalize(m: Message) -> _Msg:
    n = _Msg()
    n.method, n.request_target, n.status = m.method or "", m.request_target or "", m.status or 0
    n.headers, n.trailers = _fields(m.headers), _fields(m.trailers)
    n.body = m.body.encode() if isinstance(m.body, str) else m.body
    n.request = _normalize(m.request) if m.request is not None else None
    n.scheme = n.authority = n.path = n.query = ""
    if m.url:
        u = urlsplit(m.url)
        n.scheme, n.authority, n.path, n.query = u.scheme, u.netloc, u.path, u.query
    host = n.headers.get("host")
    if host:
        n.authority = host[0].strip()
    return n


# --- component identifiers ---

class _Comp:
    __slots__ = ("name", "params")

    def __init__(self, name: str, params: _sf.Params):
        self.name, self.params = name, params

    def id(self) -> str:
        return _sf.serialize_bare(("str", self.name)) + _sf.serialize_params(self.params)


def _checked(c: _Comp) -> _Comp:
    if re.fullmatch(r"@[a-z][a-z-]*", c.name) or re.fullmatch(r"[a-z0-9!#$%&'*+\-.^_`|~]+", c.name):
        return c
    raise ValueError("bad component name %r (lowercase field names, or @derived)" % c.name)


def _parse_component(s: str) -> _Comp:
    if not s.startswith('"'):
        return _checked(_Comp(s.lower(), []))
    try:
        it = _sf.parse_item(s)
    except ValueError:
        raise ValueError("bad component identifier %s" % s) from None
    if it.bare[0] != "str":
        raise ValueError("bad component identifier %s" % s)
    return _checked(_Comp(it.bare[1], it.params))


# --- component values (RFC 9421 §2) ---

def component_value(message: Message, component: str, field_types: Optional[Mapping[str, str]] = None) -> Tuple[str, str]:
    """The identifier and signature-base value of one component; raises ValueError if it can't be derived."""
    c = _parse_component(component)
    return c.id(), _value(_normalize(message), c, field_types or {})


def _value(m: _Msg, c: _Comp, types: Mapping[str, str]) -> str:
    cid = c.id()
    req = strict = bs = tr = False
    key = name = None
    for k, v in c.params:
        if k in ("req", "sf", "bs", "tr"):
            if v != _sf.TRUE:
                raise ValueError("%s: parameter %s must be true" % (cid, k))
            req, strict, bs, tr = req or k == "req", strict or k == "sf", bs or k == "bs", tr or k == "tr"
        elif k in ("key", "name"):
            if v[0] != "str":
                raise ValueError("%s: parameter %s must be a string" % (cid, k))
            if k == "key":
                key = v[1]
            else:
                name = v[1]
        else:
            raise ValueError("%s: unknown parameter %s" % (cid, k))
    derived = c.name.startswith("@")
    if derived and (strict or bs or tr or key is not None):
        raise ValueError("%s: sf, bs, tr and key apply to fields only" % cid)
    if name is not None and c.name != "@query-param":
        raise ValueError("%s: name applies to @query-param only" % cid)
    if bs and (strict or key is not None):
        raise ValueError("%s: bs can't be combined with sf or key" % cid)
    ctx = m
    if req:
        if not m.status or m.request is None:
            raise ValueError("%s: req needs a response and the request it answers" % cid)
        ctx = m.request
    if derived:
        if c.name == "@query-param" and name is None:
            raise ValueError("@query-param needs a name parameter")
        return _derived(ctx, c.name, name or "")
    return _field(ctx.trailers if tr else ctx.headers, c.name, strict, bs, key, types)


def _path(m: _Msg) -> str:
    return m.path or "/"


def _path_query(m: _Msg) -> str:
    return _path(m) + ("?" + m.query if m.query else "")


def _derived(m: _Msg, name: str, param: str) -> str:
    if name == "@status":
        if not m.status:
            raise ValueError("@status applies to responses only")
        return str(m.status)
    if not m.authority and not m.method:
        raise ValueError("%s needs the request (use req in a response signature)" % name)
    if name == "@method":
        if not m.method:
            raise ValueError("@method needs a request method")
        return m.method
    if name == "@target-uri":
        if not m.scheme or not m.authority:
            raise ValueError("@target-uri needs a scheme and an authority")
        return "%s://%s%s" % (m.scheme.lower(), m.authority.lower(), _path_query(m))
    if name == "@authority":
        if not m.authority:
            raise ValueError("@authority needs an authority")
        return m.authority.lower()
    if name == "@scheme":
        if not m.scheme:
            raise ValueError("@scheme needs a scheme")
        return m.scheme.lower()
    if name == "@request-target":
        return m.request_target or _path_query(m)
    if name == "@path":
        return _path(m)
    if name == "@query":
        return "?" + m.query
    if name == "@query-param":
        return _query_param(m.query, param)
    raise ValueError("unknown derived component %s" % name)


_OBS_FOLD = re.compile(r"[ \t]*\r?\n[ \t]+")


def _clean(v: str) -> str:
    return _OBS_FOLD.sub(" ", v.strip(" \t"))


def _field(h: Dict[str, List[str]], name: str, strict: bool, bs: bool, key: Optional[str], types: Mapping[str, str]) -> str:
    vals = h.get(name)
    if not vals:
        raise ValueError("covered field %s is missing" % name)
    parts = [_sf.serialize_bare(("bin", _clean(x).encode("latin-1"))) if bs else _clean(x) for x in vals]
    v = ", ".join(parts)
    if key is not None:
        try:
            d, _ = _sf.parse_dictionary(v)
        except ValueError as e:
            raise ValueError("%s is not a dictionary: %s" % (name, e)) from None
        mem = _sf.member(d, key)
        if mem is None:
            raise ValueError("%s has no member %r" % (name, key))
        return _sf.serialize_member(mem)
    return _strict(name, v, types) if strict else v


def _strict(name: str, v: str, types: Mapping[str, str]) -> str:
    t = types.get(name) or _KNOWN_TYPES.get(name)
    if t in ("dictionary", "dictionary-or-item"):
        try:
            return _sf.serialize_dictionary(_sf.parse_dictionary(v)[0])
        except ValueError as e:
            if t == "dictionary":
                raise ValueError("%s: %s" % (name, e)) from None
    if t in ("item", "dictionary-or-item"):
        return _sf.serialize_item(_sf.parse_item(v))
    if t == "list":
        return _sf.serialize_list(_sf.parse_list(v))
    raise ValueError("can't serialize %s strictly: its structured-field type is unknown" % name)


def _form_decode(s: str) -> bytes:
    s = s.replace("+", " ")
    out = bytearray()
    i = 0
    while i < len(s):
        if s[i] == "%" and i + 2 < len(s) and re.fullmatch(r"[0-9a-fA-F]{2}", s[i + 1:i + 3]):
            out.append(int(s[i + 1:i + 3], 16))
            i += 3
            continue
        out += s[i].encode("utf-8")
        i += 1
    return bytes(out)


def _form_encode(b: bytes) -> str:
    return "".join(chr(c) if re.fullmatch(r"[A-Za-z0-9*\-._]", chr(c)) else "%%%02X" % c for c in b)


def _query_param(raw: str, name: str) -> str:
    """The encoded value of one query parameter (RFC 9421 §2.2.8)."""
    vals = []
    for part in raw.split("&"):
        if not part:
            continue
        k, _, v = part.partition("=")
        if _form_encode(_form_decode(k)) == name:
            vals.append(_form_encode(_form_decode(v)))
    if not vals:
        raise ValueError("query parameter %r is missing" % name)
    if len(vals) > 1:
        raise ValueError("query parameter %r occurs more than once" % name)
    return vals[0]


# --- signature base (RFC 9421 §2.5) ---

def _base(m: _Msg, comps: Sequence[_Comp], params: str, types: Mapping[str, str]) -> str:
    seen = set()
    lines = []
    for c in comps:
        cid = c.id()
        if cid in seen:
            raise ValueError("component %s is covered twice" % cid)
        seen.add(cid)
        lines.append("%s: %s" % (cid, _value(m, c, types)))
    lines.append('"@signature-params": ' + params)
    base = "\n".join(lines)
    if re.search(r"[^\x20-\x7e\n]", base):
        raise ValueError("signature base must be printable ASCII (wrap such fields with bs)")
    return base


# --- signing ---

@dataclass(frozen=True)
class Signed:
    """A signature ready to send."""

    label: str
    input: str       # the Signature-Input member value: covered components and parameters
    signature: str   # the Signature member value: :base64:
    base: str        # the signature base that was signed

    @property
    def headers(self) -> Dict[str, str]:
        """Signature-Input and Signature with only this signature."""
        return {"Signature-Input": "%s=%s" % (self.label, self.input), "Signature": "%s=%s" % (self.label, self.signature)}


def sign_message(message: Message, signer, *, components: Sequence[str], label: str = "sig1", created: Optional[int] = None,
                 expires: Optional[int] = None, keyid: Optional[str] = None, alg: Optional[str] = None, nonce: Optional[str] = None,
                 tag: Optional[str] = None, field_types: Optional[Mapping[str, str]] = None) -> Signed:
    """Sign a message. Components are plain names (@method, content-type) or
    identifiers with parameters ('"example-dict";key="a"'). ``signer`` has
    ``sign(bytes) -> bytes`` (a messh key). Parameters left as None are omitted."""
    if not _sf.valid_key(label):
        raise ValueError("bad label %r" % label)
    comps = [_parse_component(s) for s in components]
    params: _sf.Params = []
    if created is not None:
        params.append(("created", ("int", int(created))))
    if expires is not None:
        params.append(("expires", ("int", int(expires))))
    for k, v in (("keyid", keyid), ("alg", alg), ("nonce", nonce), ("tag", tag)):
        if v is None:
            continue
        if not _sf.valid_string(v):
            raise ValueError("%s must be printable ASCII" % k)
        params.append((k, ("str", v)))
    inp = _sf.serialize_member(_sf.InnerList([_sf.Item(("str", c.name), c.params) for c in comps], params))
    base = _base(_normalize(message), comps, inp, field_types or {})
    return Signed(label, inp, _sf.serialize_bare(("bin", signer.sign(base.encode()))), base)


# --- parsing signatures ---

@dataclass(frozen=True)
class Covered:
    """One covered component of a signature."""

    id: str                     # serialized identifier, e.g. '"signature-agent";key="sig1"'
    name: str                   # component name
    key: Optional[str] = None   # its key parameter, if any


@dataclass
class Signature:
    """One signature of a message, parsed but not verified."""

    label: str
    covered: List[Covered]
    value: bytes
    created: Optional[int] = None
    expires: Optional[int] = None
    keyid: Optional[str] = None
    alg: Optional[str] = None
    nonce: Optional[str] = None
    tag: Optional[str] = None
    _comps: List[_Comp] = field(default_factory=list, repr=False)
    _params: str = field(default="", repr=False)

    def covers(self, name: str) -> bool:
        return any(c.name == name for c in self.covered)


def _dictionary(h: Dict[str, List[str]], name: str) -> _sf.Dictionary:
    try:
        d, dups = _sf.parse_dictionary(", ".join(h.get(name.lower(), [])))
    except ValueError as e:
        raise _fail("bad_signature", "%s: %s" % (name, e)) from None
    if dups:
        raise _fail("bad_signature", "%s repeats the label %s" % (name, dups[0]))
    return d


def _parse_signatures(m: _Msg) -> List[Signature]:
    if not m.headers.get("signature-input") or not m.headers.get("signature"):
        raise _fail("missing_signature", "send Signature-Input and Signature (RFC 9421)")
    inputs = _dictionary(m.headers, "Signature-Input")
    values = _dictionary(m.headers, "Signature")
    out = []
    for label, mem in inputs:
        if not isinstance(mem, _sf.InnerList):
            raise _fail("bad_signature", "Signature-Input %s is not an inner list" % label)
        s = Signature(label, [], b"", _params=_sf.serialize_member(mem))
        seen = set()
        for it in mem.items:
            if it.bare[0] != "str":
                raise _fail("bad_signature", "Signature-Input %s: a component is not a string" % label)
            try:
                c = _checked(_Comp(it.bare[1], it.params))
            except ValueError as e:
                raise _fail("bad_signature", "Signature-Input %s: %s" % (label, e)) from None
            cid = c.id()
            if cid in seen:
                raise _fail("bad_signature", "Signature-Input %s covers %s twice" % (label, cid))
            seen.add(cid)
            k = _sf.param(c.params, "key")
            s._comps.append(c)
            s.covered.append(Covered(cid, c.name, k[1] if k and k[0] == "str" else None))
        for k, v in mem.params:
            if k in ("created", "expires"):
                if v[0] != "int":
                    raise _fail("bad_signature", "%s must be an integer" % k)
                setattr(s, k, v[1])
            elif k in ("keyid", "alg", "nonce", "tag"):
                if v[0] != "str":
                    raise _fail("bad_signature", "%s must be a string" % k)
                setattr(s, k, v[1])
        sig = _sf.member(values, label)
        if not isinstance(sig, _sf.Item) or sig.bare[0] != "bin":
            raise _fail("bad_signature", "no Signature for %s" % label)
        s.value = sig.bare[1]
        out.append(s)
    if not out:
        raise _fail("missing_signature", "Signature-Input has no signatures")
    return out


def signatures(message: Message) -> List[Signature]:
    """Parse Signature-Input and Signature. Labels and covered components must not repeat (RFC 9421 §4.1, §2.5)."""
    return _parse_signatures(_normalize(message))


def pick_signature(sigs: Sequence[Signature], label: Optional[str] = None, tag: Optional[str] = None) -> Signature:
    """Choose a signature by label, else by tag, else the only one."""
    for s in sigs:
        if (label and s.label == label) or (not label and tag and s.tag == tag):
            return s
    if label:
        raise _fail("bad_signature", "no signature labeled %s" % label)
    if tag:
        raise _fail("bad_signature", "no signature with tag=%r" % tag)
    if len(sigs) == 1:
        return sigs[0]
    raise _fail("bad_signature", "the message has %d signatures: choose one by label or tag" % len(sigs))


def content_digest(body: bytes) -> str:
    """The RFC 9530 Content-Digest field for body (sha-256)."""
    return _sf.serialize_dictionary([("sha-256", _sf.Item(("bin", hashlib.sha256(body).digest()), []))])


def check_digest(value: str, body: bytes) -> None:
    """Check body against a Content-Digest field (sha-256 or sha-512); raises VerifyError digest_mismatch."""
    known = 0
    try:
        d, _ = _sf.parse_dictionary(value)
    except ValueError:
        d = []
    for k, m in d:
        if k not in ("sha-256", "sha-512"):
            continue
        known += 1
        want = hashlib.new(k.replace("-", ""), body).digest()
        if not isinstance(m, _sf.Item) or m.bare != ("bin", want):
            raise _fail("digest_mismatch", "the body doesn't match Content-Digest")
    if not known:
        raise _fail("digest_mismatch", "Content-Digest has no sha-256 or sha-512 digest")


# --- verifying ---

@dataclass(frozen=True)
class Verified:
    label: str
    components: List[str]          # covered component identifiers
    keyid: Optional[str]
    alg: Optional[str]
    nonce: Optional[str]
    tag: Optional[str]
    created: Optional[int]
    expires: Optional[int]
    base: str


Keys = Union[Mapping[str, bytes], Callable[[str], Optional[bytes]]]


def verify_message(message: Message, *, keys: Keys, label: Optional[str] = None, tag: Optional[str] = None, **options) -> Verified:
    """Verify one signature (by label, else tag, else the only one): content
    digest, time, key, then the signature. ``keys`` maps a keyid to a raw
    32-byte Ed25519 public key (a mapping or a function returning None for
    unknown keys). Options: now, max_skew (s, default 60), max_age (s),
    required (component names), nonce_store, field_types. Raises VerifyError."""
    m = _normalize(message)
    return _verify(m, pick_signature(_parse_signatures(m), label, tag), keys, **options)


def verify_signature(message: Message, sig: Signature, *, keys: Keys, **options) -> Verified:
    """Verify a signature from :func:`signatures`."""
    return _verify(_normalize(message), sig, keys, **options)


def _verify(m: _Msg, s: Signature, keys: Keys, now: Optional[float] = None, max_skew: float = 60, max_age: Optional[float] = None,
            required: Sequence[str] = (), nonce_store=None, field_types: Optional[Mapping[str, str]] = None) -> Verified:
    for name in required:
        if not s.covers(name):
            raise _fail("bad_signature", "%s must be covered" % name)
    if s.alg is not None and s.alg != "ed25519":
        raise _fail("bad_signature", "alg %r is not supported (ed25519 only)" % s.alg)
    for c in s._comps:
        if c.name != "content-digest":
            continue
        ctx = m.request if _sf.param(c.params, "req") and m.request is not None else m
        if ctx.body is not None:
            check_digest(", ".join(ctx.headers.get("content-digest", [])), ctx.body)
    now = time.time() if now is None else now
    if s.created is not None:
        if s.created > now + max_skew:
            raise _fail("clock_skew", "created is %ds ahead of the clock" % int(s.created - now))
        if max_age is not None and s.created < now - max_age:
            raise _fail("clock_skew", "the signature is %ds old" % int(now - s.created))
    if s.expires is not None and now > s.expires:
        raise _fail("clock_skew", "the signature expired")
    try:
        pub = keys.get(s.keyid or "") if isinstance(keys, Mapping) else keys(s.keyid or "")
    except VerifyError:
        raise
    except Exception as e:
        raise _fail("unknown_key", "keyid %r: %s" % (s.keyid, e)) from None
    if not pub or len(pub) != 32:
        raise _fail("unknown_key", "keyid %r is not a known Ed25519 key" % (s.keyid or ""))
    try:
        base = _base(m, s._comps, s._params, field_types or {})
    except ValueError as e:
        raise _fail("bad_signature", str(e)) from None
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(s.value, base.encode())
    except InvalidSignature:
        raise _fail("bad_signature", "the signature doesn't match the message") from None
    if nonce_store is not None and s.nonce is not None:
        ttl = max_age + max_skew if max_age is not None else 2 * max_skew
        if s.expires is not None:
            ttl = max(ttl, s.expires - now + max_skew)
        if not nonce_store.add("%s %s" % (s.keyid or "", s.nonce), ttl):
            raise _fail("nonce_replayed", "this signature was already accepted once")
    return Verified(s.label, [c.id for c in s.covered], s.keyid, s.alg, s.nonce, s.tag, s.created, s.expires, base)
