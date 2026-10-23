"""Web Bot Auth wire format: RFC 9421 signature base, structured-field
parsing, RFC 7638 thumbprints and RFC 9530 Content-Digest."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

TAG = "web-bot-auth"
LABEL = "sig1"
DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
MAX_LIFETIME = 300


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def thumbprint(public_key: bytes) -> str:
    """RFC 7638 JWK thumbprint of a raw 32-byte Ed25519 public key."""
    canon = '{"crv":"Ed25519","kty":"OKP","x":"%s"}' % b64url(public_key)
    return b64url(hashlib.sha256(canon.encode()).digest())


def ssh_string(b: bytes) -> bytes:
    """SSH wire-format string: uint32 length, then the bytes."""
    return len(b).to_bytes(4, "big") + b


def fingerprint(public_key: bytes) -> str:
    """The key's SSH fingerprint, as ssh-keygen -l and messh print it: SHA256:…"""
    blob = ssh_string(b"ssh-ed25519") + ssh_string(public_key)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def content_digest(body: bytes) -> str:
    return "sha-256=:%s:" % base64.b64encode(hashlib.sha256(body).digest()).decode()


def quote(s: str) -> str:
    # Go's strconv.Quote for the ASCII values used here.
    return json.dumps(s)


def params(names: Sequence[str], created: int, expires: int, keyid: str, nonce: str) -> str:
    inner = " ".join(quote(n) for n in names)
    return '(%s);created=%d;expires=%d;keyid=%s;alg="ed25519";nonce=%s;tag="%s"' % (
        inner, created, expires, quote(keyid), quote(nonce), TAG)


def base(components: Sequence[Tuple[str, str]], sig_params: str) -> bytes:
    lines = ["%s: %s" % (quote(name), value) for name, value in components]
    lines.append('"@signature-params": ' + sig_params)
    return "\n".join(lines).encode()


@dataclass
class SigParams:
    label: str
    components: List[str]
    params: Dict[str, str]
    raw: str = field(repr=False)


def _split_top(s: str) -> List[str]:
    out, depth, in_str, start, i = [], 0, False, 0, 0
    while i < len(s):
        c = s[i]
        if in_str and c == "\\":
            i += 2
            continue
        if c == '"':
            in_str = not in_str
        elif not in_str:
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            elif c == "," and depth == 0:
                out.append(s[start:i].strip())
                start = i + 1
        i += 1
    out.append(s[start:].strip())
    return out


def _unquote(v: str) -> str:
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return json.loads(v)
    return v


def _member(label: str, raw: str) -> SigParams:
    if not raw.startswith("("):
        raise ValueError("Signature-Input member is not an inner list")
    end = raw.find(")")
    if end < 0:
        raise ValueError("unterminated inner list")
    comps = []
    for item in raw[1:end].split():
        if not (item.startswith('"') and item.endswith('"')):
            raise ValueError("bad component %s" % item)
        comps.append(json.loads(item))
    ps: Dict[str, str] = {}
    for p in raw[end + 1:].split(";")[1:]:
        k, _, v = p.partition("=")
        ps[k.strip()] = _unquote(v)
    return SigParams(label, comps, ps, raw)


def pick_web_bot_auth(header: str) -> SigParams:
    for m in _split_top(header):
        label, eq, raw = m.partition("=")
        if not eq:
            continue
        sp = _member(label, raw)
        if sp.params.get("tag") == TAG:
            return sp
    raise ValueError('no signature with tag="web-bot-auth"')


def signature_bytes(header: str, label: str) -> bytes:
    for m in _split_top(header):
        l, _, v = m.partition("=")
        if l == label and len(v) > 2 and v[0] == ":" and v[-1] == ":":
            return base64.b64decode(v[1:-1], validate=True)
    raise ValueError("no Signature for %s" % label)


def parse_agent(header: str, label: str) -> str:
    h = header.strip()
    if h.startswith('"'):
        return json.loads(h)
    for m in _split_top(h):
        l, eq, v = m.partition("=")
        if eq and l == label:
            return json.loads(v)
    raise ValueError("Signature-Agent has no value for %s" % label)


def jwk_public_key(jwk: dict) -> Optional[bytes]:
    """Decode an Ed25519 JWK; None if malformed or kid isn't its thumbprint."""
    try:
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            return None
        pub = b64url_decode(jwk["x"])
    except Exception:
        return None
    if len(pub) != 32 or (jwk.get("kid") and jwk["kid"] != thumbprint(pub)):
        return None
    return pub
