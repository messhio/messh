"""Verify Web Bot Auth signatures with keys from messh, or from the key
directories of other agents you trust."""

from __future__ import annotations

import asyncio
import base64
import json
import re
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Set, Tuple, Union
from urllib.parse import unquote_to_bytes, urlsplit

from . import _sf, _wba
from .client import DIRECTORY_TAG, __version__
from .errors import VerifyError
from .httpsig import Message, Signature, check_digest, signatures, verify_signature

try:  # FastAPI injects the request into current_agent by this annotation
    from starlette.requests import Request as _Request
except ImportError:  # starlette is optional: pip install "messh-sdk[fastapi]"
    _Request = object

__all__ = ["Agent", "Verifier", "VerifyError", "MemoryNonceStore", "NonceStore", "MesshAuthMiddleware", "current_agent", "ACCEPT_SIGNATURE",
           "verify_directory"]

ACCEPT_SIGNATURE = 'sig1=("@method" "@authority" "@path" "signature-agent");keyid;created;expires;nonce;alg="ed25519";tag="web-bot-auth"'
_IDENTITY = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,28}[a-z0-9])$")

# Directory cache policy, the same in every messh SDK.
_MIN_REFRESH = 30       # an unknown keyid refetches its signer's directory at most this often (s)
_RETRY_AFTER = 5        # while messh is unreachable, retry a directory at most this often (s)
_MAX_ENTRIES = 10_000   # directories kept at most
_STRIPES = 64           # fetch locks: one fetch per directory at a time
MAX_BODY_BYTES = 1 << 20  # default limit on request bodies MesshAuthMiddleware reads
_UNSET = object()       # no good answer yet (None means: no such identity)
_DEFAULT_REQUIRED = ("@method", "@authority", "@path", "signature-agent")


class _Entry:
    """dir is the last good answer (None: no such identity), fetched at ``at``; failed_at is the last failed fetch;
    signed holds the key IDs the directory response signed."""

    __slots__ = ("dir", "at", "failed_at", "signed")

    def __init__(self, dir, at, failed_at=None, signed=frozenset()):
        self.dir, self.at, self.failed_at, self.signed = dir, at, failed_at, signed
Headers = Union[Mapping[str, str], Iterable[Tuple[str, str]]]


@dataclass(frozen=True)
class Agent:
    identity: str      # messh username, e.g. "mukul"; for other agents, their origin or jwk:<thumbprint>
    key_name: str      # key name on messh, e.g. "laptop"
    key_id: str        # RFC 7638 thumbprint
    fingerprint: str   # SHA256:… of the SSH key
    agent_url: str     # Signature-Agent
    created: int       # unix seconds
    external: bool = False          # not a messh identity: an agent origin you trust, or inline keys
    signed_directory: bool = False  # the key's directory response carried a valid signature by that key


class NonceStore(Protocol):
    def add(self, key: str, ttl: float) -> bool:
        """Record key; return False if it was already seen within ttl."""


class MemoryNonceStore:
    """In-process replay store. Use a shared store when running several instances."""

    def __init__(self):
        self._seen: Dict[str, float] = {}
        self._lock = threading.Lock()

    def add(self, key: str, ttl: float) -> bool:
        now = time.monotonic()
        with self._lock:
            for k in [k for k, exp in self._seen.items() if exp < now]:
                del self._seen[k]
            if key in self._seen:
                return False
            self._seen[key] = now + ttl
            return True


def _fail(code: str, msg: str, status: int = 401) -> VerifyError:
    return VerifyError(code, msg, status)


class _Who:
    """Who a Signature-Agent names."""

    __slots__ = ("identity", "external", "fetch_url", "inline")

    def __init__(self, identity: str, external: bool, fetch_url: str = "", inline: Optional[dict] = None):
        self.identity, self.external, self.fetch_url, self.inline = identity, external, fetch_url, inline


def _find(d, kid: str):
    for k in d.get("keys", []) if isinstance(d, dict) else []:
        p = _wba.jwk_public_key(k)
        if p and (k.get("kid") == kid or (not k.get("kid") and _wba.thumbprint(p) == kid)):
            return k, p
    return None


class Verifier:
    """Create once and reuse; it caches key directories.

    >>> v = Verifier(trust=["mukul"])
    >>> agent = v.verify("GET", "https://api.example.com/hello", headers)

    ``trust`` lists messh usernames, "*" for any messh identity, the origin of
    another Web Bot Auth agent ("https://agent.example", whose key directory is
    at <origin>/.well-known/http-message-signatures-directory), or
    jwk:<thumbprint> for a key sent inline in Signature-Agent.
    ``require_components`` replaces the components every signature must cover
    (default @method, @authority, @path, signature-agent), for agents that sign
    less; @target-uri counts for @authority, @path and @query, @request-target
    for @path and @query; Signature-Agent, a query and a body must be covered
    regardless. ``require_signed_directory`` ignores keys a fetched key
    directory doesn't sign (messh.io doesn't sign its directories yet).
    """

    def __init__(
        self,
        trust: Sequence[str],
        *,
        registries: Union[Sequence[str], Mapping[str, str], None] = None,
        max_skew: int = 60,
        cache_ttl: float = 300,
        stale_if_error: float = 3600,
        nonce_store: Optional[NonceStore] = None,
        timeout: float = 5.0,
        max_body_bytes: int = MAX_BODY_BYTES,
        clock: Optional[Callable[[], float]] = None,
        directory: Union[dict, Callable[[str, str], dict], None] = None,
        require_components: Optional[Sequence[str]] = None,
        require_signed_directory: bool = False,
    ):
        if not trust:
            raise ValueError("trust is required, e.g. trust=['mukul'] or ['*']")
        self.trust = [t.lower().rstrip("/") if t.startswith(("https://", "http://")) else t for t in trust]
        regs = registries or ["https://messh.io"]
        self._registries = {k.rstrip("/"): v.rstrip("/") for k, v in (regs.items() if isinstance(regs, Mapping) else ((r, r) for r in regs))}
        self.max_skew = max_skew
        self.cache_ttl = cache_ttl
        self.stale_if_error = stale_if_error
        self.nonces = nonce_store or MemoryNonceStore()
        self.timeout = timeout
        self.max_body_bytes = max_body_bytes
        self._clock = clock or time.time
        self._directory = directory
        self._required = list(require_components) if require_components is not None else None
        self._require_signed = require_signed_directory
        self._cache: "OrderedDict[str, _Entry]" = OrderedDict()
        self._lock = threading.Lock()
        self._fetching = [threading.Lock() for _ in range(_STRIPES)]

    def verify(self, method: str, url: str, headers: Headers, body: bytes = b"") -> Agent:
        """Verify one request. ``url`` is the full request URL; the authority
        is the Host header if present, else the URL's host. Raises VerifyError."""
        pairs = [((k.decode("latin-1") if isinstance(k, bytes) else k), (v.decode("latin-1") if isinstance(v, bytes) else v))
                 for k, v in (headers.items() if isinstance(headers, Mapping) else headers)]
        h = _lower(pairs)
        now = self._clock()
        if not h.get("signature-input") or not h.get("signature"):
            raise _fail("missing_signature", "send Signature, Signature-Input and Signature-Agent (Web Bot Auth)")
        msg = Message(method, url, headers=pairs)
        sig = next((s for s in signatures(msg) if s.tag == _wba.TAG), None)
        if sig is None:
            raise _fail("bad_signature", 'no signature with tag="web-bot-auth"')
        self._coverage(sig, bool(urlsplit(url).query))
        agent_url = _agent_of(h.get("signature-agent"), sig)
        if sig.alg is not None and sig.alg != "ed25519":
            raise _fail("bad_signature", "alg %r is not supported" % sig.alg)

        body = body or b""
        if sig.covers("content-digest"):
            check_digest(h.get("content-digest", ""), body)
        elif body:
            raise _fail("bad_signature", "a request body must be covered by content-digest")

        created = sig.created
        if created is None:
            raise _fail("bad_signature", "created is required")
        if abs(now - created) > self.max_skew:
            raise _fail("clock_skew", "created is %ds from the server clock" % int(now - created))
        if sig.expires is not None and (now > sig.expires or sig.expires - created > _wba.MAX_LIFETIME):
            raise _fail("clock_skew", "signature expired")
        if not sig.nonce:
            raise _fail("bad_signature", "nonce is required")

        who = self._classify(agent_url, sig.keyid or "")
        # Before any fetch: callers outside the trust list can't make this API fetch directories.
        if not any(t == who.identity or (t == "*" and not who.external) for t in self.trust):
            raise _fail("untrusted", "%s is not in this API's trust list" % who.identity, 403)
        found = {}

        def keys(kid):
            found["hit"] = self._lookup(agent_url, who, kid)
            return found["hit"][1]

        msg.body = body
        verify_signature(msg, sig, keys=keys, now=now, max_skew=self.max_skew, max_age=self.max_skew)
        if not self.nonces.add(agent_url + " " + sig.nonce, 2 * self.max_skew):
            raise _fail("nonce_replayed", "this signature was already accepted once")
        key, pub, signed = found["hit"]
        return Agent(who.identity, key.get("messh_name", ""), sig.keyid or "", key.get("messh_fingerprint") or _wba.fingerprint(pub),
                     agent_url, created, who.external, signed)

    async def averify(self, method: str, url: str, headers: Headers, body: bytes = b"") -> Agent:
        """Async verify; the directory fetch runs in a thread."""
        return await asyncio.to_thread(self.verify, method, url, headers, body)

    def _coverage(self, s: Signature, has_query: bool) -> None:
        def has(name: str) -> bool:
            return (s.covers(name) or (name == "@authority" and s.covers("@target-uri"))
                    or (name in ("@path", "@query") and (s.covers("@target-uri") or s.covers("@request-target"))))

        for c in list(self._required if self._required is not None else _DEFAULT_REQUIRED) + ["signature-agent"]:
            if not has(c):
                raise _fail("bad_signature", "%s must be covered" % c)
        if has_query and not has("@query"):
            raise _fail("bad_signature", "@query must be covered when the URL has a query")

    def _classify(self, agent_url: str, keyid: str) -> _Who:
        """Map Signature-Agent to a messh identity (<registry>/<user>), an agent origin, or inline keys, refusing anything else."""
        if agent_url.startswith("data:"):
            return _Who("jwk:" + keyid, True, inline=_parse_data_uri(agent_url))
        u = urlsplit(agent_url)
        if u.scheme not in ("https", "http") or not u.netloc:
            raise _fail("bad_signature", "Signature-Agent is not a URL")
        base = self._registries.get("%s://%s" % (u.scheme, u.netloc))
        if base is not None:
            ident = u.path.strip("/")
            if not _IDENTITY.match(ident):
                raise _fail("unknown_key", "Signature-Agent must be <registry>/<user>")
            return _Who(ident, False, base + "/" + ident + _wba.DIRECTORY_PATH)
        origin = ("%s://%s" % (u.scheme, u.netloc)).lower()
        if origin in self.trust:
            if u.path not in ("", "/") or u.query:
                raise _fail("untrusted", "Signature-Agent %s: an agent outside messh is an origin, like %s" % (agent_url, origin), 403)
            return _Who(origin, True, origin + _wba.DIRECTORY_PATH)
        raise _fail("untrusted", "Signature-Agent %s is not a messh registry or an agent this API trusts" % agent_url, 403)

    def _lookup(self, agent_url: str, who: _Who, kid: str):
        """The signer's (jwk, public key, signed) for kid. Directories are cached
        for cache_ttl; an unknown kid refetches at most every 30 s (so a key
        published a moment ago works), unknown identities are remembered the
        same way, one fetch per directory runs at a time, and while the
        directory is unreachable cached keys keep working for stale_if_error."""

        def found(d, signed=frozenset()):
            hit = _find(d, kid)
            if hit:
                return hit[0], hit[1], kid in signed
            if d is None:
                raise _fail("unknown_key", "there's no messh identity at %s" % agent_url)
            raise _fail("unknown_key", "keyid %s is not an active key of %s; publish it with messh publish" % (kid, agent_url))

        if who.inline is not None:
            return found(who.inline)
        if isinstance(self._directory, dict):
            return found(self._directory)
        if callable(self._directory):
            return found(self._directory(agent_url, who.identity))
        now = self._clock()
        e = self._entry(agent_url)
        if e and e.at is not None and now - e.at < self.cache_ttl:
            if _find(e.dir, kid):
                return found(e.dir, e.signed)
            if now - e.at < _MIN_REFRESH:
                return found(e.dir)
        with self._fetching[hash(agent_url) % _STRIPES]:
            e = self._entry(agent_url)
            if e and e.at is not None and now - e.at < min(self.cache_ttl, _MIN_REFRESH):
                return found(e.dir, e.signed)  # fetched by another thread while this one waited
            if not (e and e.failed_at is not None and now - e.failed_at < _RETRY_AFTER):
                d, signed, ok = self._fetch(who.fetch_url)
                if ok:
                    self._store(agent_url, _Entry(d, now, signed=signed))
                    return found(d, signed)
                e = self._store(agent_url, _Entry(e.dir if e else _UNSET, e.at if e else None, now, e.signed if e else frozenset()))
        # The directory is unreachable: keep verifying with the cached one for a while.
        if e and e.at is not None and e.dir is not _UNSET and now - e.at < self.stale_if_error:
            return found(e.dir, e.signed)
        raise _fail("unknown_key", "key directory for %s is unavailable" % agent_url)

    def _fetch(self, url: str):
        """(directory, signed, True); (None, ∅, True) for no such identity; (None, ∅, False) if it couldn't be fetched."""
        req = urllib.request.Request(url, headers={
            "Accept": "application/http-message-signatures-directory+json, application/json",
            "User-Agent": "messh-python/" + __version__,
        })
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body, headers = r.read(1 << 20), list(r.headers.items())
            d, signed = verify_directory(url, headers, body, self._clock())
        except urllib.error.HTTPError as e:
            return None, frozenset(), e.code == 404
        except (OSError, ValueError):
            return None, frozenset(), False
        if self._require_signed:
            d = dict(d, keys=[k for k in d["keys"] if k.get("kid") in signed])
        return d, frozenset(signed), True

    def _entry(self, agent_url: str) -> Optional[_Entry]:
        with self._lock:
            return self._cache.get(agent_url)

    def _store(self, agent_url: str, e: _Entry) -> _Entry:
        with self._lock:
            self._cache[agent_url] = e
            self._cache.move_to_end(agent_url)
            while len(self._cache) > _MAX_ENTRIES:
                self._cache.popitem(last=False)
        return e


def _agent_of(header: Optional[str], s: Signature) -> str:
    """Signature-Agent: the member named by the covered component's key parameter, else a string, else the member named like the label."""
    if not header:
        raise _fail("bad_signature", "Signature-Agent header is missing")

    def str_member(key):
        try:
            m = _sf.member(_sf.parse_dictionary(header)[0], key)
        except ValueError:
            return None
        return m.bare[1] if isinstance(m, _sf.Item) and m.bare[0] == "str" else None

    keyed = next((c for c in s.covered if c.name == "signature-agent" and c.key is not None), None)
    if keyed is not None:
        v = str_member(keyed.key)
        if v is None:
            raise _fail("bad_signature", "Signature-Agent has no member %s" % keyed.key)
        return v
    try:
        it = _sf.parse_item(header)
        if it.bare[0] == "str":
            return it.bare[1]
    except ValueError:
        pass
    v = str_member(s.label)
    if v is None:
        raise _fail("bad_signature", "Signature-Agent has no value for %s" % s.label)
    return v


def _parse_data_uri(s: str) -> dict:
    """An inline key directory: data:application/http-message-signatures-directory[+json][;base64],…"""
    meta, sep, data = s[5:].partition(",")
    is_b64 = meta.endswith(";base64")
    media = meta[: -len(";base64")] if is_b64 else meta
    if not sep or media.split(";")[0].strip().lower() not in (
            "application/http-message-signatures-directory", "application/http-message-signatures-directory+json", "application/json"):
        raise _fail("bad_signature", "Signature-Agent: the data URI isn't a key directory")
    try:
        raw = base64.b64decode(data + "=" * (-len(data) % 4)) if is_b64 else unquote_to_bytes(data)
        d = json.loads(raw)
    except ValueError:
        d = None
    if not isinstance(d, dict) or not isinstance(d.get("keys"), list):
        raise _fail("bad_signature", "Signature-Agent: the data URI isn't a key directory")
    return d


def verify_directory(url: str, headers: Headers, body: bytes, now: Optional[float] = None) -> Tuple[dict, Set[str]]:
    """A key directory response fetched from ``url``: its keys, and the key IDs
    a valid directory signature covers (tag http-message-signatures-directory,
    signed by that key, binding the response to the authority it came from;
    draft-meunier-http-message-signatures-directory §5)."""
    d = json.loads(body)
    if not isinstance(d, dict) or not isinstance(d.get("keys"), list):
        raise ValueError("not a key directory")
    # The response carries the request's URL too, for directories signed over a plain "@authority".
    msg = Message(url=url, headers=headers, body=body, status=200, request=Message("GET", url))
    signed: Set[str] = set()
    try:
        sigs = signatures(msg)
    except VerifyError:
        return d, signed
    for s in sigs:
        hit = _find(d, s.keyid or "") if s.tag == DIRECTORY_TAG else None
        if not hit:
            continue
        try:
            verify_signature(msg, s, keys=lambda _kid, pub=hit[1]: pub, now=time.time() if now is None else now)
            signed.add(s.keyid)
        except VerifyError:
            pass
    return d, signed


def _lower(headers: Headers) -> Dict[str, str]:
    items = headers.items() if isinstance(headers, Mapping) else headers
    out: Dict[str, str] = {}
    for k, v in items:
        k = (k.decode() if isinstance(k, bytes) else k).lower()
        v = (v.decode() if isinstance(v, bytes) else v).strip()
        out[k] = out[k] + ", " + v if k in out else v
    return out


class MesshAuthMiddleware:
    """ASGI middleware (FastAPI, Starlette, any ASGI app).

    app.add_middleware(MesshAuthMiddleware, trust=["mukul"])

    Verified callers are in ``scope["state"]["messh_agent"]`` (``request.state.messh_agent``).
    Set ``paths`` to protect only some prefixes, e.g. ``paths=["/api/"]``.
    """

    def __init__(self, app, verifier: Optional[Verifier] = None, paths: Sequence[str] = ("/",), **verifier_options):
        self.app = app
        self.verifier = verifier or Verifier(**verifier_options)
        self.paths = tuple(paths)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope["path"].startswith(self.paths):
            return await self.app(scope, receive, send)
        chunks, more, size, limit = [], True, 0, self.verifier.max_body_bytes
        while more:
            msg = await receive()
            chunk = msg.get("body", b"")
            size += len(chunk)
            if size > limit:
                err = _fail("body_too_large", "the request body is over this API's limit of %d bytes" % limit, 413)
                await send({"type": "http.response.start", "status": 413, "headers": [(b"content-type", b"application/json")]})
                await send({"type": "http.response.body", "body": json.dumps(err.to_dict()).encode()})
                return
            chunks.append(chunk)
            more = msg.get("more_body", False)
        body = b"".join(chunks)
        headers = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in scope["headers"]]
        host = dict(headers).get("host") or "%s:%s" % tuple(scope.get("server") or ("localhost", 80))
        qs = scope.get("query_string", b"").decode("latin-1")
        url = "%s://%s%s%s" % (scope.get("scheme", "http"), host, scope.get("raw_path", scope["path"].encode()).decode("latin-1").split("?")[0], "?" + qs if qs else "")
        try:
            agent = await self.verifier.averify(scope["method"], url, headers, body)
        except VerifyError as e:
            hdrs = [(b"content-type", b"application/json")]
            if e.status == 401:
                hdrs.append((b"accept-signature", ACCEPT_SIGNATURE.encode()))
            await send({"type": "http.response.start", "status": e.status, "headers": hdrs})
            await send({"type": "http.response.body", "body": json.dumps(e.to_dict()).encode()})
            return
        scope.setdefault("state", {})["messh_agent"] = agent
        sent = False

        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


def current_agent(request: _Request) -> Agent:
    """FastAPI dependency: ``agent: Agent = Depends(current_agent)``."""
    agent = getattr(request.state, "messh_agent", None)
    if agent is None:
        raise VerifyError("missing_signature", "MesshAuthMiddleware did not run for this path")
    return agent
