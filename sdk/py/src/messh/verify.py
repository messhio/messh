"""Verify Web Bot Auth signatures with keys from messh."""

from __future__ import annotations

import asyncio
import json
import re
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, Mapping, Optional, Protocol, Sequence, Tuple, Union
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import _wba
from .client import __version__
from .errors import VerifyError

try:  # FastAPI injects the request into current_agent by this annotation
    from starlette.requests import Request as _Request
except ImportError:  # starlette is optional: pip install "messh-sdk[fastapi]"
    _Request = object

__all__ = ["Agent", "Verifier", "VerifyError", "MemoryNonceStore", "NonceStore", "MesshAuthMiddleware", "current_agent", "ACCEPT_SIGNATURE"]

ACCEPT_SIGNATURE = 'sig1=("@method" "@authority" "@path" "signature-agent");keyid;created;expires;nonce;alg="ed25519";tag="web-bot-auth"'
_IDENTITY = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,28}[a-z0-9])$")

# Directory cache policy, the same in every messh SDK.
_MIN_REFRESH = 30       # an unknown keyid refetches its signer's directory at most this often (s)
_RETRY_AFTER = 5        # while messh is unreachable, retry a directory at most this often (s)
_MAX_ENTRIES = 10_000   # directories kept at most
_STRIPES = 64           # fetch locks: one fetch per directory at a time
MAX_BODY_BYTES = 1 << 20  # default limit on request bodies MesshAuthMiddleware reads
_UNSET = object()       # no good answer yet (None means: no such identity)


class _Entry:
    """dir is the last good answer (None: no such identity), fetched at ``at``; failed_at is the last failed fetch."""

    __slots__ = ("dir", "at", "failed_at")

    def __init__(self, dir, at, failed_at=None):
        self.dir, self.at, self.failed_at = dir, at, failed_at
Headers = Union[Mapping[str, str], Iterable[Tuple[str, str]]]


@dataclass(frozen=True)
class Agent:
    identity: str      # messh username, e.g. "mukul"
    key_name: str      # key name on messh, e.g. "laptop"
    key_id: str        # RFC 7638 thumbprint
    fingerprint: str   # SHA256:… of the SSH key
    agent_url: str     # Signature-Agent
    created: int       # unix seconds


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


class Verifier:
    """Create once and reuse; it caches key directories.

    >>> v = Verifier(trust=["mukul"])
    >>> agent = v.verify("GET", "https://api.example.com/hello", headers)
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
    ):
        if not trust:
            raise ValueError("trust is required, e.g. trust=['mukul'] or ['*']")
        self.trust = list(trust)
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
        self._cache: "OrderedDict[str, _Entry]" = OrderedDict()
        self._lock = threading.Lock()
        self._fetching = [threading.Lock() for _ in range(_STRIPES)]

    def verify(self, method: str, url: str, headers: Headers, body: bytes = b"") -> Agent:
        """Verify one request. ``url`` is the full request URL; the authority
        is the Host header if present, else the URL's host. Raises VerifyError."""
        h = _lower(headers)
        now = self._clock()
        sig_input, sig_header = h.get("signature-input"), h.get("signature")
        if not sig_input or not sig_header:
            raise _fail("missing_signature", "send Signature, Signature-Input and Signature-Agent (Web Bot Auth)")
        try:
            sp = _wba.pick_web_bot_auth(sig_input)
            sig = _wba.signature_bytes(sig_header, sp.label)
        except ValueError as e:
            raise _fail("bad_signature", str(e))
        for c in ("@method", "@authority", "@path", "signature-agent"):
            if c not in sp.components:
                raise _fail("bad_signature", "%s must be covered" % c)
        u = urlsplit(url)
        if u.query and "@query" not in sp.components:
            raise _fail("bad_signature", "@query must be covered when the URL has a query")
        if "signature-agent" not in h:
            raise _fail("bad_signature", "Signature-Agent header is missing")
        try:
            agent_url = _wba.parse_agent(h["signature-agent"], sp.label)
        except ValueError as e:
            raise _fail("bad_signature", str(e))
        if sp.params.get("alg", "ed25519") != "ed25519":
            raise _fail("bad_signature", "alg %r is not supported" % sp.params["alg"])

        body = body or b""
        if "content-digest" in sp.components:
            if h.get("content-digest") != _wba.content_digest(body):
                raise _fail("digest_mismatch", "the body doesn't match Content-Digest")
        elif body:
            raise _fail("bad_signature", "a request body must be covered by content-digest")

        try:
            created = int(sp.params["created"])
        except (KeyError, ValueError):
            raise _fail("bad_signature", "created is required")
        if abs(now - created) > self.max_skew:
            raise _fail("clock_skew", "created is %ds from the server clock" % int(now - created))
        if "expires" in sp.params:
            try:
                expires = int(sp.params["expires"])
            except ValueError:
                raise _fail("clock_skew", "signature expired")
            if now > expires or expires - created > _wba.MAX_LIFETIME:
                raise _fail("clock_skew", "signature expired")
        nonce = sp.params.get("nonce")
        if not nonce:
            raise _fail("bad_signature", "nonce is required")

        identity = self._identity(agent_url)
        # Before any fetch: callers outside the trust list can't make this API fetch directories.
        if "*" not in self.trust and identity not in self.trust:
            raise _fail("untrusted", "%s is not in this API's trust list" % identity, 403)
        kid = sp.params.get("keyid", "")
        key, pub = self._lookup(agent_url, identity, kid)

        values = {
            "@method": method.upper(),
            "@authority": (h.get("host") or u.netloc).lower(),
            "@path": u.path or "/",
            "@query": "?" + u.query,
        }
        comps = []
        for c in sp.components:
            if c in values:
                comps.append((c, values[c]))
            elif c.startswith("@"):
                raise _fail("bad_signature", "unsupported component %s" % c)
            elif c in h:
                comps.append((c, h[c]))
            else:
                raise _fail("bad_signature", "covered header %s is missing" % c)
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, _wba.base(comps, sp.raw))
        except InvalidSignature:
            raise _fail("bad_signature", "the signature doesn't match the request")
        if not self.nonces.add(agent_url + " " + nonce, 2 * self.max_skew):
            raise _fail("nonce_replayed", "this signature was already accepted once")
        return Agent(identity, key.get("messh_name", ""), kid, key.get("messh_fingerprint", ""), agent_url, created)

    async def averify(self, method: str, url: str, headers: Headers, body: bytes = b"") -> Agent:
        """Async verify; the directory fetch runs in a thread."""
        return await asyncio.to_thread(self.verify, method, url, headers, body)

    def _identity(self, agent_url: str) -> str:
        u = urlsplit(agent_url)
        if not u.scheme or not u.netloc:
            raise _fail("bad_signature", "Signature-Agent is not a URL")
        if "%s://%s" % (u.scheme, u.netloc) not in self._registries:
            raise _fail("untrusted", "Signature-Agent %s is not a messh registry this API accepts" % agent_url, 403)
        ident = u.path.strip("/")
        if not _IDENTITY.match(ident):
            raise _fail("unknown_key", "Signature-Agent must be <registry>/<user>")
        return ident

    def _lookup(self, agent_url: str, identity: str, kid: str):
        """The signer's (jwk, public key) for kid. Directories are cached for
        cache_ttl; an unknown kid refetches at most every 30 s (so a key
        published a moment ago works), unknown identities are remembered the
        same way, one fetch per directory runs at a time, and while messh is
        unreachable cached keys keep working for stale_if_error."""

        def find(d):
            for k in d.get("keys", []) if isinstance(d, dict) else []:
                if k.get("kid") == kid:
                    p = _wba.jwk_public_key(k)
                    if p:
                        return k, p
            return None

        def found(d):
            hit = find(d)
            if hit:
                return hit
            if d is None:
                raise _fail("unknown_key", "there's no messh identity at %s" % agent_url)
            raise _fail("unknown_key", "keyid %s is not an active key of %s; publish it with messh publish" % (kid, agent_url))

        if isinstance(self._directory, dict):
            return found(self._directory)
        if callable(self._directory):
            return found(self._directory(agent_url, identity))
        now = self._clock()
        e = self._entry(agent_url)
        if e and e.at is not None and now - e.at < self.cache_ttl:
            hit = find(e.dir)
            if hit:
                return hit
            if now - e.at < _MIN_REFRESH:
                return found(e.dir)
        with self._fetching[hash(agent_url) % _STRIPES]:
            e = self._entry(agent_url)
            if e and e.at is not None and now - e.at < min(self.cache_ttl, _MIN_REFRESH):
                return found(e.dir)  # fetched by another thread while this one waited
            if not (e and e.failed_at is not None and now - e.failed_at < _RETRY_AFTER):
                d, ok = self._fetch(agent_url, identity)
                if ok:
                    self._store(agent_url, _Entry(d, now))
                    return found(d)
                e = self._store(agent_url, _Entry(e.dir if e else _UNSET, e.at if e else None, now))
        # messh is unreachable: keep verifying with the cached directory for a while.
        if e and e.at is not None and e.dir is not _UNSET and now - e.at < self.stale_if_error:
            return found(e.dir)
        raise _fail("unknown_key", "key directory for %s is unavailable" % agent_url)

    def _fetch(self, agent_url: str, identity: str):
        """(directory, True); (None, True) for no such identity; (None, False) if messh couldn't answer."""
        u = urlsplit(agent_url)
        url = self._registries["%s://%s" % (u.scheme, u.netloc)] + "/" + identity + _wba.DIRECTORY_PATH
        req = urllib.request.Request(url, headers={
            "Accept": "application/http-message-signatures-directory+json, application/json",
            "User-Agent": "messh-python/" + __version__,
        })
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                d = json.loads(r.read(1 << 20))
            return (d, True) if isinstance(d, dict) and isinstance(d.get("keys"), list) else (None, False)
        except urllib.error.HTTPError as e:
            return None, e.code == 404
        except (OSError, ValueError):
            return None, False

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
