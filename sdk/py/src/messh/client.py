"""Sign HTTP requests as a messh identity (Web Bot Auth)."""

from __future__ import annotations

import base64
import json as _json
import os
import re
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Dict, Mapping, Optional, Union
from urllib.parse import urlsplit

from . import _wba
from .errors import MesshError
from .keys import KeySource, key_env, key_file, resolve

__version__ = "0.1.0"
DEFAULT_REGISTRY = "https://messh.io"
_IDENTITY = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,28}[a-z0-9])$")


@dataclass
class Response:
    status: int
    headers: Dict[str, str]
    body: bytes

    @property
    def ok(self) -> bool:
        return self.status < 400

    def json(self):
        return _json.loads(self.body)

    def text(self) -> str:
        return self.body.decode()


@dataclass(frozen=True)
class PublishedKey:
    """This client's key as messh lists it: what an API will see. See :meth:`Client.whoami`."""

    identity: str      # messh username, e.g. "mukul"
    key_name: str      # the key's name on messh, e.g. "build-bot"
    key_id: str        # RFC 7638 thumbprint, sent as keyid
    fingerprint: str   # SHA256:… of the SSH key
    agent_url: str     # Signature-Agent: <registry>/<identity>


class Client:
    """Signs requests as ``identity`` (a messh username such as ``"mukul"``).

    >>> client = Client("mukul", key=key_file("~/.ssh/id_ed25519"))
    >>> client.get("https://api.example.com/hello").json()
    """

    def __init__(
        self,
        identity: str,
        *,
        key: Optional[KeySource] = None,
        registry: str = DEFAULT_REGISTRY,
        expires_in: int = 60,
        timeout: float = 30.0,
        clock: Optional[Callable[[], float]] = None,
        nonce: Optional[Callable[[], str]] = None,
    ):
        if not _IDENTITY.match(identity or ""):
            raise MesshError("invalid_identity", "%r is not a messh username" % identity)
        if not registry.startswith(("https://", "http://")):
            raise MesshError("invalid_option", "registry must be an http(s) URL")
        if not 1 <= expires_in <= _wba.MAX_LIFETIME:
            raise MesshError("invalid_option", "expires_in must be 1..300 seconds")
        self.identity = identity
        self.registry = registry.rstrip("/")
        self.expires_in = expires_in
        self.timeout = timeout
        self._signer = resolve(key if key is not None else key_file(os.path.join("~", ".ssh", "id_ed25519")))
        self._clock = clock or time.time
        self._nonce = nonce or (lambda: secrets.token_urlsafe(16))

    @property
    def agent(self) -> str:
        """Signature-Agent URL: ``<registry>/<identity>``."""
        return "%s/%s" % (self.registry, self.identity)

    @property
    def key_id(self) -> str:
        """keyid sent in Signature-Input (RFC 7638 JWK thumbprint)."""
        return _wba.thumbprint(self._signer.public_key())

    @property
    def fingerprint(self) -> str:
        """SSH fingerprint of the signing key (SHA256:…), as ``messh keys`` and ssh-keygen -l print it."""
        return _wba.fingerprint(self._signer.public_key())

    @classmethod
    def from_env(cls, **overrides) -> "Client":
        """A client from the environment, for agents and CI: MESSH_IDENTITY
        (required), MESSH_KEY (PEM, or base64 of PEM or PKCS#8 DER) or
        MESSH_KEY_FILE (default ~/.ssh/id_ed25519), and MESSH_REGISTRY.
        Keyword arguments win over the environment."""
        env = os.environ
        identity = overrides.pop("identity", None) or env.get("MESSH_IDENTITY")
        if not identity:
            raise MesshError("invalid_identity", "set MESSH_IDENTITY to your messh username, or pass identity")
        if overrides.get("key") is None:
            if env.get("MESSH_KEY"):
                overrides["key"] = key_env("MESSH_KEY")
            elif env.get("MESSH_KEY_FILE"):
                overrides["key"] = key_file(env["MESSH_KEY_FILE"])
        if not overrides.get("registry") and env.get("MESSH_REGISTRY"):
            overrides["registry"] = env["MESSH_REGISTRY"]
        return cls(identity, **overrides)

    def whoami(self) -> PublishedKey:
        """Check that this client's key is published and active on messh, and
        how APIs will see it. Run it once at startup: it turns the most common
        setup mistake (an unpublished key, so every API answers 401
        unknown_key) into a clear error. Raises MesshError not_published or
        registry_unreachable."""
        url = self.agent + _wba.DIRECTORY_PATH
        req = urllib.request.Request(url, headers={
            "Accept": "application/http-message-signatures-directory+json, application/json",
            "User-Agent": "messh-python/" + __version__,
        })
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                directory = _json.loads(r.read(1 << 20))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise MesshError("not_published", "%s has no user %s; sign up, then publish this key (%s) with messh publish"
                                 % (self.registry, self.identity, self.fingerprint)) from e
            raise MesshError("registry_unreachable", "%s answered HTTP %d" % (url, e.code)) from e
        except (OSError, ValueError) as e:
            raise MesshError("registry_unreachable", "can't reach %s: %s" % (self.registry, e)) from e
        for k in directory.get("keys", []) if isinstance(directory, dict) else []:
            if k.get("kid") == self.key_id:
                return PublishedKey(self.identity, k.get("messh_name", ""), self.key_id, k.get("messh_fingerprint") or self.fingerprint, self.agent)
        raise MesshError("not_published", "this key (%s) isn't an active key of %s; publish it with messh publish --key <key>.pub --name <name>"
                         % (self.fingerprint, self.agent))

    def sign(self, method: str, url: str, body: Union[bytes, str, None] = None, host: Optional[str] = None) -> Dict[str, str]:
        """Return the headers to add: Signature-Agent, Signature-Input,
        Signature and, with a body, Content-Digest. ``host`` overrides the
        authority if you send a different Host header than the URL's."""
        u = urlsplit(url)
        if not u.scheme or not u.netloc:
            raise MesshError("sign_failed", "url must be absolute")
        agent_header = _wba.quote(self.agent)
        comps = [
            ("@method", method.upper()),
            ("@authority", (host or u.netloc).lower()),
            ("@path", u.path or "/"),
        ]
        if u.query:
            comps.append(("@query", "?" + u.query))
        headers: Dict[str, str] = {"Signature-Agent": agent_header}
        if body:
            data = body.encode() if isinstance(body, str) else body
            headers["Content-Digest"] = _wba.content_digest(data)
            comps.append(("content-digest", headers["Content-Digest"]))
        comps.append(("signature-agent", agent_header))
        created = int(self._clock())
        params = _wba.params([c for c, _ in comps], created, created + self.expires_in, self.key_id, self._nonce())
        try:
            sig = self._signer.sign(_wba.base(comps, params))
        except Exception as e:
            raise MesshError("sign_failed", str(e)) from e
        headers["Signature-Input"] = "%s=%s" % (_wba.LABEL, params)
        headers["Signature"] = "%s=:%s:" % (_wba.LABEL, base64.b64encode(sig).decode())
        return headers

    def request(
        self,
        method: str,
        url: str,
        *,
        json=None,
        data: Union[bytes, str, None] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Response:
        """Sign and send with the standard library. HTTP errors are returned, not raised."""
        hdrs = dict(headers or {})
        if json is not None:
            data = _json.dumps(json, separators=(",", ":"))
            hdrs.setdefault("Content-Type", "application/json")
        body = data.encode() if isinstance(data, str) else data
        hdrs.update(self.sign(method, url, body))
        hdrs.setdefault("User-Agent", "messh-python/" + __version__)
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method.upper())
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return Response(r.status, dict(r.headers), r.read())
        except urllib.error.HTTPError as e:
            return Response(e.code, dict(e.headers), e.read())

    def get(self, url: str, **kw) -> Response:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> Response:
        return self.request("POST", url, **kw)


def _httpx_auth():
    import httpx

    class MesshAuth(httpx.Auth):
        """httpx auth: ``httpx.Client(auth=MesshAuth(client))``."""

        requires_request_body = True

        def __init__(self, client: Client):
            self.client = client

        def auth_flow(self, request):
            host = request.headers.get("host")
            for k, v in self.client.sign(request.method, str(request.url), request.content or None, host).items():
                request.headers[k] = v
            yield request

    return MesshAuth


def __getattr__(name):  # lazy so httpx stays optional
    if name == "MesshAuth":
        return _httpx_auth()
    raise AttributeError(name)
