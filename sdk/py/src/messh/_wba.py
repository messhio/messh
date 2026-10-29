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
