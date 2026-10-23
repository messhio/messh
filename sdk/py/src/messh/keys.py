"""Key sources. Keys are used locally; they never go to messh."""

from __future__ import annotations

import base64
import os
import socket
from typing import Callable, Optional, Protocol, Union, runtime_checkable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import _wba
from .errors import MesshError


@runtime_checkable
class Signer(Protocol):
    """Implement this to sign in a KMS, HSM or ssh-agent."""

    def public_key(self) -> bytes:
        """Raw 32-byte Ed25519 public key."""

    def sign(self, message: bytes) -> bytes:
        """64-byte Ed25519 signature over message."""


KeySource = Union[Signer, Callable[[], Signer]]


class _LocalSigner:
    __slots__ = ("_k",)

    def __init__(self, key: Ed25519PrivateKey):
        self._k = key

    def public_key(self) -> bytes:
        return self._k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def sign(self, message: bytes) -> bytes:
        return self._k.sign(message)

    def __repr__(self) -> str:
        return "messh.Signer(ed25519)"


def _parse(data: bytes) -> _LocalSigner:
    try:
        if b"OPENSSH PRIVATE KEY" in data:
            key = serialization.load_ssh_private_key(data, password=None)
        elif b"-----BEGIN" in data:
            key = serialization.load_pem_private_key(data, password=None)
        else:
            key = serialization.load_der_private_key(data, password=None)
    except TypeError as e:  # raised for encrypted keys without a password
        raise MesshError("invalid_key", "passphrase-protected key; load it into ssh-agent (ssh-add) and use ssh_agent()") from e
    except ValueError as e:
        raise MesshError("invalid_key", str(e)) from e
    if not isinstance(key, Ed25519PrivateKey):
        raise MesshError("invalid_key", "need an Ed25519 key")
    return _LocalSigner(key)


def key_file(path: Union[str, os.PathLike]) -> Callable[[], Signer]:
    """Unencrypted ssh-ed25519 OpenSSH key or PKCS#8 PEM, e.g. ~/.ssh/id_ed25519."""

    def load() -> Signer:
        try:
            with open(os.path.expanduser(path), "rb") as f:
                return _parse(f.read())
        except OSError as e:
            hint = "; create one with ssh-keygen -t ed25519, then messh publish" if isinstance(e, FileNotFoundError) else ""
            raise MesshError("invalid_key", "read %s: %s%s" % (path, e.strerror or e, hint)) from e

    return load


def ssh_agent(fingerprint: Optional[str] = None, socket_path: Optional[str] = None) -> Callable[[], Signer]:
    """A key held by ssh-agent, such as a passphrase-protected key you added
    with ssh-add. The private key stays in the agent. With several Ed25519
    keys loaded, pass the fingerprint (SHA256:…) of the one you published."""

    def load() -> Signer:
        path = socket_path or os.environ.get("SSH_AUTH_SOCK") or (r"\\.\pipe\openssh-ssh-agent" if os.name == "nt" else "")
        if not path:
            raise MesshError("invalid_key", 'ssh-agent isn\'t running (SSH_AUTH_SOCK is not set); start it: eval "$(ssh-agent)" && ssh-add')
        try:
            reply = _agent_call(path, bytes([_AGENTC_REQUEST_IDENTITIES]))
            if reply[:1] != bytes([_AGENT_IDENTITIES_ANSWER]):
                raise OSError("it wouldn't list its keys")
            keys = []
            r = _Reader(reply[1:])
            for _ in range(r.u32()):
                blob, _comment = r.string(), r.string()
                b = _Reader(blob)
                if b.string() == b"ssh-ed25519":
                    pub = b.string()
                    keys.append((blob, pub, _wba.fingerprint(pub)))
        except (OSError, ValueError) as e:
            raise MesshError("invalid_key", "ssh-agent at %s: %s" % (path, e)) from e
        listed = ", ".join(k[2] for k in keys)
        if not keys:
            raise MesshError("invalid_key", "ssh-agent has no Ed25519 keys; add yours with ssh-add ~/.ssh/id_ed25519")
        pick = [k for k in keys if k[2] == fingerprint] if fingerprint else keys
        if not pick:
            raise MesshError("invalid_key", "ssh-agent has no key %s; it has %s" % (fingerprint, listed))
        if len(pick) > 1:
            raise MesshError("invalid_key", "ssh-agent has %d Ed25519 keys; choose one with ssh_agent(fingerprint=...): %s" % (len(keys), listed))
        return _AgentSigner(path, pick[0][0], pick[0][1])

    return load


# ssh-agent protocol (draft-miller-ssh-agent): uint32 length, message type, payload.
_AGENTC_REQUEST_IDENTITIES, _AGENT_IDENTITIES_ANSWER, _AGENTC_SIGN_REQUEST, _AGENT_SIGN_RESPONSE = 11, 12, 13, 14


class _AgentSigner:
    __slots__ = ("_path", "_blob", "_pub")

    def __init__(self, path: str, blob: bytes, pub: bytes):
        self._path, self._blob, self._pub = path, blob, pub

    def public_key(self) -> bytes:
        return self._pub

    def sign(self, message: bytes) -> bytes:
        msg = bytes([_AGENTC_SIGN_REQUEST]) + _wba.ssh_string(self._blob) + _wba.ssh_string(message) + bytes(4)
        reply = _agent_call(self._path, msg)
        if reply[:1] != bytes([_AGENT_SIGN_RESPONSE]):
            raise RuntimeError("ssh-agent refused to sign; is the key still loaded (ssh-add -l)?")
        sig = _Reader(_Reader(reply[1:]).string())
        if sig.string() != b"ssh-ed25519":
            raise RuntimeError("ssh-agent returned an unexpected signature")
        raw = sig.string()
        if len(raw) != 64:
            raise RuntimeError("ssh-agent returned an unexpected signature")
        return raw

    def __repr__(self) -> str:
        return "messh.Signer(ssh-agent)"


class _Reader:
    def __init__(self, b: bytes):
        self.b, self.o = b, 0

    def u32(self) -> int:
        if self.o + 4 > len(self.b):
            raise ValueError("malformed ssh-agent reply")
        self.o += 4
        return int.from_bytes(self.b[self.o - 4:self.o], "big")

    def string(self) -> bytes:
        n = self.u32()
        if self.o + n > len(self.b):
            raise ValueError("malformed ssh-agent reply")
        self.o += n
        return self.b[self.o - n:self.o]


def _agent_call(path: str, msg: bytes) -> bytes:
    def frame(read: Callable[[int], bytes]) -> bytes:
        buf = b""
        while len(buf) < 4 or len(buf) < 4 + int.from_bytes(buf[:4], "big"):
            chunk = read(65536)
            if not chunk:
                raise OSError("ssh-agent closed the connection")
            buf += chunk
        return buf[4:4 + int.from_bytes(buf[:4], "big")]

    if os.name == "nt" and path.startswith("\\\\.\\pipe\\"):
        with open(path, "r+b", buffering=0) as f:
            f.write(_wba.ssh_string(msg))
            return frame(f.read)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(30)
        s.connect(path)
        s.sendall(_wba.ssh_string(msg))
        return frame(s.recv)


def key_env(name: str) -> Callable[[], Signer]:
    """Key in an environment variable: PEM text, or base64 of PEM or PKCS#8 DER."""

    def load() -> Signer:
        v = os.environ.get(name, "").strip()
        if not v:
            raise MesshError("invalid_key", "environment variable %s is empty" % name)
        if "-----BEGIN" in v:
            return _parse(v.encode())
        try:
            return _parse(base64.b64decode(v, validate=True))
        except ValueError as e:
            raise MesshError("invalid_key", "%s is neither PEM nor base64" % name) from e

    return load


def key_seed(seed: bytes) -> Callable[[], Signer]:
    """Raw 32-byte Ed25519 seed."""

    def load() -> Signer:
        if len(seed) != 32:
            raise MesshError("invalid_key", "seed must be 32 bytes")
        return _LocalSigner(Ed25519PrivateKey.from_private_bytes(seed))

    return load


def resolve(source: KeySource) -> Signer:
    signer = source if isinstance(source, Signer) else source()
    if len(signer.public_key()) != 32:
        raise MesshError("invalid_key", "signer has no Ed25519 public key")
    return signer
