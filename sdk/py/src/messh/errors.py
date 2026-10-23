class MesshError(Exception):
    """Client-side error. ``code`` is one of invalid_identity, invalid_key,
    invalid_option, sign_failed; from whoami(): not_published, registry_unreachable."""

    def __init__(self, code: str, message: str):
        super().__init__("%s: %s" % (code, message))
        self.code = code
        self.message = message


class VerifyError(Exception):
    """Verification failure. ``code`` and ``status`` follow the messh spec:
    missing_signature, bad_signature, digest_mismatch, clock_skew,
    nonce_replayed, unknown_key (401); untrusted (403); body_too_large (413)."""

    def __init__(self, code: str, message: str, status: int = 401):
        super().__init__("%s: %s" % (code, message))
        self.code = code
        self.message = message
        self.status = status

    def to_dict(self) -> dict:
        return {"error": self.code, "message": self.message}
