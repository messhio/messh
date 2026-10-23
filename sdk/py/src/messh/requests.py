"""requests integration: ``requests.get(url, auth=MesshAuth(client))``."""

from __future__ import annotations

from requests.auth import AuthBase

from .client import Client


class MesshAuth(AuthBase):
    def __init__(self, client: Client):
        self.client = client

    def __call__(self, r):
        body = r.body.encode() if isinstance(r.body, str) else r.body
        r.headers.update(self.client.sign(r.method, r.url, body or None, r.headers.get("Host")))
        return r
