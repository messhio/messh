"""Production behavior: environment config, whoami, ssh-agent, the verifier's
directory cache policy and body limits. Runs against a local fake registry."""

import asyncio
import base64
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from messh import Client, MesshError, PublishedKey, key_file, ssh_agent
from messh._wba import fingerprint
from messh.verify import MesshAuthMiddleware, Verifier, VerifyError

VEC = pathlib.Path(__file__).resolve().parents[3] / "spec" / "vectors"
DOC = json.loads((VEC / "web-bot-auth.json").read_text())
OPENSSH = VEC / DOC["key"]["files"]["openssh"]
JWK = DOC["key"]["jwk"]


class Registry:
    """A fake registry: dirs[identity] is a directory, None for 404, "error" for 500."""

    def __init__(self, dirs):
        self.dirs, self.hits = dirs, []
        reg = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                ident = self.path.split("/")[1]
                reg.hits.append(ident)
                time.sleep(0.05)  # long enough for concurrent misses to overlap
                d = reg.dirs.get(ident)
                if d == "error":
                    self.send_response(500)
                    self.end_headers()
                elif d is None:
                    self.send_response(404)
                    self.end_headers()
                else:
                    body = json.dumps(d).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class Setup:
    """A signer and verifier sharing a fake clock, against a fake registry."""

    def __init__(self, dirs, **opts):
        self.reg = Registry(dirs)
        self.t = 1_800_000_000
        opts.setdefault("trust", ["*"])
        self.verifier = Verifier(registries=[self.reg.url], clock=lambda: self.t, **opts)

    def send(self, identity):
        c = Client(identity, key=key_file(OPENSSH), registry=self.reg.url, clock=lambda: self.t)
        url = "https://api.example/hello"
        try:
            self.verifier.verify("GET", url, c.sign("GET", url))
            return "ok"
        except VerifyError as e:
            return e.code


class ClientTests(unittest.TestCase):
    def test_fingerprint(self):
        c = Client("mukul", key=key_file(OPENSSH))
        self.assertEqual(c.fingerprint, JWK["messh_fingerprint"])
        self.assertEqual(fingerprint(base64.urlsafe_b64decode(JWK["x"] + "=")), JWK["messh_fingerprint"])

    def test_from_env(self):
        env = {"MESSH_IDENTITY": "mukul", "MESSH_KEY_FILE": str(OPENSSH), "MESSH_REGISTRY": "https://registry.example/"}
        with mock.patch.dict(os.environ, env, clear=True):
            c = Client.from_env()
            self.assertEqual((c.identity, c.key_id, c.agent), ("mukul", JWK["kid"], "https://registry.example/mukul"))
        pkcs8 = base64.b64encode((VEC / DOC["key"]["files"]["pkcs8"]).read_bytes()).decode()
        with mock.patch.dict(os.environ, {"MESSH_KEY": pkcs8}, clear=True):
            c = Client.from_env(identity="acme-ci")
            self.assertEqual((c.identity, c.key_id), ("acme-ci", JWK["kid"]))
            with self.assertRaises(MesshError) as e:
                Client.from_env()
            self.assertEqual(e.exception.code, "invalid_identity")
            self.assertIn("MESSH_IDENTITY", str(e.exception))

    def test_whoami(self):
        reg = Registry({"mukul": {"keys": [JWK]}, "empty": {"keys": []}})
        try:
            as_ = lambda ident: Client(ident, key=key_file(OPENSSH), registry=reg.url)  # noqa: E731
            self.assertEqual(as_("mukul").whoami(), PublishedKey("mukul", "sdk-test", JWK["kid"], JWK["messh_fingerprint"], reg.url + "/mukul"))
            for ident, want in (("nobody", "no user nobody"), ("empty", JWK["messh_fingerprint"])):
                with self.assertRaises(MesshError) as e:
                    as_(ident).whoami()
                self.assertEqual(e.exception.code, "not_published")
                self.assertIn(want, str(e.exception))
        finally:
            reg.close()
        with self.assertRaises(MesshError) as e:
            Client("mukul", key=key_file(OPENSSH), registry=reg.url).whoami()
        self.assertEqual(e.exception.code, "registry_unreachable")

    def test_missing_key_file_says_how_to_fix_it(self):
        with self.assertRaises(MesshError) as e:
            Client("mukul", key=key_file("/nonexistent/id_ed25519"))
        self.assertIn("ssh-keygen -t ed25519", str(e.exception))


class CacheTests(unittest.TestCase):
    def test_untrusted_callers_never_trigger_a_fetch(self):
        s = Setup({"mukul": {"keys": [JWK]}}, trust=["alice"])
        try:
            self.assertEqual(s.send("mukul"), "untrusted")
            self.assertEqual(s.reg.hits, [])
        finally:
            s.reg.close()

    def test_unknown_identities_are_remembered_for_30s(self):
        s = Setup({})
        try:
            self.assertEqual(s.send("ghost"), "unknown_key")
            s.t += 10
            self.assertEqual(s.send("ghost"), "unknown_key")
            self.assertEqual(len(s.reg.hits), 1)
            s.t += 21
            s.send("ghost")
            self.assertEqual(len(s.reg.hits), 2)
        finally:
            s.reg.close()

    def test_new_keys_work_within_30s(self):
        s = Setup({"mukul": {"keys": []}})
        try:
            self.assertEqual(s.send("mukul"), "unknown_key")
            s.reg.dirs["mukul"] = {"keys": [JWK]}
            s.t += 10
            self.assertEqual(s.send("mukul"), "unknown_key")
            s.t += 21
            self.assertEqual(s.send("mukul"), "ok")
            s.t += 60
            self.assertEqual(s.send("mukul"), "ok")
            self.assertEqual(len(s.reg.hits), 2)
        finally:
            s.reg.close()

    def test_404_is_never_stale_but_an_outage_is(self):
        s = Setup({"mukul": {"keys": [JWK]}})
        try:
            self.assertEqual(s.send("mukul"), "ok")
            s.reg.dirs["mukul"] = "error"
            s.t += 301
            self.assertEqual(s.send("mukul"), "ok")
            s.t += 2
            self.assertEqual(s.send("mukul"), "ok")
            self.assertEqual(len(s.reg.hits), 2, "no retry within 5 s of a failure")
            s.reg.dirs["mukul"] = None
            s.t += 5
            self.assertEqual(s.send("mukul"), "unknown_key")
        finally:
            s.reg.close()

    def test_concurrent_misses_share_one_fetch(self):
        s = Setup({"mukul": {"keys": [JWK]}})
        try:
            with ThreadPoolExecutor(4) as pool:
                self.assertEqual(list(pool.map(lambda _: s.send("mukul"), range(4))), ["ok"] * 4)
            self.assertEqual(len(s.reg.hits), 1)
        finally:
            s.reg.close()

    def test_middleware_rejects_big_bodies(self):
        async def app(scope, receive, send):
            raise AssertionError("not reached")

        mw = MesshAuthMiddleware(app, trust=["*"], directory={"keys": [JWK]}, max_body_bytes=8)
        out, pending = [], [{"type": "http.request", "body": b"01234", "more_body": True},
                            {"type": "http.request", "body": b"56789", "more_body": False}]

        async def receive():
            return pending.pop(0)

        async def send(m):
            out.append(m)

        scope = {"type": "http", "method": "POST", "scheme": "https", "path": "/x", "query_string": b"", "headers": [(b"host", b"api.example")]}
        asyncio.run(mw(scope, receive, send))
        self.assertEqual(out[0]["status"], 413)
        self.assertEqual(json.loads(out[1]["body"])["error"], "body_too_large")


@unittest.skipUnless(shutil.which("ssh-agent") and shutil.which("ssh-add"), "ssh-agent not installed")
class SSHAgentTests(unittest.TestCase):
    def test_ssh_agent_signs_like_the_key_file(self):
        d = tempfile.mkdtemp(prefix="messh-agent-")
        sock, key = os.path.join(d, "agent.sock"), os.path.join(d, "id")
        shutil.copy(OPENSSH, key)
        os.chmod(key, 0o600)
        agent = subprocess.Popen(["ssh-agent", "-D", "-a", sock], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(50):
                if os.path.exists(sock):
                    break
                time.sleep(0.05)
            subprocess.run(["ssh-add", key], env={**os.environ, "SSH_AUTH_SOCK": sock}, check=True, capture_output=True)
            c = DOC["sign"][0]
            client = Client("mukul", key=ssh_agent(socket_path=sock), registry="https://registry.example",
                            clock=lambda: c["created"], nonce=lambda: c["nonce"])
            self.assertEqual(client.sign(c["method"], c["url"], c.get("body") or None), c["expected_headers"])
            self.assertEqual(client.fingerprint, JWK["messh_fingerprint"])
            with self.assertRaises(MesshError) as e:
                Client("mukul", key=ssh_agent(fingerprint="SHA256:nope", socket_path=sock))
            self.assertIn(JWK["messh_fingerprint"], str(e.exception))
        finally:
            agent.kill()
            agent.wait()


if __name__ == "__main__":
    unittest.main()
