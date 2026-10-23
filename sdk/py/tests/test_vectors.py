import asyncio
import base64
import json
import os
import pathlib
import unittest

from messh import Client, MesshError, key_env, key_file, key_seed
from messh.verify import MesshAuthMiddleware, Verifier, VerifyError

try:
    import fastapi
except ImportError:
    fastapi = None

VEC = pathlib.Path(__file__).resolve().parents[3] / "spec" / "vectors"
DOC = json.loads((VEC / "web-bot-auth.json").read_text())
OPENSSH = VEC / DOC["key"]["files"]["openssh"]


class SignVectors(unittest.TestCase):
    def test_sign(self):
        for c in DOC["sign"]:
            cl = Client("mukul", key=key_file(OPENSSH), registry="https://registry.example",
                        clock=lambda c=c: c["created"], nonce=lambda c=c: c["nonce"])
            got = cl.sign(c["method"], c["url"], c.get("body") or None)
            self.assertEqual(got, c["expected_headers"], c["name"])

    def test_key_sources(self):
        want = DOC["key"]["jwk"]["kid"]
        pkcs8 = (VEC / DOC["key"]["files"]["pkcs8"]).read_bytes()
        os.environ["MESSH_TEST_KEY"] = base64.b64encode(pkcs8).decode()
        for name, src in {
            "openssh": key_file(OPENSSH),
            "pkcs8": key_file(VEC / DOC["key"]["files"]["pkcs8"]),
            "env": key_env("MESSH_TEST_KEY"),
            "seed": key_seed(bytes.fromhex(DOC["key"]["seed_hex"])),
        }.items():
            self.assertEqual(Client("mukul", key=src).key_id, want, name)
        with self.assertRaises(MesshError):
            Client("mukul", key=key_file(VEC / DOC["key"]["files"]["public"]))
        with self.assertRaises(MesshError):
            Client("Not A User", key=key_file(OPENSSH))


def verifier(case, **kw):
    kw.setdefault("trust", ["*"])
    kw.setdefault("registries", ["https://registry.example"])
    return Verifier(directory={"keys": case["directory_keys"]}, clock=lambda: case["now"], **kw)


class VerifyVectors(unittest.TestCase):
    def test_verify(self):
        for c in DOC["verify"]:
            v = verifier(c)
            args = (c["method"], c["url"], c["headers"], (c.get("body") or "").encode())
            try:
                a = v.verify(*args)
                got = "ok"
            except VerifyError as e:
                got = e.code
            self.assertEqual(got, c["expect"], c["name"])
            if got == "ok":
                self.assertEqual((a.identity, a.key_name), ("mukul", "sdk-test"))
                with self.assertRaises(VerifyError) as e:
                    v.verify(*args)
                self.assertEqual(e.exception.code, "nonce_replayed")

    def test_trust_and_registry(self):
        c = DOC["verify"][0]
        args = (c["method"], c["url"], c["headers"])
        with self.assertRaises(VerifyError) as e:
            verifier(c, trust=["alice"]).verify(*args)
        self.assertEqual((e.exception.code, e.exception.status), ("untrusted", 403))
        with self.assertRaises(VerifyError) as e:
            verifier(c, registries=None).verify(*args)
        self.assertEqual(e.exception.code, "untrusted")
        with self.assertRaises(ValueError):
            Verifier(trust=[])

    def test_asgi_middleware(self):
        c = next(x for x in DOC["verify"] if x["name"] == "ok-post")
        seen = {}

        async def app(scope, receive, send):
            msg = await receive()
            seen["agent"], seen["body"] = scope["state"]["messh_agent"].identity, msg["body"]
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        mw = MesshAuthMiddleware(app, verifier=verifier(c))
        scope, host = asgi_scope(c)
        out = asgi_call(mw, scope, c["body"].encode())
        self.assertEqual(out[0]["status"], 200)
        self.assertEqual(seen, {"agent": "mukul", "body": c["body"].encode()})
        out = asgi_call(mw, {**scope, "headers": [(b"host", host.encode())]}, c["body"].encode())
        self.assertEqual(out[0]["status"], 401)

    @unittest.skipUnless(fastapi, "needs fastapi (sdk/test.sh installs it)")
    def test_fastapi_current_agent(self):
        from fastapi import Depends, FastAPI
        from messh.verify import Agent, current_agent

        c = next(x for x in DOC["verify"] if x["name"] == "ok-post")
        api = FastAPI()
        api.add_middleware(MesshAuthMiddleware, verifier=verifier(c))

        @api.post("/{rest:path}")
        def handler(agent: Agent = Depends(current_agent)):
            return {"caller": agent.identity, "key": agent.key_name}

        scope, _ = asgi_scope(c)
        out = asgi_call(api, scope, c["body"].encode())
        self.assertEqual(out[0]["status"], 200, out)
        self.assertEqual(json.loads(out[1]["body"]), {"caller": "mukul", "key": "sdk-test"})


def asgi_scope(case):
    host, path = case["url"].split("://", 1)[1].split("/", 1)
    return {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": case["method"], "scheme": "https",
            "path": "/" + path, "raw_path": ("/" + path).encode(), "root_path": "", "query_string": b"",
            "server": (host, 443), "client": ("127.0.0.1", 50000),
            "headers": [(b"host", host.encode())] + [(k.lower().encode(), v.encode()) for k, v in case["headers"].items()]}, host


def asgi_call(app, scope, body):
    """Runs one request through an ASGI app; returns the messages it sent."""
    out, pending = [], [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        return pending.pop(0) if pending else {"type": "http.disconnect"}

    async def send(m):
        out.append(m)

    asyncio.run(app(scope, receive, send))
    return out


if __name__ == "__main__":
    unittest.main()
