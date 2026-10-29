import json
import os
import unittest

from messh import Client, directory_response, key_seed
from messh import _sf
from messh.errors import VerifyError
from messh.httpsig import Message, component_value, sign_message, verify_message
from messh.verify import Verifier, verify_directory

DOC = json.load(open(os.path.join(os.path.dirname(__file__), "../../../spec/vectors/http-message-signatures.json")))


def message(m):
    body = m.get("body")
    return Message(m.get("method", ""), m.get("url", ""), headers=[tuple(h) for h in m["headers"]],
                   body=body.encode() if body is not None else None, status=m.get("status", 0),
                   request=message(m["request"]) if m.get("request") else None, trailers=[tuple(h) for h in m.get("trailers", [])],
                   request_target=m.get("request_target", ""))


def seed(name):
    return key_seed(bytes.fromhex(DOC["keys"][name]["seed_hex"]))


def pub(name):
    import base64
    x = DOC["keys"][name]["x"]
    return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))


class Vectors(unittest.TestCase):
    def test_structured_fields(self):
        for c in DOC["structured_fields"]:
            def run():
                if c["type"] == "dictionary":
                    return _sf.serialize_dictionary(_sf.parse_dictionary(c["input"])[0])
                if c["type"] == "list":
                    return _sf.serialize_list(_sf.parse_list(c["input"]))
                return _sf.serialize_item(_sf.parse_item(c["input"]))
            with self.subTest(c["name"]):
                if c.get("error"):
                    self.assertRaises(ValueError, run)
                else:
                    self.assertEqual(run(), c["canonical"])

    def test_components(self):
        for c in DOC["components"]:
            run = lambda: component_value(message(DOC["messages"][c["message"]]), c["component"], DOC["field_types"])
            with self.subTest(c["name"]):
                if c.get("error"):
                    self.assertRaises(ValueError, run)
                else:
                    self.assertEqual(run(), (c["identifier"], c["value"]))

    def test_sign(self):
        for c in DOC["sign"]:
            with self.subTest(c["name"]):
                s = sign_message(message(c["message"]), seed(c["key"])(), components=c["components"], label=c["label"],
                                 field_types=DOC["field_types"], **c["params"])
                self.assertEqual(s.base, c["expected_base"])
                self.assertEqual(s.headers, {k: c["expected_headers"][k] for k in ("Signature-Input", "Signature")})

    def test_verify(self):
        for c in DOC["verify"]:
            with self.subTest(c["name"]):
                keys = {kid: pub(name) for kid, name in c["keys"].items()}
                try:
                    v = verify_message(message(c["message"]), keys=keys, label=c.get("label"), tag=c.get("tag"), now=c["now"],
                                       max_age=c.get("max_age"), field_types=DOC["field_types"])
                    got = "ok"
                except VerifyError as e:
                    got = e.code
                self.assertEqual(got, c["expect"])
                if got == "ok":
                    self.assertEqual(v.label, c["expect_label"])

    def test_web_bot_auth(self):
        wba = DOC["web_bot_auth"]
        for c in wba["cases"]:
            with self.subTest(c["name"]):
                def directory(agent_url, _identity, dirs=c["directories"]):
                    names = dirs.get(agent_url)
                    if names is None:
                        return None
                    return {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": DOC["keys"][n]["x"], "kid": DOC["keys"][n]["thumbprint"]} for n in names]}
                v = Verifier(c["trust"], registries=[wba["registry"]], clock=lambda now=c["now"]: now,
                             require_components=c.get("require"), directory=directory)
                m = c["message"]
                try:
                    a = v.verify(m["method"], m["url"], [tuple(h) for h in m["headers"]], (m.get("body") or "").encode())
                    got = "ok"
                except VerifyError as e:
                    got = e.code
                self.assertEqual(got, c["expect"])
                if got == "ok":
                    self.assertEqual((a.identity, a.external), (c["identity"], c.get("external", False)))

    def test_client_dictionary_agent(self):
        for c in [s for s in DOC["sign"] if s.get("client")]:
            cl = c["client"]
            client = Client(cl["identity"], key=seed(c["key"]), registry=cl["registry"], clock=lambda: cl["created"],
                            nonce=lambda: cl["nonce"], agent_dictionary=True)
            self.assertEqual(client.sign(c["message"]["method"], c["message"]["url"]), c["expected_headers"])

    def test_directories(self):
        d = DOC["directory"]["sign"]
        r = directory_response(d["authority"], [seed(n) for n in d["keys"]], d["created"], d["expires_in"])
        self.assertEqual(r.body.decode(), d["expected_body"])
        for k, v in d["expected_headers"].items():
            self.assertEqual(r.headers[k], v, k)
        for c in DOC["directory"]["verify"]:
            with self.subTest(c["name"]):
                _, signed = verify_directory(c["url"], c["headers"], c["body"].encode(), c["now"])
                self.assertEqual(sorted(signed), sorted(c["expect_signed"]))


if __name__ == "__main__":
    unittest.main()
