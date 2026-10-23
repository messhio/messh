"""Live check against the running stack."""
import os
import sys

from messh import Client, key_file
from messh.verify import Verifier, VerifyError


def check(ok, step, detail=""):
    print(("PASS" if ok else "FAIL") + " py  " + step + ("" if ok else ": %s" % detail))
    if not ok:
        sys.exit(1)


app, registry = os.environ["APP"], os.environ["REGISTRY"]
client = Client("mukul", key=key_file(os.environ["KEY"]), registry=registry)
r = client.get(app + "/api/hello")
check(r.status == 200 and r.json()["key"] == "sdk-test", "GET /api/hello → 200 mukul · sdk-test", r.body)
r = client.post(app + "/api/deploy", json={"env": "staging"})
check(r.status == 200 and r.json()["method"] == "POST", "POST /api/deploy with body → 200", r.body)

url, body = "http://api.example/orders?id=7", b'{"qty":1}'
a = Verifier(trust=["mukul"], registries=[registry]).verify("POST", url, client.sign("POST", url, body), body)
check(a.identity == "mukul" and a.key_name == "sdk-test", "verifier with live messh directory → mukul · sdk-test", a)
try:
    Verifier(trust=["alice"], registries=[registry]).verify("GET", "http://api.example/x", client.sign("GET", "http://api.example/x"))
    check(False, "identity outside trust list → 403 untrusted", "accepted")
except VerifyError as e:
    check(e.code == "untrusted" and e.status == 403, "identity outside trust list → 403 untrusted", e)
