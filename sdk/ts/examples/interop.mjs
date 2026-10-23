// Live check against the running stack.
import { MesshClient, keyFile } from "../dist/index.js";
import { Verifier } from "../dist/verify.js";

const check = (ok, step, detail = "") => {
  console.log(`${ok ? "PASS" : "FAIL"} ts  ${step}${ok ? "" : `: ${detail}`}`);
  if (!ok) process.exit(1);
};
const { APP, REGISTRY, KEY } = process.env;
const client = await MesshClient.create({ identity: "mukul", key: keyFile(KEY), registry: REGISTRY });

let r = await client.fetch(`${APP}/api/hello`);
let j = await r.json();
check(r.status === 200 && j.key === "sdk-test", "GET /api/hello → 200 mukul · sdk-test", JSON.stringify(j));
r = await client.fetch(`${APP}/api/deploy`, { method: "POST", body: '{"env":"staging"}', headers: { "content-type": "application/json" } });
j = await r.json();
check(r.status === 200 && j.method === "POST", "POST /api/deploy with body → 200", JSON.stringify(j));

const url = "http://api.example/orders?id=7", body = '{"qty":1}';
const a = await new Verifier({ trust: ["mukul"], registries: [REGISTRY] }).verify({ method: "POST", url, headers: await client.sign({ method: "POST", url, body }), body });
check(a.identity === "mukul" && a.keyName === "sdk-test", "verifier with live messh directory → mukul · sdk-test", JSON.stringify(a));
try {
  await new Verifier({ trust: ["alice"], registries: [REGISTRY] }).verify({ method: "GET", url: "http://api.example/x", headers: await client.sign({ method: "GET", url: "http://api.example/x" }) });
  check(false, "identity outside trust list → 403 untrusted", "accepted");
} catch (e) {
  check(e.code === "untrusted" && e.status === 403, "identity outside trust list → 403 untrusted", e);
}
