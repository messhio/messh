import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { MesshClient, MesshError, keyEnv, keyFile, keySeed } from "../dist/index.js";
import { Verifier, VerifyError, messhAuth } from "../dist/verify.js";

const VEC = join(dirname(fileURLToPath(import.meta.url)), "../../../spec/vectors");
const DOC = JSON.parse(readFileSync(join(VEC, "web-bot-auth.json"), "utf8"));
const OPENSSH = join(VEC, DOC.key.files.openssh);

test("sign vectors", async () => {
  for (const c of DOC.sign) {
    const client = await MesshClient.create({
      identity: "mukul", key: keyFile(OPENSSH), registry: "https://registry.example",
      clock: () => c.created, nonce: () => c.nonce,
    });
    assert.deepEqual(await client.sign({ method: c.method, url: c.url, body: c.body || null }), c.expected_headers, c.name);
  }
});

test("key sources", async () => {
  const want = DOC.key.jwk.kid;
  process.env.MESSH_TEST_KEY = readFileSync(join(VEC, DOC.key.files.pkcs8)).toString("base64");
  for (const [name, key] of Object.entries({
    openssh: keyFile(OPENSSH),
    pkcs8: keyFile(join(VEC, DOC.key.files.pkcs8)),
    env: keyEnv("MESSH_TEST_KEY"),
    seed: keySeed(Buffer.from(DOC.key.seed_hex, "hex")),
  })) {
    assert.equal((await MesshClient.create({ identity: "mukul", key })).keyId, want, name);
  }
  await assert.rejects(MesshClient.create({ identity: "mukul", key: keyFile(join(VEC, DOC.key.files.public)) }), MesshError);
  await assert.rejects(MesshClient.create({ identity: "Not A User", key: keyFile(OPENSSH) }), MesshError);
});

const verifier = (c, extra = {}) => new Verifier({
  trust: ["*"], registries: ["https://registry.example"], directory: { keys: c.directory_keys }, clock: () => c.now, ...extra,
});

test("verify vectors", async () => {
  for (const c of DOC.verify) {
    const v = verifier(c);
    const input = { method: c.method, url: c.url, headers: c.headers, body: c.body || null };
    let got = "ok", agent;
    try { agent = await v.verify(input); } catch (e) { assert.ok(e instanceof VerifyError, String(e)); got = e.code; }
    assert.equal(got, c.expect, c.name);
    if (got === "ok") {
      assert.equal(agent.identity, "mukul");
      assert.equal(agent.keyName, "sdk-test");
      await assert.rejects(v.verify(input), (e) => e.code === "nonce_replayed");
    }
  }
});

test("trust and registries", async () => {
  const c = DOC.verify[0];
  const input = { method: c.method, url: c.url, headers: c.headers };
  await assert.rejects(verifier(c, { trust: ["alice"] }).verify(input), (e) => e.code === "untrusted" && e.status === 403);
  await assert.rejects(verifier(c, { registries: undefined }).verify(input), (e) => e.code === "untrusted");
  assert.throws(() => new Verifier({ trust: [] }), TypeError);
});

test("verifyRequest with a fetch Request", async () => {
  const c = DOC.verify.find((x) => x.name === "ok-post");
  const agent = await verifier(c).verifyRequest(new Request(c.url, { method: c.method, headers: c.headers, body: c.body }));
  assert.equal(agent.identity, "mukul");
});

test("express-style middleware", async () => {
  const c = DOC.verify.find((x) => x.name === "ok-post");
  const u = new URL(c.url);
  const run = (headers) => new Promise((resolve) => {
    const handlers = {};
    const req = { method: c.method, url: u.pathname, headers: { host: u.host, ...headers }, protocol: "https", on: (ev, fn) => { handlers[ev] = fn; } };
    const res = { code: 200, hdrs: {}, status(n) { this.code = n; return this; }, setHeader(k, v) { this.hdrs[k] = v; }, json(b) { resolve({ res: this, body: b }); } };
    messhAuth({ verifier: verifier(c) })(req, res, () => resolve({ req, res }));
    handlers.data(Buffer.from(c.body));
    handlers.end();
  });
  const ok = await run({ "content-type": "application/json", ...Object.fromEntries(Object.entries(c.headers).map(([k, v]) => [k.toLowerCase(), v])) });
  assert.equal(ok.req.agent.identity, "mukul");
  assert.deepEqual(ok.req.body, { env: "staging" });
  const bad = await run({});
  assert.equal(bad.res.code, 401);
  assert.ok(bad.res.hdrs["Accept-Signature"]);
});
