// Production behavior: environment config, whoami, ssh-agent, the verifier's
// directory cache policy and body limits. Runs against a local fake registry.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { copyFileSync, chmodSync, mkdtempSync, readFileSync, existsSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { MesshClient, MesshError, fingerprint, keyFile, sshAgent } from "../dist/index.js";
import { Verifier, messhAuth } from "../dist/verify.js";

const VEC = join(dirname(fileURLToPath(import.meta.url)), "../../../spec/vectors");
const DOC = JSON.parse(readFileSync(join(VEC, "web-bot-auth.json"), "utf8"));
const OPENSSH = join(VEC, DOC.key.files.openssh);
const JWK = DOC.key.jwk;

// A fake registry: dirs[identity] is a directory, null for 404, "error" for 500.
async function registry(dirs) {
  const hits = [];
  const server = createServer((req, res) => {
    const id = req.url.split("/")[1];
    hits.push(id);
    const d = dirs[id];
    if (d === "error") return res.writeHead(500).end();
    if (d === undefined || d === null) return res.writeHead(404).end();
    res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(d));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}`;
  return { url, hits, dirs, close: () => server.close() };
}

test("fingerprint matches the SSH fingerprint messh lists", async () => {
  const client = await MesshClient.create({ identity: "mukul", key: keyFile(OPENSSH) });
  assert.equal(client.fingerprint, JWK.messh_fingerprint);
  assert.equal(fingerprint(Buffer.from(JWK.x, "base64url")), JWK.messh_fingerprint);
});

test("fromEnv reads MESSH_IDENTITY, MESSH_KEY / MESSH_KEY_FILE and MESSH_REGISTRY", async () => {
  const saved = { ...process.env };
  try {
    delete process.env.MESSH_KEY;
    Object.assign(process.env, { MESSH_IDENTITY: "mukul", MESSH_KEY_FILE: OPENSSH, MESSH_REGISTRY: "https://registry.example/" });
    let c = await MesshClient.fromEnv();
    assert.deepEqual([c.identity, c.keyId, c.agent], ["mukul", JWK.kid, "https://registry.example/mukul"]);
    process.env.MESSH_KEY = readFileSync(join(VEC, DOC.key.files.pkcs8)).toString("base64");
    c = await MesshClient.fromEnv({ identity: "acme-ci" });
    assert.deepEqual([c.identity, c.keyId], ["acme-ci", JWK.kid]);
    delete process.env.MESSH_IDENTITY;
    await assert.rejects(MesshClient.fromEnv(), (e) => e instanceof MesshError && e.code === "invalid_identity" && /MESSH_IDENTITY/.test(e.message));
  } finally {
    process.env = saved;
  }
});

test("whoami: published, unknown user, unpublished key, unreachable registry", async () => {
  const reg = await registry({ mukul: { keys: [JWK] }, empty: { keys: [] } });
  try {
    const as = (identity) => MesshClient.create({ identity, key: keyFile(OPENSSH), registry: reg.url });
    assert.deepEqual(await (await as("mukul")).whoami(), {
      identity: "mukul", keyName: "sdk-test", keyId: JWK.kid, fingerprint: JWK.messh_fingerprint, agentUrl: `${reg.url}/mukul`,
    });
    await assert.rejects((await as("nobody")).whoami(), (e) => e.code === "not_published" && /no user nobody/.test(e.message));
    await assert.rejects((await as("empty")).whoami(), (e) => e.code === "not_published" && e.message.includes(JWK.messh_fingerprint));
  } finally {
    reg.close();
  }
  const gone = await MesshClient.create({ identity: "mukul", key: keyFile(OPENSSH), registry: reg.url });
  await assert.rejects(gone.whoami(), (e) => e.code === "registry_unreachable");
});

// A signer and verifier sharing a fake clock, against a fake registry.
async function setup(dirs, opts = {}) {
  const reg = await registry(dirs);
  const clock = { t: 1_800_000_000 };
  const verifier = new Verifier({ trust: ["*"], registries: [reg.url], clock: () => clock.t, ...opts });
  const send = async (identity) => {
    const c = await MesshClient.create({ identity, key: keyFile(OPENSSH), registry: reg.url, clock: () => clock.t });
    const url = "https://api.example/hello";
    return verifier.verify({ method: "GET", url, headers: await c.sign({ method: "GET", url }) });
  };
  return { reg, clock, verifier, send };
}
const code = async (p) => p.then(() => "ok", (e) => e.code);

test("untrusted callers are refused before any directory fetch", async () => {
  const { reg, send } = await setup({ mukul: { keys: [JWK] } }, { trust: ["alice"] });
  try {
    assert.equal(await code(send("mukul")), "untrusted");
    assert.deepEqual(reg.hits, []);
  } finally {
    reg.close();
  }
});

test("unknown identities are remembered for 30 s", async () => {
  const { reg, clock, send } = await setup({});
  try {
    assert.equal(await code(send("ghost")), "unknown_key");
    clock.t += 10;
    assert.equal(await code(send("ghost")), "unknown_key");
    assert.equal(reg.hits.length, 1);
    clock.t += 21;
    await code(send("ghost"));
    assert.equal(reg.hits.length, 2);
  } finally {
    reg.close();
  }
});

test("a key published after the directory was cached works within 30 s", async () => {
  const { reg, clock, send } = await setup({ mukul: { keys: [] } });
  try {
    assert.equal(await code(send("mukul")), "unknown_key");
    reg.dirs.mukul = { keys: [JWK] };
    clock.t += 10;
    assert.equal(await code(send("mukul")), "unknown_key", "refetches at most every 30 s");
    clock.t += 21;
    assert.equal(await code(send("mukul")), "ok");
    assert.equal(reg.hits.length, 2);
    clock.t += 60;
    assert.equal(await code(send("mukul")), "ok", "a found key is served from cache");
    assert.equal(reg.hits.length, 2);
  } finally {
    reg.close();
  }
});

test("a 404 is never answered from the stale cache; an outage is, with back-off", async () => {
  const { reg, clock, send } = await setup({ mukul: { keys: [JWK] } });
  try {
    assert.equal(await code(send("mukul")), "ok");
    reg.dirs.mukul = "error";
    clock.t += 301;
    assert.equal(await code(send("mukul")), "ok", "messh down: cached keys keep working");
    clock.t += 2;
    assert.equal(await code(send("mukul")), "ok");
    assert.equal(reg.hits.length, 2, "no retry within 5 s of a failure");
    reg.dirs.mukul = null;
    clock.t += 5;
    assert.equal(await code(send("mukul")), "unknown_key", "deleted identity: not served stale");
  } finally {
    reg.close();
  }
});

test("concurrent misses share one directory fetch", async () => {
  const { reg, send } = await setup({ mukul: { keys: [JWK] } });
  try {
    assert.deepEqual(await Promise.all([1, 2, 3, 4].map(() => code(send("mukul")))), ["ok", "ok", "ok", "ok"]);
    assert.equal(reg.hits.length, 1);
  } finally {
    reg.close();
  }
});

test("bodies over maxBodyBytes get 413 body_too_large", async () => {
  const v = new Verifier({ trust: ["*"], directory: { keys: [JWK] }, maxBodyBytes: 8 });
  await assert.rejects(v.verifyRequest(new Request("https://api.example/x", { method: "POST", body: "x".repeat(9) })),
    (e) => e.code === "body_too_large" && e.status === 413);
  const out = await new Promise((resolve) => {
    const h = {};
    const req = { method: "POST", url: "/x", headers: { host: "api.example" }, on: (ev, fn) => { h[ev] = fn; } };
    const res = { status(n) { this.code = n; return this; }, setHeader() {}, json(b) { resolve({ code: this.code, b }); } };
    messhAuth({ verifier: v })(req, res, () => resolve({ code: "next" }));
    h.data(Buffer.from("0123456789"));
    h.end();
  });
  assert.deepEqual([out.code, out.b.error], [413, "body_too_large"]);
});

// ssh-agent: a real agent holding the conformance key signs byte-identically to the file.
const agentBin = ["/usr/bin/ssh-agent", "/opt/homebrew/bin/ssh-agent", "/usr/local/bin/ssh-agent"].find(existsSync);
test("sshAgent signs with a key held by ssh-agent", { skip: !agentBin && "ssh-agent not installed" }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "messh-agent-"));
  const sock = join(dir, "agent.sock");
  const keyCopy = join(dir, "id");
  copyFileSync(OPENSSH, keyCopy);
  chmodSync(keyCopy, 0o600);
  const agent = spawn(agentBin, ["-D", "-a", sock], { stdio: "ignore" });
  try {
    for (let i = 0; i < 50 && !existsSync(sock); i++) await new Promise((r) => setTimeout(r, 50));
    execFileSync("ssh-add", [keyCopy], { env: { ...process.env, SSH_AUTH_SOCK: sock }, stdio: "ignore" });
    const c = DOC.sign[0];
    const opts = { identity: "mukul", registry: "https://registry.example", clock: () => c.created, nonce: () => c.nonce };
    const viaAgent = await MesshClient.create({ ...opts, key: sshAgent({ socket: sock }) });
    assert.deepEqual(await viaAgent.sign({ method: c.method, url: c.url, body: c.body || null }), c.expected_headers);
    assert.equal(viaAgent.fingerprint, JWK.messh_fingerprint);
    await assert.rejects(MesshClient.create({ ...opts, key: sshAgent({ socket: sock, fingerprint: "SHA256:nope" }) }),
      (e) => e.code === "invalid_key" && e.message.includes(JWK.messh_fingerprint));
  } finally {
    agent.kill();
  }
});
