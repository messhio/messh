import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import * as sf from "../dist/sf.js";
import { componentValue, signMessage, verifyMessage, VerifyError } from "../dist/httpsig.js";
import { MesshClient, directoryResponse, keySeed } from "../dist/index.js";
import { Verifier, verifyDirectory } from "../dist/verify.js";

const DOC = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../../../spec/vectors/http-message-signatures.json"), "utf8"));
const seed = (name) => keySeed(Buffer.from(DOC.keys[name].seed_hex, "hex"));
const pub = (name) => Buffer.from(DOC.keys[name].x, "base64url");

/** A vector message as an HttpMessage: header pairs keep separate field lines. */
const message = (m) => ({
  method: m.method, url: m.url, requestTarget: m.request_target, status: m.status, headers: m.headers, trailers: m.trailers,
  body: m.body, request: m.request ? message(m.request) : undefined,
});
const code = async (fn) => {
  try {
    await fn();
    return "ok";
  } catch (e) {
    if (e instanceof VerifyError) return e.code;
    throw e;
  }
};

test("structured fields", () => {
  for (const c of DOC.structured_fields) {
    const run = () => {
      if (c.type === "dictionary") return sf.serializeDictionary(sf.parseDictionary(c.input).dict);
      if (c.type === "list") return sf.serializeList(sf.parseList(c.input));
      return sf.serializeItem(sf.parseItem(c.input));
    };
    if (c.error) assert.throws(run, c.name);
    else assert.equal(run(), c.canonical, c.name);
  }
});

test("component values", () => {
  for (const c of DOC.components) {
    const run = () => componentValue(message(DOC.messages[c.message]), c.component, DOC.field_types);
    if (c.error) assert.throws(run, c.name);
    else assert.deepEqual(run(), { identifier: c.identifier, value: c.value }, c.name);
  }
});

test("sign vectors", async () => {
  for (const c of DOC.sign) {
    const signer = await seed(c.key)();
    const s = await signMessage(message(c.message), signer, { label: c.label, components: c.components, ...c.params, fieldTypes: DOC.field_types });
    assert.equal(s.base, c.expected_base, c.name);
    assert.equal(s.headers["Signature-Input"], c.expected_headers["Signature-Input"], c.name);
    assert.equal(s.headers.Signature, c.expected_headers.Signature, c.name);
  }
});

test("verify vectors", async () => {
  for (const c of DOC.verify) {
    let label;
    const got = await code(async () => {
      ({ label } = await verifyMessage(message(c.message), {
        label: c.label, tag: c.tag, now: c.now, maxAge: c.max_age, fieldTypes: DOC.field_types,
        keys: (id) => (c.keys[id] ? pub(c.keys[id]) : null),
      }));
    });
    assert.equal(got, c.expect, c.name);
    if (got === "ok") assert.equal(label, c.expect_label, c.name);
  }
});

test("web bot auth vectors", async () => {
  for (const c of DOC.web_bot_auth.cases) {
    const v = new Verifier({
      trust: c.trust, registries: [DOC.web_bot_auth.registry], clock: () => c.now, requireComponents: c.require,
      directory: async (agentUrl) => {
        const names = c.directories[agentUrl];
        return names ? { keys: names.map((n) => ({ kty: "OKP", crv: "Ed25519", x: DOC.keys[n].x, kid: DOC.keys[n].thumbprint })) } : null;
      },
    });
    let agent;
    const headers = new Headers();
    for (const [k, val] of c.message.headers) headers.append(k, val);
    const got = await code(async () => {
      agent = await v.verify({ method: c.message.method, url: c.message.url, headers: Object.fromEntries(c.message.headers.reduce((m, [k, val]) => m.set(k.toLowerCase(), [...(m.get(k.toLowerCase()) ?? []), val]), new Map())), body: c.message.body ?? null });
    });
    assert.equal(got, c.expect, c.name);
    if (got === "ok") assert.deepEqual([agent.identity, agent.external], [c.identity, c.external ?? false], c.name);
  }
});

test("client: dictionary Signature-Agent", async () => {
  for (const c of DOC.sign.filter((s) => s.client)) {
    const client = await MesshClient.create({
      identity: c.client.identity, registry: c.client.registry, key: seed(c.key), clock: () => c.client.created, nonce: () => c.client.nonce,
      agentDictionary: true,
    });
    assert.deepEqual(await client.sign({ method: c.message.method, url: c.message.url }), c.expected_headers, c.name);
  }
});

test("key directories: sign and verify", async () => {
  const d = DOC.directory.sign;
  const { body, headers } = await directoryResponse({ authority: d.authority, keys: d.keys.map(seed), created: d.created, expiresIn: d.expires_in });
  assert.equal(body, d.expected_body);
  for (const [k, val] of Object.entries(d.expected_headers)) assert.equal(headers[k], val, k);
  for (const c of DOC.directory.verify) {
    const { signed } = await verifyDirectory(c.url, c.headers, c.body, c.now);
    assert.deepEqual([...signed].sort(), [...c.expect_signed].sort(), c.name);
  }
});
