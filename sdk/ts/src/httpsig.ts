// @messh/sdk/httpsig: HTTP message signatures (RFC 9421) with Ed25519 for any
// request or response: any label, tag and key ID, every derived component and
// every field parameter (sf, key, bs, req, tr).
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";

import * as sf from "./sf.js";
import { VerifyError } from "./errors.js";
import type { Signer } from "./keys.js";

export { VerifyError } from "./errors.js";

/** Header fields: a Headers object, a record, or [name, value] pairs (keeps separate field lines). */
export type HeaderInit = Headers | Record<string, string | string[] | undefined> | [string, string][];

/** What a signature covers: a request, or a response with the request it answers. */
export interface HttpMessage {
  /** Request method, exactly as sent. */
  method?: string;
  /** Absolute target URI of a request. A Host header, if any, is the authority. */
  url?: string | URL;
  /** The request line's target, if known; else path and query. */
  requestTarget?: string;
  /** Response status code. */
  status?: number;
  headers?: HeaderInit;
  /** Trailer fields, for components with tr. */
  trailers?: HeaderInit;
  /** Checked against a covered Content-Digest; omit to skip the check. */
  body?: Uint8Array | string | null;
  /** For a response: the request it answers, for components with req. */
  request?: HttpMessage;
}

/** Structured-field types ("dictionary", "list" or "item") of fields covered with sf. Common fields need no entry. */
export type FieldTypes = Record<string, string>;

const KNOWN_TYPES: FieldTypes = {
  "accept-signature": "dictionary", "cache-status": "list", "content-digest": "dictionary", priority: "dictionary",
  "proxy-status": "list", "repr-digest": "dictionary", signature: "dictionary", "signature-input": "dictionary",
  "signature-agent": "dictionary-or-item", "want-content-digest": "dictionary", "want-repr-digest": "dictionary",
};

const fail = (code: string, msg: string) => new VerifyError(code, msg, 401);

interface Msg {
  method: string;
  scheme: string;
  authority: string;
  path: string;
  query: string;
  requestTarget: string;
  status: number;
  headers: Map<string, string[]>;
  trailers: Map<string, string[]>;
  body?: Uint8Array;
  request?: Msg;
}

function fields(h?: HeaderInit): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const add = (k: string, v: string) => {
    k = k.toLowerCase();
    out.set(k, [...(out.get(k) ?? []), v]);
  };
  if (!h) return out;
  if (Array.isArray(h)) h.forEach(([k, v]) => add(k, v));
  else if (typeof (h as Headers).forEach === "function" && typeof (h as Headers).get === "function") (h as Headers).forEach((v, k) => add(k, v));
  else {
    for (const [k, v] of Object.entries(h as Record<string, string | string[] | undefined>)) {
      if (Array.isArray(v)) v.forEach((x) => add(k, x));
      else if (v !== undefined) add(k, v);
    }
  }
  return out;
}

function normalize(m: HttpMessage): Msg {
  const headers = fields(m.headers);
  const out: Msg = {
    method: m.method ?? "", scheme: "", authority: "", path: "", query: "", requestTarget: m.requestTarget ?? "",
    status: m.status ?? 0, headers, trailers: fields(m.trailers),
    body: m.body == null ? undefined : typeof m.body === "string" ? Buffer.from(m.body) : m.body,
    request: m.request ? normalize(m.request) : undefined,
  };
  if (m.url !== undefined) {
    const u = new URL(m.url);
    out.scheme = u.protocol.replace(/:$/, "");
    out.authority = u.host;
    out.path = u.pathname;
    out.query = u.search.replace(/^\?/, "");
  }
  const host = headers.get("host");
  if (host?.length) out.authority = host[0].trim();
  return out;
}

// --- component identifiers ---

/** @internal A parsed component identifier. */
export interface Comp {
  name: string;
  params: sf.Params;
}

const idOf = (c: Comp) => sf.serializeBare(sf.str(c.name)) + sf.serializeParams(c.params);

function checked(c: Comp): Comp {
  if (/^@[a-z][a-z-]*$/.test(c.name) || /^[a-z0-9!#$%&'*+\-.^_`|~]+$/.test(c.name)) return c;
  throw new Error(`bad component name ${JSON.stringify(c.name)} (lowercase field names, or @derived)`);
}

function parseComponent(s: string): Comp {
  if (!s.startsWith('"')) return checked({ name: s.toLowerCase(), params: [] });
  let it: sf.Item;
  try {
    it = sf.parseItem(s);
  } catch {
    throw new Error(`bad component identifier ${s}`);
  }
  if (it.bare.t !== "str") throw new Error(`bad component identifier ${s}`);
  return checked({ name: it.bare.v, params: it.params });
}

// --- component values (RFC 9421 §2) ---

/** The identifier and signature-base value of one component of a message. Throws for a component it can't derive. */
export function componentValue(message: HttpMessage, component: string, fieldTypes: FieldTypes = {}): { identifier: string; value: string } {
  const c = parseComponent(component);
  return { identifier: idOf(c), value: valueOf(normalize(message), c, fieldTypes) };
}

function valueOf(m: Msg, c: Comp, types: FieldTypes): string {
  const id = idOf(c);
  let req = false, strict = false, bs = false, tr = false;
  let key: string | undefined, name: string | undefined;
  for (const [k, v] of c.params) {
    if (["req", "sf", "bs", "tr"].includes(k)) {
      if (v.t !== "bool" || !v.v) throw new Error(`${id}: parameter ${k} must be true`);
      req ||= k === "req";
      strict ||= k === "sf";
      bs ||= k === "bs";
      tr ||= k === "tr";
    } else if (k === "key" || k === "name") {
      if (v.t !== "str") throw new Error(`${id}: parameter ${k} must be a string`);
      if (k === "key") key = v.v;
      else name = v.v;
    } else throw new Error(`${id}: unknown parameter ${k}`);
  }
  const derived = c.name.startsWith("@");
  if (derived && (strict || bs || tr || key !== undefined)) throw new Error(`${id}: sf, bs, tr and key apply to fields only`);
  if (name !== undefined && c.name !== "@query-param") throw new Error(`${id}: name applies to @query-param only`);
  if (bs && (strict || key !== undefined)) throw new Error(`${id}: bs can't be combined with sf or key`);
  let ctx = m;
  if (req) {
    if (!m.status || !m.request) throw new Error(`${id}: req needs a response and the request it answers`);
    ctx = m.request;
  }
  if (derived) {
    if (c.name === "@query-param" && name === undefined) throw new Error("@query-param needs a name parameter");
    return derivedValue(ctx, c.name, name ?? "");
  }
  return fieldValue(tr ? ctx.trailers : ctx.headers, c.name, strict, bs, key, types);
}

const pathOf = (m: Msg) => m.path || "/";
const pathQuery = (m: Msg) => (m.query ? `${pathOf(m)}?${m.query}` : pathOf(m));

function derivedValue(m: Msg, name: string, param: string): string {
  if (name === "@status") {
    if (!m.status) throw new Error("@status applies to responses only");
    return String(m.status);
  }
  if (!m.authority && !m.method) throw new Error(`${name} needs the request (use req in a response signature)`);
  switch (name) {
    case "@method":
      if (!m.method) throw new Error("@method needs a request method");
      return m.method;
    case "@target-uri":
      if (!m.scheme || !m.authority) throw new Error("@target-uri needs a scheme and an authority");
      return `${m.scheme.toLowerCase()}://${m.authority.toLowerCase()}${pathQuery(m)}`;
    case "@authority":
      if (!m.authority) throw new Error("@authority needs an authority");
      return m.authority.toLowerCase();
    case "@scheme":
      if (!m.scheme) throw new Error("@scheme needs a scheme");
      return m.scheme.toLowerCase();
    case "@request-target":
      return m.requestTarget || pathQuery(m);
    case "@path":
      return pathOf(m);
    case "@query":
      return `?${m.query}`;
    case "@query-param":
      return queryParam(m.query, param);
  }
  throw new Error(`unknown derived component ${name}`);
}

const clean = (v: string) => v.replace(/^[ \t]+|[ \t]+$/g, "").replace(/[ \t]*\r?\n[ \t]+/g, " ");

function fieldValue(h: Map<string, string[]>, name: string, strict: boolean, bs: boolean, key: string | undefined, types: FieldTypes): string {
  const vals = h.get(name);
  if (!vals?.length) throw new Error(`covered field ${name} is missing`);
  const v = vals.map((x) => (bs ? sf.serializeBare(sf.bin(Buffer.from(clean(x), "latin1"))) : clean(x))).join(", ");
  if (key !== undefined) {
    let d: sf.Dictionary;
    try {
      d = sf.parseDictionary(v).dict;
    } catch (e) {
      throw new Error(`${name} is not a dictionary: ${(e as Error).message}`);
    }
    const m = sf.member(d, key);
    if (!m) throw new Error(`${name} has no member ${JSON.stringify(key)}`);
    return sf.serializeMember(m);
  }
  return strict ? strictValue(name, v, types) : v;
}

function strictValue(name: string, v: string, types: FieldTypes): string {
  const t = types[name] ?? KNOWN_TYPES[name];
  if (t === "dictionary" || t === "dictionary-or-item") {
    try {
      return sf.serializeDictionary(sf.parseDictionary(v).dict);
    } catch (e) {
      if (t === "dictionary") throw new Error(`${name}: ${(e as Error).message}`);
    }
  }
  if (t === "item" || t === "dictionary-or-item") return sf.serializeItem(sf.parseItem(v));
  if (t === "list") return sf.serializeList(sf.parseList(v));
  throw new Error(`can't serialize ${name} strictly: its structured-field type is unknown`);
}

function formDecode(s: string): Buffer {
  s = s.replace(/\+/g, " ");
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "%" && i + 2 < s.length && /^[0-9a-fA-F]{2}$/.test(s.slice(i + 1, i + 3))) {
      out.push(parseInt(s.slice(i + 1, i + 3), 16));
      i += 2;
    } else out.push(...Buffer.from(s[i]));
  }
  return Buffer.from(out);
}

function formEncode(b: Uint8Array): string {
  let out = "";
  for (const c of b) {
    const ch = String.fromCharCode(c);
    out += /[A-Za-z0-9*\-._]/.test(ch) ? ch : "%" + c.toString(16).toUpperCase().padStart(2, "0");
  }
  return out;
}

/** The encoded value of one query parameter (RFC 9421 §2.2.8). */
function queryParam(raw: string, name: string): string {
  const vals: string[] = [];
  for (const part of raw.split("&")) {
    if (!part) continue;
    const i = part.indexOf("=");
    const [k, v] = i < 0 ? [part, ""] : [part.slice(0, i), part.slice(i + 1)];
    if (formEncode(formDecode(k)) === name) vals.push(formEncode(formDecode(v)));
  }
  if (vals.length === 0) throw new Error(`query parameter ${JSON.stringify(name)} is missing`);
  if (vals.length > 1) throw new Error(`query parameter ${JSON.stringify(name)} occurs more than once`);
  return vals[0];
}

// --- signature base (RFC 9421 §2.5) ---

function baseOf(m: Msg, comps: Comp[], params: string, types: FieldTypes): string {
  const seen = new Set<string>();
  const lines = comps.map((c) => {
    const id = idOf(c);
    if (seen.has(id)) throw new Error(`component ${id} is covered twice`);
    seen.add(id);
    return `${id}: ${valueOf(m, c, types)}`;
  });
  lines.push(`"@signature-params": ${params}`);
  const base = lines.join("\n");
  if (/[^\x20-\x7e\n]/.test(base)) throw new Error("signature base must be printable ASCII (wrap such fields with bs)");
  return base;
}

// --- signing ---

export interface SignOptions {
  /** Default "sig1". */
  label?: string;
  /** Covered components, in order: plain names (@method, content-type) or identifiers with parameters ("example-dict";key="a"). */
  components: string[];
  /** Seconds since epoch; omitted when undefined. */
  created?: number;
  expires?: number;
  keyid?: string;
  /** "ed25519", or undefined to leave it out. */
  alg?: string;
  nonce?: string;
  tag?: string;
  fieldTypes?: FieldTypes;
}

/** A signature ready to send. */
export interface Signed {
  label: string;
  /** Signature-Input member value: covered components and parameters. */
  input: string;
  /** Signature member value: :base64:. */
  signature: string;
  /** The signature base that was signed. */
  base: string;
  /** Signature-Input and Signature with only this signature. */
  headers: { "Signature-Input": string; Signature: string };
}

/** Sign a message. Throws for a bad option or a component that can't be derived. */
export async function signMessage(message: HttpMessage, signer: Signer, options: SignOptions): Promise<Signed> {
  const label = options.label ?? "sig1";
  if (!sf.validKey(label)) throw new TypeError(`bad label ${JSON.stringify(label)}`);
  const comps = options.components.map(parseComponent);
  const params: sf.Params = [];
  if (options.created !== undefined) params.push(["created", sf.int(Math.floor(options.created))]);
  if (options.expires !== undefined) params.push(["expires", sf.int(Math.floor(options.expires))]);
  for (const k of ["keyid", "alg", "nonce", "tag"] as const) {
    const v = options[k];
    if (v === undefined) continue;
    if (!sf.validString(v)) throw new TypeError(`${k} must be printable ASCII`);
    params.push([k, sf.str(v)]);
  }
  const input = sf.serializeMember({ inner: true, items: comps.map((c) => ({ bare: sf.str(c.name), params: c.params })), params });
  const base = baseOf(normalize(message), comps, input, options.fieldTypes ?? {});
  const signature = sf.serializeBare(sf.bin(await signer.sign(Buffer.from(base))));
  return { label, input, signature, base, headers: { "Signature-Input": `${label}=${input}`, Signature: `${label}=${signature}` } };
}

// --- parsing signatures ---

/** One covered component of a signature. */
export interface Covered {
  /** Serialized identifier, e.g. "signature-agent";key="sig1". */
  id: string;
  name: string;
  /** Its key parameter, if any. */
  key?: string;
}

/** One signature of a message, parsed but not verified. */
export interface Signature {
  label: string;
  covered: Covered[];
  created?: number;
  expires?: number;
  keyid?: string;
  alg?: string;
  nonce?: string;
  tag?: string;
  value: Uint8Array;
  /** @internal */ comps: Comp[];
  /** @internal */ params: string;
}

export const covers = (s: Signature, name: string) => s.covered.some((c) => c.name === name);

function dictionaryOf(h: Map<string, string[]>, name: string): sf.Dictionary {
  let parsed: { dict: sf.Dictionary; duplicates: string[] };
  try {
    parsed = sf.parseDictionary((h.get(name.toLowerCase()) ?? []).join(", "));
  } catch (e) {
    throw fail("bad_signature", `${name}: ${(e as Error).message}`);
  }
  if (parsed.duplicates.length) throw fail("bad_signature", `${name} repeats the label ${parsed.duplicates[0]}`);
  return parsed.dict;
}

function parseSignatures(m: Msg): Signature[] {
  if (!m.headers.get("signature-input")?.length || !m.headers.get("signature")?.length) {
    throw fail("missing_signature", "send Signature-Input and Signature (RFC 9421)");
  }
  const inputs = dictionaryOf(m.headers, "Signature-Input");
  const values = dictionaryOf(m.headers, "Signature");
  const out: Signature[] = [];
  for (const [label, mem] of inputs) {
    if (!mem.inner) throw fail("bad_signature", `Signature-Input ${label} is not an inner list`);
    const s: Signature = { label, covered: [], value: new Uint8Array(), comps: [], params: sf.serializeMember(mem) };
    const seen = new Set<string>();
    for (const it of mem.items) {
      if (it.bare.t !== "str") throw fail("bad_signature", `Signature-Input ${label}: a component is not a string`);
      let c: Comp;
      try {
        c = checked({ name: it.bare.v, params: it.params });
      } catch (e) {
        throw fail("bad_signature", `Signature-Input ${label}: ${(e as Error).message}`);
      }
      const id = idOf(c);
      if (seen.has(id)) throw fail("bad_signature", `Signature-Input ${label} covers ${id} twice`);
      seen.add(id);
      const key = sf.param(c.params, "key");
      s.comps.push(c);
      s.covered.push({ id, name: c.name, ...(key?.t === "str" ? { key: key.v } : {}) });
    }
    for (const [k, v] of mem.params) {
      if (k === "created" || k === "expires") {
        if (v.t !== "int") throw fail("bad_signature", `${k} must be an integer`);
        s[k] = v.v;
      } else if (k === "keyid" || k === "alg" || k === "nonce" || k === "tag") {
        if (v.t !== "str") throw fail("bad_signature", `${k} must be a string`);
        s[k] = v.v;
      }
    }
    const sig = sf.member(values, label);
    if (!sig || sig.inner || sig.bare.t !== "bin") throw fail("bad_signature", `no Signature for ${label}`);
    s.value = sig.bare.v;
    out.push(s);
  }
  if (!out.length) throw fail("missing_signature", "Signature-Input has no signatures");
  return out;
}

/** Parse a message's Signature-Input and Signature. Labels and covered components must not repeat (RFC 9421 §4.1, §2.5). */
export function signatures(message: HttpMessage): Signature[] {
  return parseSignatures(normalize(message));
}

/** Choose a signature by label, else by tag, else the only one. */
export function pickSignature(sigs: Signature[], label?: string, tag?: string): Signature {
  const s = label ? sigs.find((x) => x.label === label) : tag ? sigs.find((x) => x.tag === tag) : sigs.length === 1 ? sigs[0] : undefined;
  if (s) return s;
  if (label) throw fail("bad_signature", `no signature labeled ${label}`);
  if (tag) throw fail("bad_signature", `no signature with tag=${JSON.stringify(tag)}`);
  throw fail("bad_signature", `the message has ${sigs.length} signatures: choose one by label or tag`);
}

/** The RFC 9530 Content-Digest field for a body (sha-256). */
export function contentDigest(body: Uint8Array | string): string {
  return `sha-256=:${createHash("sha256").update(body).digest("base64")}:`;
}

/** Check a body against a Content-Digest field (sha-256 or sha-512); throws digest_mismatch. */
export function checkDigest(field: string, body: Uint8Array): void {
  let known = 0;
  try {
    for (const [k, m] of sf.parseDictionary(field).dict) {
      if (k !== "sha-256" && k !== "sha-512") continue;
      known++;
      const sum = createHash(k.replace("-", "")).update(body).digest();
      if (m.inner || m.bare.t !== "bin" || !sum.equals(Buffer.from(m.bare.v))) throw fail("digest_mismatch", "the body doesn't match Content-Digest");
    }
  } catch (e) {
    if (e instanceof VerifyError) throw e;
  }
  if (!known) throw fail("digest_mismatch", "Content-Digest has no sha-256 or sha-512 digest");
}

// --- verifying ---

/** Replay store. add() returns false if key was seen within ttlSeconds. */
export interface NonceStore {
  add(key: string, ttlSeconds: number): boolean | Promise<boolean>;
}

export interface VerifyOptions {
  /** Verify the signature with this label. */
  label?: string;
  /** Or the first one with this tag (else the only one). */
  tag?: string;
  /** Required: the Ed25519 public key for a keyid; null or undefined means unknown_key. */
  keys: (keyid: string) => Uint8Array | null | undefined | Promise<Uint8Array | null | undefined>;
  /** Seconds since epoch. Default now. */
  now?: number;
  /** How far created may be ahead of now, in seconds. Default 60. */
  maxSkew?: number;
  /** If set, how old created may be, in seconds. */
  maxAge?: number;
  /** Component names that must be covered. */
  required?: string[];
  /** Reject a nonce seen before (signatures with a nonce). */
  nonceStore?: NonceStore;
  fieldTypes?: FieldTypes;
}

/** A verified signature. */
export interface Verified {
  label: string;
  /** Covered component identifiers. */
  components: string[];
  keyid?: string;
  alg?: string;
  nonce?: string;
  tag?: string;
  created?: number;
  expires?: number;
  base: string;
}

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** Verify one signature of a message: content digest, time, key, then the signature. Throws VerifyError. */
export async function verifyMessage(message: HttpMessage, options: VerifyOptions): Promise<Verified> {
  const m = normalize(message);
  return verifyParsed(m, pickSignature(parseSignatures(m), options.label, options.tag), options);
}

/** Verify a signature from signatures(); label and tag are ignored. */
export async function verifySignature(message: HttpMessage, sig: Signature, options: VerifyOptions): Promise<Verified> {
  return verifyParsed(normalize(message), sig, options);
}

async function verifyParsed(m: Msg, s: Signature, o: VerifyOptions): Promise<Verified> {
  for (const name of o.required ?? []) if (!covers(s, name)) throw fail("bad_signature", `${name} must be covered`);
  if (s.alg !== undefined && s.alg !== "ed25519") throw fail("bad_signature", `alg ${JSON.stringify(s.alg)} is not supported (ed25519 only)`);
  for (const c of s.comps) {
    if (c.name !== "content-digest") continue;
    const ctx = sf.param(c.params, "req") && m.request ? m.request : m;
    if (ctx.body !== undefined) checkDigest((ctx.headers.get("content-digest") ?? []).join(", "), ctx.body);
  }
  const now = o.now ?? Date.now() / 1000;
  const skew = o.maxSkew ?? 60;
  if (s.created !== undefined) {
    if (s.created > now + skew) throw fail("clock_skew", `created is ${Math.round(s.created - now)}s ahead of the clock`);
    if (o.maxAge !== undefined && s.created < now - o.maxAge) throw fail("clock_skew", `the signature is ${Math.round(now - s.created)}s old`);
  }
  if (s.expires !== undefined && now > s.expires) throw fail("clock_skew", "the signature expired");
  let pub: Uint8Array | null | undefined;
  try {
    pub = await o.keys(s.keyid ?? "");
  } catch (e) {
    if (e instanceof VerifyError) throw e;
    throw fail("unknown_key", `keyid ${JSON.stringify(s.keyid)}: ${(e as Error).message}`);
  }
  if (!pub || pub.length !== 32) throw fail("unknown_key", `keyid ${JSON.stringify(s.keyid ?? "")} is not a known Ed25519 key`);
  let base: string;
  try {
    base = baseOf(m, s.comps, s.params, o.fieldTypes ?? {});
  } catch (e) {
    throw fail("bad_signature", (e as Error).message);
  }
  const key = createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, pub]), format: "der", type: "spki" });
  if (!edVerify(null, Buffer.from(base), key, s.value)) throw fail("bad_signature", "the signature doesn't match the message");
  if (o.nonceStore && s.nonce !== undefined) {
    let ttl = o.maxAge !== undefined ? o.maxAge + skew : 2 * skew;
    if (s.expires !== undefined) ttl = Math.max(ttl, s.expires - now + skew);
    if (!(await o.nonceStore.add(`${s.keyid ?? ""} ${s.nonce}`, ttl))) throw fail("nonce_replayed", "this signature was already accepted once");
  }
  return {
    label: s.label, components: s.covered.map((c) => c.id), keyid: s.keyid, alg: s.alg, nonce: s.nonce, tag: s.tag,
    created: s.created, expires: s.expires, base,
  };
}
