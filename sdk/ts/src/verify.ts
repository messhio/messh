// @messh/sdk/verify: verify Web Bot Auth signatures with keys from messh, or
// from the key directories of other agents you trust.
import * as sf from "./sf.js";
import * as wba from "./wba.js";
import { VerifyError } from "./errors.js";
import { DIRECTORY_TAG, VERSION } from "./index.js";
import { checkDigest, covers, signatures, verifySignature, type HeaderInit, type HttpMessage, type Signature } from "./httpsig.js";

export { VerifyError } from "./errors.js";

export const ACCEPT_SIGNATURE = 'sig1=("@method" "@authority" "@path" "signature-agent");keyid;created;expires;nonce;alg="ed25519";tag="web-bot-auth"';
const IDENTITY = /^[a-z0-9](?:[a-z0-9-]{1,28}[a-z0-9])$/;
const DEFAULT_REQUIRED = ["@method", "@authority", "@path", "signature-agent"];

// Directory cache policy, the same in every messh SDK.
/** An unknown keyid refetches its signer's directory at most this often (s), so new keys work within seconds. */
const MIN_REFRESH = 30;
/** While messh is unreachable, retry a directory at most this often (s). */
const RETRY_AFTER = 5;
/** Directories kept at most. */
const MAX_ENTRIES = 10_000;
/** Default limit on request bodies the middleware reads (bytes). */
export const MAX_BODY_BYTES = 1 << 20;

/** A verified caller. */
export interface Agent {
  /** messh username, e.g. "mukul"; for other agents, their origin or jwk:<thumbprint>. */
  identity: string;
  /** Key name on messh, e.g. "laptop". */
  keyName: string;
  /** RFC 7638 thumbprint. */
  keyId: string;
  /** SHA256:… of the SSH key. */
  fingerprint: string;
  /** Signature-Agent. */
  agentUrl: string;
  /** Signature creation time, seconds since epoch. */
  created: number;
  /** Not a messh identity: an agent origin you trust, or inline keys. */
  external: boolean;
  /** The key's directory response carried a valid signature by that key. */
  signedDirectory: boolean;
}

/** Replay store. add() returns false if key was seen within ttlSeconds. */
export interface NonceStore {
  add(key: string, ttlSeconds: number): boolean | Promise<boolean>;
}

export class MemoryNonceStore implements NonceStore {
  #seen = new Map<string, number>();
  add(key: string, ttlSeconds: number): boolean {
    const now = Date.now();
    for (const [k, exp] of this.#seen) if (exp < now) this.#seen.delete(k);
    if (this.#seen.has(key)) return false;
    this.#seen.set(key, now + ttlSeconds * 1000);
    return true;
  }
}

export interface VerifierOptions {
  /**
   * Who may call. Required. messh usernames, "*" for any messh identity, the origin of another Web Bot
   * Auth agent ("https://agent.example", whose key directory is at <origin>/.well-known/http-message-signatures-directory),
   * or jwk:<thumbprint> for a key sent inline in Signature-Agent.
   */
  trust: string[];
  /** Accepted registry origins (default ["https://messh.io"]), or origin → fetch base URL. */
  registries?: string[] | Record<string, string>;
  /** Max |now − created| in seconds. Default 60. */
  maxSkew?: number;
  /** Key directory cache in seconds. Default 300. */
  cacheTtl?: number;
  /** Keep cached keys this long if messh is unreachable. Default 3600. */
  staleIfError?: number;
  /** Replay store. Default in memory. */
  nonceStore?: NonceStore;
  /** Directory fetch timeout. Default 5000 ms. */
  timeoutMs?: number;
  /** Largest request body messhAuth and verifyRequest read; bigger ones get 413 body_too_large. Default 1 MiB. */
  maxBodyBytes?: number;
  /** Seconds since epoch (tests). */
  clock?: () => number;
  /** Fixed directory or resolver (tests, air-gapped setups). */
  directory?: wba.Directory | ((agentUrl: string, identity: string) => Promise<wba.Directory>);
  /**
   * Components every signature must cover, replacing the default (@method, @authority, @path, signature-agent),
   * for agents that sign less. @target-uri counts for @authority, @path and @query, @request-target for @path and
   * @query. Signature-Agent, a query, and a body (through content-digest) must be covered regardless.
   */
  requireComponents?: string[];
  /** Ignore keys a fetched key directory doesn't sign (draft §5). messh.io doesn't sign its directories yet. */
  requireSignedDirectory?: boolean;
}

export interface VerifyInput {
  method: string;
  /** Full request URL. */
  url: string | URL;
  headers: Headers | Record<string, string | string[] | undefined>;
  body?: Uint8Array | string | null;
}

const fail = (code: string, msg: string, status = 401) => new VerifyError(code, msg, status);

/** A cached directory: dir is the last good answer (null: no such identity), fetched at `at`; failedAt is the last failed fetch; signed holds the key IDs the response signed. */
interface Entry {
  dir?: wba.Directory | null;
  signed?: Set<string>;
  at?: number;
  failedAt?: number;
}

type Found = { key: wba.JWK; pub: Uint8Array; signed: boolean };
/** Who a Signature-Agent names. */
type Who = { identity: string; external: boolean; fetchUrl?: string; inline?: wba.Directory };
type Fetched = { dir: wba.Directory; signed: Set<string> } | null | undefined;

function findKey(dir: wba.Directory | null | undefined, kid: string): { key: wba.JWK; pub: Uint8Array } | undefined {
  for (const key of dir?.keys ?? []) {
    const pub = wba.jwkPublicKey(key);
    if (pub && (key.kid === kid || (!key.kid && wba.thumbprint(pub) === kid))) return { key, pub };
  }
  return undefined;
}

export class Verifier {
  readonly trust: string[];
  readonly maxBodyBytes: number;
  private readonly registries: Map<string, string>;
  private readonly maxSkew: number;
  private readonly cacheTtl: number;
  private readonly staleIfError: number;
  private readonly nonces: NonceStore;
  private readonly timeoutMs: number;
  private readonly clock: () => number;
  private readonly directory?: VerifierOptions["directory"];
  private readonly required?: string[];
  private readonly requireSigned: boolean;
  private readonly cache = new Map<string, Entry>();
  private readonly inflight = new Map<string, Promise<Fetched>>();

  constructor(options: VerifierOptions) {
    if (!options?.trust?.length) throw new TypeError('trust is required, e.g. { trust: ["mukul"] } or ["*"]');
    this.trust = options.trust.map((t) => (/^https?:\/\//.test(t) ? t.toLowerCase().replace(/\/+$/, "") : t));
    const regs = options.registries ?? ["https://messh.io"];
    const pairs = Array.isArray(regs) ? regs.map((r) => [r, r]) : Object.entries(regs);
    this.registries = new Map(pairs.map(([o, b]) => [o.replace(/\/+$/, ""), b.replace(/\/+$/, "")]));
    this.maxSkew = options.maxSkew ?? 60;
    this.cacheTtl = options.cacheTtl ?? 300;
    this.staleIfError = options.staleIfError ?? 3600;
    this.nonces = options.nonceStore ?? new MemoryNonceStore();
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.maxBodyBytes = options.maxBodyBytes ?? MAX_BODY_BYTES;
    this.clock = options.clock ?? (() => Date.now() / 1000);
    this.directory = options.directory;
    this.required = options.requireComponents ? [...options.requireComponents] : undefined;
    this.requireSigned = options.requireSignedDirectory ?? false;
  }

  /** Verify one request; throws VerifyError. */
  async verify(input: VerifyInput): Promise<Agent> {
    const h = lower(input.headers);
    const now = this.clock();
    if (!h["signature-input"] || !h["signature"]) throw fail("missing_signature", "send Signature, Signature-Input and Signature-Agent (Web Bot Auth)");
    const u = new URL(input.url);
    const msg: HttpMessage = { method: input.method, url: u, headers: input.headers as HeaderInit };
    const sig = signatures(msg).find((s) => s.tag === wba.TAG);
    if (!sig) throw fail("bad_signature", 'no signature with tag="web-bot-auth"');
    this.coverage(sig, u.search !== "");
    const agentUrl = agentOf(h["signature-agent"], sig);
    if (sig.alg !== undefined && sig.alg !== "ed25519") throw fail("bad_signature", `alg ${sig.alg} is not supported`);

    const body = typeof input.body === "string" ? Buffer.from(input.body) : (input.body ?? new Uint8Array());
    if (covers(sig, "content-digest")) checkDigest(h["content-digest"] ?? "", body);
    else if (body.length) throw fail("bad_signature", "a request body must be covered by content-digest");

    const created = sig.created;
    if (created === undefined) throw fail("bad_signature", "created is required");
    if (Math.abs(now - created) > this.maxSkew) throw fail("clock_skew", `created is ${Math.round(now - created)}s from the server clock`);
    if (sig.expires !== undefined && (now > sig.expires || sig.expires - created > wba.MAX_LIFETIME)) throw fail("clock_skew", "signature expired");
    if (!sig.nonce) throw fail("bad_signature", "nonce is required");

    const who = this.classify(agentUrl, sig.keyid ?? "");
    // Before any fetch: callers outside the trust list can't make this API fetch directories.
    if (!this.trust.some((t) => t === who.identity || (t === "*" && !who.external))) {
      throw fail("untrusted", `${who.identity} is not in this API's trust list`, 403);
    }
    let found: Found | undefined;
    await verifySignature({ ...msg, body }, sig, {
      keys: async (kid) => (found = await this.lookup(agentUrl, who, kid)).pub,
      now, maxSkew: this.maxSkew, maxAge: this.maxSkew,
    });
    if (!(await this.nonces.add(`${agentUrl} ${sig.nonce}`, 2 * this.maxSkew))) throw fail("nonce_replayed", "this signature was already accepted once");
    const { key, pub, signed } = found!;
    return {
      identity: who.identity, keyName: key.messh_name ?? "", keyId: sig.keyid ?? "", fingerprint: key.messh_fingerprint ?? wba.fingerprint(pub),
      agentUrl, created, external: who.external, signedDirectory: signed,
    };
  }

  /** Verify a fetch Request (Workers, Hono, Next.js route handlers, Deno, Bun). */
  async verifyRequest(request: Request): Promise<Agent> {
    const body = request.body ? await readLimited(request.clone(), this.maxBodyBytes) : undefined;
    return this.verify({ method: request.method, url: request.url, headers: request.headers, body });
  }

  private coverage(s: Signature, hasQuery: boolean) {
    const has = (name: string) =>
      covers(s, name) ||
      (name === "@authority" && covers(s, "@target-uri")) ||
      ((name === "@path" || name === "@query") && (covers(s, "@target-uri") || covers(s, "@request-target")));
    for (const c of [...(this.required ?? DEFAULT_REQUIRED), "signature-agent"]) if (!has(c)) throw fail("bad_signature", `${c} must be covered`);
    if (hasQuery && !has("@query")) throw fail("bad_signature", "@query must be covered when the URL has a query");
  }

  /** Map Signature-Agent to a messh identity (<registry>/<user>), an agent origin, or inline keys, refusing anything else. */
  private classify(agentUrl: string, keyid: string): Who {
    if (agentUrl.startsWith("data:")) return { identity: `jwk:${keyid}`, external: true, inline: parseDataUri(agentUrl) };
    let u: URL;
    try {
      u = new URL(agentUrl);
    } catch {
      throw fail("bad_signature", "Signature-Agent is not a URL");
    }
    if (u.protocol !== "https:" && u.protocol !== "http:") throw fail("bad_signature", "Signature-Agent is not a URL");
    const base = this.registries.get(u.origin);
    if (base !== undefined) {
      const id = u.pathname.replace(/^\/+|\/+$/g, "");
      if (!IDENTITY.test(id)) throw fail("unknown_key", "Signature-Agent must be <registry>/<user>");
      return { identity: id, external: false, fetchUrl: `${base}/${id}${wba.DIRECTORY_PATH}` };
    }
    const origin = u.origin.toLowerCase();
    if (this.trust.includes(origin)) {
      if ((u.pathname !== "" && u.pathname !== "/") || u.search) {
        throw fail("untrusted", `Signature-Agent ${agentUrl}: an agent outside messh is an origin, like ${origin}`, 403);
      }
      return { identity: origin, external: true, fetchUrl: origin + wba.DIRECTORY_PATH };
    }
    throw fail("untrusted", `Signature-Agent ${agentUrl} is not a messh registry or an agent this API trusts`, 403);
  }

  /**
   * The signer's key for kid. Directories are cached for cacheTtl; an unknown
   * kid refetches at most every MIN_REFRESH s (so a key published a moment ago
   * works), unknown identities are remembered the same way, one fetch per
   * directory runs at a time, and while messh is unreachable cached keys keep
   * working for staleIfError.
   */
  private async lookup(agentUrl: string, who: Who, kid: string): Promise<Found> {
    const found = (dir?: wba.Directory | null, signed?: Set<string>): Found => {
      const hit = findKey(dir, kid);
      if (hit) return { ...hit, signed: signed?.has(kid) ?? false };
      throw dir === null
        ? fail("unknown_key", `there's no messh identity at ${agentUrl}`)
        : fail("unknown_key", `keyid ${kid} is not an active key of ${agentUrl}; publish it with messh publish`);
    };
    if (who.inline) return found(who.inline);
    if (this.directory) return found(typeof this.directory === "function" ? await this.directory(agentUrl, who.identity) : this.directory);
    const now = this.clock();
    let e = this.cache.get(agentUrl);
    const age = e?.at === undefined ? Infinity : now - e.at;
    if (age < this.cacheTtl) {
      if (findKey(e!.dir, kid)) return found(e!.dir, e!.signed);
      if (age < MIN_REFRESH) return found(e!.dir);
    }
    if (e?.failedAt === undefined || now - e.failedAt >= RETRY_AFTER) {
      const got = await this.fetchOnce(agentUrl, who.fetchUrl!);
      if (got !== undefined) {
        this.store(agentUrl, { dir: got?.dir ?? null, signed: got?.signed, at: now });
        return found(got?.dir ?? null, got?.signed);
      }
      e = { ...e, failedAt: now };
      this.store(agentUrl, e);
    }
    // The directory is unreachable: keep verifying with the cached one for a while.
    if (e?.dir !== undefined && now - e.at! < this.staleIfError) return found(e.dir, e.signed);
    throw fail("unknown_key", `key directory for ${agentUrl} is unavailable`);
  }

  /** Fetch a directory: it and the keys its response signs, null for no such identity, undefined if it couldn't be fetched. One request per URL at a time. */
  private fetchOnce(agentUrl: string, fetchUrl: string): Promise<Fetched> {
    let p = this.inflight.get(agentUrl);
    if (!p) {
      p = (async (): Promise<Fetched> => {
        try {
          const res = await fetch(fetchUrl, {
            headers: { accept: "application/http-message-signatures-directory+json, application/json", "user-agent": `messh-js/${VERSION}` },
            signal: AbortSignal.timeout(this.timeoutMs),
          });
          if (res.status === 404) return null;
          if (!res.ok) return undefined;
          const { directory, signed } = await verifyDirectory(fetchUrl, res.headers, new Uint8Array(await res.arrayBuffer()), this.clock());
          const keep = new Set(signed);
          if (this.requireSigned) directory.keys = directory.keys.filter((k) => k.kid !== undefined && keep.has(k.kid));
          return { dir: directory, signed: keep };
        } catch {
          return undefined;
        }
      })().finally(() => this.inflight.delete(agentUrl));
      this.inflight.set(agentUrl, p);
    }
    return p;
  }

  private store(agentUrl: string, e: Entry) {
    this.cache.delete(agentUrl); // re-insert: Map order is then least recently stored first
    this.cache.set(agentUrl, e);
    while (this.cache.size > MAX_ENTRIES) this.cache.delete(this.cache.keys().next().value!);
  }
}

/** Read Signature-Agent: the member named by the covered component's key parameter, else a string, else the member named like the label. */
function agentOf(header: string | undefined, s: Signature): string {
  if (!header) throw fail("bad_signature", "Signature-Agent header is missing");
  const str = (m?: sf.Member) => (m && !m.inner && m.bare.t === "str" ? m.bare.v : undefined);
  const keyed = s.covered.find((c) => c.name === "signature-agent" && c.key !== undefined);
  if (keyed) {
    let v: string | undefined;
    try { v = str(sf.member(sf.parseDictionary(header).dict, keyed.key!)); } catch { /* not a dictionary */ }
    if (v !== undefined) return v;
    throw fail("bad_signature", `Signature-Agent has no member ${keyed.key}`);
  }
  try {
    const it = sf.parseItem(header);
    if (it.bare.t === "str") return it.bare.v;
  } catch { /* not an item */ }
  let v: string | undefined;
  try { v = str(sf.member(sf.parseDictionary(header).dict, s.label)); } catch { /* not a dictionary */ }
  if (v !== undefined) return v;
  throw fail("bad_signature", `Signature-Agent has no value for ${s.label}`);
}

/** An inline key directory: data:application/http-message-signatures-directory[+json][;base64],… */
function parseDataUri(s: string): wba.Directory {
  const comma = s.indexOf(",");
  const meta = comma < 0 ? "" : s.slice(5, comma);
  const isBase64 = meta.endsWith(";base64");
  const mediaType = meta.replace(/;base64$/, "").split(";")[0].trim().toLowerCase();
  if (comma < 0 || !["application/http-message-signatures-directory", "application/http-message-signatures-directory+json", "application/json"].includes(mediaType)) {
    throw fail("bad_signature", "Signature-Agent: the data URI isn't a key directory");
  }
  try {
    const data = s.slice(comma + 1);
    const dir = JSON.parse(isBase64 ? Buffer.from(data, "base64").toString("utf8") : decodeURIComponent(data)) as wba.Directory;
    if (Array.isArray(dir?.keys)) return dir;
  } catch { /* below */ }
  throw fail("bad_signature", "Signature-Agent: the data URI isn't a key directory");
}

/**
 * Read a key directory response fetched from url: its keys, and the key IDs a
 * valid directory signature covers (tag http-message-signatures-directory,
 * signed by that key, binding the response to the authority it came from;
 * draft-meunier-http-message-signatures-directory §5).
 */
export async function verifyDirectory(url: string, headers: HeaderInit, body: Uint8Array | string, now = Date.now() / 1000): Promise<{ directory: wba.Directory; signed: string[] }> {
  const bytes = typeof body === "string" ? Buffer.from(body) : body;
  const directory = JSON.parse(Buffer.from(bytes).toString("utf8")) as wba.Directory;
  if (!Array.isArray(directory?.keys)) throw new Error("not a key directory");
  const u = new URL(url);
  // The response carries the request's URL too, for directories signed over a plain "@authority".
  const msg: HttpMessage = { status: 200, url: u, headers, body: bytes, request: { method: "GET", url: u } };
  const signed: string[] = [];
  let sigs: Signature[];
  try {
    sigs = signatures(msg);
  } catch {
    return { directory, signed };
  }
  for (const s of sigs) {
    const hit = s.tag === DIRECTORY_TAG ? findKey(directory, s.keyid ?? "") : undefined;
    if (!hit) continue;
    try {
      await verifySignature(msg, s, { keys: () => hit.pub, now });
      signed.push(s.keyid!);
    } catch { /* not signed */ }
  }
  return { directory, signed };
}

async function readLimited(request: Request, max: number): Promise<Uint8Array> {
  const reader = request.body!.getReader();
  const parts: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > max) {
      // Not awaited: on a cloned request the cancel settles only once the original's branch is done too.
      reader.cancel().catch(() => {});
      throw fail("body_too_large", `the request body is over this API's limit of ${max} bytes`, 413);
    }
    parts.push(value);
  }
  return Buffer.concat(parts);
}

function lower(headers: VerifyInput["headers"]): Record<string, string> {
  const out: Record<string, string> = {};
  const add = (k: string, v: string) => {
    k = k.toLowerCase();
    v = v.trim();
    out[k] = k in out ? `${out[k]}, ${v}` : v;
  };
  if (typeof (headers as Headers).forEach === "function" && typeof (headers as Headers).get === "function") {
    (headers as Headers).forEach((v, k) => add(k, v));
  } else {
    for (const [k, v] of Object.entries(headers as Record<string, string | string[] | undefined>)) {
      if (Array.isArray(v)) v.forEach((x) => add(k, x));
      else if (v !== undefined) add(k, v);
    }
  }
  return out;
}

/** Create a verifier (reuse it; it caches keys). */
export function createVerifier(options: VerifierOptions): Verifier {
  return new Verifier(options);
}

type Req = { method: string; originalUrl?: string; url: string; headers: Record<string, string | string[] | undefined>; protocol?: string; on: Function; body?: unknown; rawBody?: Buffer; agent?: Agent; _body?: boolean };
type Res = { status(code: number): Res; setHeader(k: string, v: string): void; json(body: unknown): void };

/**
 * Express / Connect middleware. Mount it before express.json(): it reads
 * the raw body, verifies, then sets req.rawBody, req.agent and (for JSON)
 * req.body. Set `trustProxy` if TLS ends at a proxy (uses X-Forwarded-Proto).
 */
export function messhAuth(options: VerifierOptions & { verifier?: Verifier; trustProxy?: boolean }) {
  const v = options.verifier ?? new Verifier(options);
  return (req: Req, res: Res, next: (err?: unknown) => void) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size <= v.maxBodyBytes) chunks.push(c);
    });
    req.on("error", next);
    req.on("end", async () => {
      if (size > v.maxBodyBytes) {
        res.status(413).json(fail("body_too_large", `the request body is over this API's limit of ${v.maxBodyBytes} bytes`, 413).toJSON());
        return;
      }
      const body = Buffer.concat(chunks);
      const proto = (options.trustProxy && String(req.headers["x-forwarded-proto"] ?? "").split(",")[0]) || req.protocol || "http";
      const url = `${proto}://${req.headers.host}${req.originalUrl ?? req.url}`;
      try {
        req.agent = await v.verify({ method: req.method, url, headers: req.headers, body });
      } catch (e) {
        const err = e instanceof VerifyError ? e : fail("bad_signature", String(e));
        if (err.status === 401) res.setHeader("Accept-Signature", ACCEPT_SIGNATURE);
        res.status(err.status).json(err.toJSON());
        return;
      }
      req.rawBody = body;
      if (body.length && String(req.headers["content-type"] ?? "").includes("json")) {
        try { req.body = JSON.parse(body.toString("utf8")); } catch { /* leave unparsed */ }
      }
      req._body = true; // body-parser: already read
      next();
    });
  };
}
