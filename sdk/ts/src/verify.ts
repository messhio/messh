// @messh/sdk/verify: verify Web Bot Auth signatures with keys from messh.
import { createPublicKey, verify as edVerify } from "node:crypto";

import * as wba from "./wba.js";
import { VerifyError } from "./errors.js";
import { VERSION } from "./index.js";

export { VerifyError } from "./errors.js";

export const ACCEPT_SIGNATURE = 'sig1=("@method" "@authority" "@path" "signature-agent");keyid;created;expires;nonce;alg="ed25519";tag="web-bot-auth"';
const IDENTITY = /^[a-z0-9](?:[a-z0-9-]{1,28}[a-z0-9])$/;
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

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
  /** messh username, e.g. "mukul". */
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
  /** Who may call: messh usernames, or "*". Required. */
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
}

export interface VerifyInput {
  method: string;
  /** Full request URL. */
  url: string | URL;
  headers: Headers | Record<string, string | string[] | undefined>;
  body?: Uint8Array | string | null;
}

const fail = (code: string, msg: string, status = 401) => new VerifyError(code, msg, status);

/** A cached directory: dir is the last good answer (null: no such identity), fetched at `at`; failedAt is the last failed fetch. */
interface Entry {
  dir?: wba.Directory | null;
  at?: number;
  failedAt?: number;
}

type Found = { key: wba.JWK; pub: Uint8Array };

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
  private readonly cache = new Map<string, Entry>();
  private readonly inflight = new Map<string, Promise<wba.Directory | null | undefined>>();

  constructor(options: VerifierOptions) {
    if (!options?.trust?.length) throw new TypeError('trust is required, e.g. { trust: ["mukul"] } or ["*"]');
    this.trust = [...options.trust];
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
  }

  /** Verify one request; throws VerifyError. */
  async verify(input: VerifyInput): Promise<Agent> {
    const h = lower(input.headers);
    const now = this.clock();
    if (!h["signature-input"] || !h["signature"]) throw fail("missing_signature", "send Signature, Signature-Input and Signature-Agent (Web Bot Auth)");
    let sp: wba.SigParams, sig: Uint8Array;
    try {
      sp = wba.pickWebBotAuth(h["signature-input"]);
      sig = wba.signatureBytes(h["signature"], sp.label);
    } catch (e) {
      throw fail("bad_signature", (e as Error).message);
    }
    for (const c of ["@method", "@authority", "@path", "signature-agent"]) {
      if (!sp.components.includes(c)) throw fail("bad_signature", `${c} must be covered`);
    }
    const u = new URL(input.url);
    if (u.search && !sp.components.includes("@query")) throw fail("bad_signature", "@query must be covered when the URL has a query");
    if (!h["signature-agent"]) throw fail("bad_signature", "Signature-Agent header is missing");
    let agentUrl: string;
    try {
      agentUrl = wba.parseAgent(h["signature-agent"], sp.label);
    } catch (e) {
      throw fail("bad_signature", (e as Error).message);
    }
    if ((sp.params.alg ?? "ed25519") !== "ed25519") throw fail("bad_signature", `alg ${sp.params.alg} is not supported`);

    const body = typeof input.body === "string" ? Buffer.from(input.body) : (input.body ?? new Uint8Array());
    if (sp.components.includes("content-digest")) {
      if (h["content-digest"] !== wba.contentDigest(body)) throw fail("digest_mismatch", "the body doesn't match Content-Digest");
    } else if (body.length) {
      throw fail("bad_signature", "a request body must be covered by content-digest");
    }

    const created = Number.parseInt(sp.params.created ?? "", 10);
    if (!Number.isFinite(created)) throw fail("bad_signature", "created is required");
    if (Math.abs(now - created) > this.maxSkew) throw fail("clock_skew", `created is ${Math.round(now - created)}s from the server clock`);
    if (sp.params.expires !== undefined) {
      const expires = Number.parseInt(sp.params.expires, 10);
      if (!Number.isFinite(expires) || now > expires || expires - created > wba.MAX_LIFETIME) throw fail("clock_skew", "signature expired");
    }
    const nonce = sp.params.nonce;
    if (!nonce) throw fail("bad_signature", "nonce is required");

    const identity = this.identityOf(agentUrl);
    // Before any fetch: callers outside the trust list can't make this API fetch directories.
    if (!this.trust.includes("*") && !this.trust.includes(identity)) throw fail("untrusted", `${identity} is not in this API's trust list`, 403);
    const kid = sp.params.keyid ?? "";
    const { key, pub } = await this.lookup(agentUrl, identity, kid);

    const values: Record<string, string> = {
      "@method": input.method.toUpperCase(),
      "@authority": (h["host"] ?? u.host).toLowerCase(),
      "@path": u.pathname || "/",
      "@query": u.search || "?",
    };
    const comps: [string, string][] = sp.components.map((c) => {
      if (c in values) return [c, values[c]];
      if (c.startsWith("@")) throw fail("bad_signature", `unsupported component ${c}`);
      if (h[c] === undefined) throw fail("bad_signature", `covered header ${c} is missing`);
      return [c, h[c]];
    });
    const publicKey = createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, pub]), format: "der", type: "spki" });
    if (!edVerify(null, wba.base(comps, sp.raw), publicKey, sig)) throw fail("bad_signature", "the signature doesn't match the request");
    if (!(await this.nonces.add(`${agentUrl} ${nonce}`, 2 * this.maxSkew))) throw fail("nonce_replayed", "this signature was already accepted once");
    return { identity, keyName: key.messh_name ?? "", keyId: kid, fingerprint: key.messh_fingerprint ?? "", agentUrl, created };
  }

  /** Verify a fetch Request (Workers, Hono, Next.js route handlers, Deno, Bun). */
  async verifyRequest(request: Request): Promise<Agent> {
    const body = request.body ? await readLimited(request.clone(), this.maxBodyBytes) : undefined;
    return this.verify({ method: request.method, url: request.url, headers: request.headers, body });
  }

  private identityOf(agentUrl: string): string {
    let u: URL;
    try { u = new URL(agentUrl); } catch { throw fail("bad_signature", "Signature-Agent is not a URL"); }
    if (!this.registries.has(u.origin)) throw fail("untrusted", `Signature-Agent ${agentUrl} is not a messh registry this API accepts`, 403);
    const id = u.pathname.replace(/^\/+|\/+$/g, "");
    if (!IDENTITY.test(id)) throw fail("unknown_key", "Signature-Agent must be <registry>/<user>");
    return id;
  }

  /**
   * The signer's key for kid. Directories are cached for cacheTtl; an unknown
   * kid refetches at most every MIN_REFRESH s (so a key published a moment ago
   * works), unknown identities are remembered the same way, one fetch per
   * directory runs at a time, and while messh is unreachable cached keys keep
   * working for staleIfError.
   */
  private async lookup(agentUrl: string, identity: string, kid: string): Promise<Found> {
    const find = (dir?: wba.Directory | null): Found | undefined => {
      for (const key of dir?.keys ?? []) {
        if (key.kid !== kid) continue;
        const pub = wba.jwkPublicKey(key);
        if (pub) return { key, pub };
      }
      return undefined;
    };
    const found = (dir?: wba.Directory | null): Found => {
      const hit = find(dir);
      if (hit) return hit;
      throw dir === null
        ? fail("unknown_key", `there's no messh identity at ${agentUrl}`)
        : fail("unknown_key", `keyid ${kid} is not an active key of ${agentUrl}; publish it with messh publish`);
    };
    if (this.directory) return found(typeof this.directory === "function" ? await this.directory(agentUrl, identity) : this.directory);
    const now = this.clock();
    let e = this.cache.get(agentUrl);
    const age = e?.at === undefined ? Infinity : now - e.at;
    if (age < this.cacheTtl) {
      const hit = find(e!.dir);
      if (hit) return hit;
      if (age < MIN_REFRESH) return found(e!.dir);
    }
    if (e?.failedAt === undefined || now - e.failedAt >= RETRY_AFTER) {
      const dir = await this.fetchOnce(agentUrl, identity);
      if (dir !== undefined) {
        this.store(agentUrl, { dir, at: now });
        return found(dir);
      }
      e = { ...e, failedAt: now };
      this.store(agentUrl, e);
    }
    // messh is unreachable: keep verifying with the cached directory for a while.
    if (e?.dir !== undefined && now - e.at! < this.staleIfError) return found(e.dir);
    throw fail("unknown_key", `key directory for ${agentUrl} is unavailable`);
  }

  /** Fetch a directory: the directory, null for no such identity, undefined if messh couldn't answer. One request per URL at a time. */
  private fetchOnce(agentUrl: string, identity: string): Promise<wba.Directory | null | undefined> {
    let p = this.inflight.get(agentUrl);
    if (!p) {
      const url = `${this.registries.get(new URL(agentUrl).origin)}/${identity}${wba.DIRECTORY_PATH}`;
      p = (async () => {
        try {
          const res = await fetch(url, {
            headers: { accept: "application/http-message-signatures-directory+json, application/json", "user-agent": `messh-js/${VERSION}` },
            signal: AbortSignal.timeout(this.timeoutMs),
          });
          if (res.status === 404) return null;
          const dir = res.ok ? ((await res.json()) as wba.Directory) : undefined;
          return dir && Array.isArray(dir.keys) ? dir : undefined;
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
