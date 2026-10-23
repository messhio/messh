// @messh/sdk: sign HTTP requests as a messh identity (Web Bot Auth).
import { randomBytes } from "node:crypto";
import { homedir } from "node:os";

import * as wba from "./wba.js";
import { MesshError } from "./errors.js";
import { keyEnv, keyFile, resolveKey, type KeySource, type Signer } from "./keys.js";

export { MesshError, VerifyError } from "./errors.js";
export { keyEnv, keyFile, keySeed, sshAgent, type KeySource, type Signer } from "./keys.js";
export { fingerprint, thumbprint, type Directory, type JWK } from "./wba.js";

export const VERSION = "0.1.0";
export const DEFAULT_REGISTRY = "https://messh.io";
const IDENTITY = /^[a-z0-9](?:[a-z0-9-]{1,28}[a-z0-9])$/;

export interface ClientOptions {
  /** messh username, e.g. "mukul". */
  identity: string;
  /** Signing key. Default: keyFile("~/.ssh/id_ed25519"). */
  key?: KeySource;
  /** messh registry base URL. Default: https://messh.io. */
  registry?: string;
  /** Signature lifetime in seconds. Default 60, max 300. */
  expiresIn?: number;
  /** Seconds since epoch (tests). */
  clock?: () => number;
  /** Nonce generator (tests). */
  nonce?: () => string;
}

export interface SignInput {
  method: string;
  /** Absolute URL. */
  url: string | URL;
  body?: Uint8Array | string | null;
  /** Host header, if different from the URL's host. */
  host?: string;
}

/** This client's key as messh lists it: what an API will see. See {@link MesshClient.whoami}. */
export interface PublishedKey {
  /** messh username, e.g. "mukul". */
  identity: string;
  /** The key's name on messh, e.g. "build-bot". */
  keyName: string;
  /** RFC 7638 thumbprint, sent as keyid. */
  keyId: string;
  /** SHA256:… of the SSH key. */
  fingerprint: string;
  /** Signature-Agent: <registry>/<identity>. */
  agentUrl: string;
}

export class MesshClient {
  private constructor(
    readonly identity: string,
    readonly registry: string,
    readonly keyId: string,
    /** SSH fingerprint of the signing key (SHA256:…), as `messh keys` and ssh-keygen -l print it. */
    readonly fingerprint: string,
    private readonly signer: Signer,
    private readonly expiresIn: number,
    private readonly clock: () => number,
    private readonly nonce: () => string,
  ) {}

  /** Create a client; loads the key once. */
  static async create(options: ClientOptions): Promise<MesshClient> {
    const { identity, registry = DEFAULT_REGISTRY, expiresIn = 60 } = options;
    if (!IDENTITY.test(identity ?? "")) throw new MesshError("invalid_identity", `${JSON.stringify(identity)} is not a messh username`);
    if (!/^https?:\/\//.test(registry)) throw new MesshError("invalid_option", "registry must be an http(s) URL");
    if (!(expiresIn >= 1 && expiresIn <= wba.MAX_LIFETIME)) throw new MesshError("invalid_option", "expiresIn must be 1..300 seconds");
    const signer = await resolveKey(options.key ?? keyFile(`${homedir()}/.ssh/id_ed25519`));
    const pub = await signer.publicKey();
    return new MesshClient(
      identity, registry.replace(/\/+$/, ""), wba.thumbprint(pub), wba.fingerprint(pub), signer, expiresIn,
      options.clock ?? (() => Math.floor(Date.now() / 1000)),
      options.nonce ?? (() => randomBytes(16).toString("base64url")),
    );
  }

  /**
   * Create a client from the environment, for agents and CI: MESSH_IDENTITY
   * (required), MESSH_KEY (PEM, or base64 of PEM or PKCS#8 DER) or
   * MESSH_KEY_FILE (default ~/.ssh/id_ed25519), and MESSH_REGISTRY.
   * Options you pass win over the environment.
   */
  static async fromEnv(overrides: Partial<ClientOptions> = {}): Promise<MesshClient> {
    const env = process.env;
    const identity = overrides.identity ?? env.MESSH_IDENTITY;
    if (!identity) throw new MesshError("invalid_identity", "set MESSH_IDENTITY to your messh username, or pass identity");
    const key = overrides.key ?? (env.MESSH_KEY ? keyEnv("MESSH_KEY") : env.MESSH_KEY_FILE ? keyFile(env.MESSH_KEY_FILE) : undefined);
    return MesshClient.create({ ...overrides, identity, key, registry: overrides.registry ?? (env.MESSH_REGISTRY || undefined) });
  }

  /**
   * Check that this client's key is published and active on messh, and how
   * APIs will see it. Run it once at startup: it turns the most common setup
   * mistake (an unpublished key, so every API answers 401 unknown_key) into a
   * clear error. Throws MesshError not_published or registry_unreachable.
   */
  async whoami(): Promise<PublishedKey> {
    const url = `${this.agent}${wba.DIRECTORY_PATH}`;
    let res: Response;
    try {
      res = await fetch(url, {
        headers: { accept: "application/http-message-signatures-directory+json, application/json", "user-agent": `messh-js/${VERSION}` },
        signal: AbortSignal.timeout(10_000),
      });
    } catch (e) {
      throw new MesshError("registry_unreachable", `can't reach ${this.registry}: ${(e as Error).message}`);
    }
    if (res.status === 404) {
      throw new MesshError("not_published", `${this.registry} has no user ${this.identity}; sign up, then publish this key (${this.fingerprint}) with messh publish`);
    }
    const dir = res.ok ? ((await res.json().catch(() => null)) as wba.Directory | null) : null;
    if (!dir) throw new MesshError("registry_unreachable", `${url} answered HTTP ${res.status} without a key directory`);
    const key = (dir.keys ?? []).find((k) => k.kid === this.keyId);
    if (!key) {
      throw new MesshError("not_published", `this key (${this.fingerprint}) isn't an active key of ${this.agent}; publish it with messh publish --key <key>.pub --name <name>`);
    }
    return { identity: this.identity, keyName: key.messh_name ?? "", keyId: this.keyId, fingerprint: key.messh_fingerprint ?? this.fingerprint, agentUrl: this.agent };
  }

  /** Signature-Agent URL: <registry>/<identity>. */
  get agent(): string {
    return `${this.registry}/${this.identity}`;
  }

  /**
   * Headers to add: Signature-Agent, Signature-Input, Signature and, with a
   * body, Content-Digest. Sign last; don't change the request afterwards.
   */
  async sign(input: SignInput): Promise<Record<string, string>> {
    const u = new URL(input.url);
    const agentHeader = wba.quote(this.agent);
    const comps: [string, string][] = [
      ["@method", input.method.toUpperCase()],
      ["@authority", (input.host ?? u.host).toLowerCase()],
      ["@path", u.pathname || "/"],
    ];
    if (u.search) comps.push(["@query", u.search]);
    const headers: Record<string, string> = { "Signature-Agent": agentHeader };
    if (input.body && input.body.length) {
      const data = typeof input.body === "string" ? Buffer.from(input.body) : input.body;
      headers["Content-Digest"] = wba.contentDigest(data);
      comps.push(["content-digest", headers["Content-Digest"]]);
    }
    comps.push(["signature-agent", agentHeader]);
    const created = Math.floor(this.clock());
    const params = wba.params(comps.map(([n]) => n), created, created + this.expiresIn, this.keyId, this.nonce());
    let sig: Uint8Array;
    try {
      sig = await this.signer.sign(wba.base(comps, params));
    } catch (e) {
      throw new MesshError("sign_failed", (e as Error).message);
    }
    headers["Signature-Input"] = `${wba.LABEL}=${params}`;
    headers["Signature"] = `${wba.LABEL}=:${Buffer.from(sig).toString("base64")}:`;
    return headers;
  }

  /** Return a signed copy of a fetch Request. */
  async signRequest(request: Request): Promise<Request> {
    const body = request.body ? new Uint8Array(await request.clone().arrayBuffer()) : undefined;
    const headers = new Headers(request.headers);
    for (const [k, v] of Object.entries(await this.sign({ method: request.method, url: request.url, body }))) headers.set(k, v);
    return new Request(request, { headers, body });
  }

  /** fetch(), signed. Bodies must be strings or bytes (they're hashed). */
  async fetch(input: string | URL, init: RequestInit = {}): Promise<Response> {
    const body = init.body;
    if (body != null && typeof body !== "string" && !(body instanceof Uint8Array)) {
      throw new MesshError("sign_failed", "body must be a string or Uint8Array to be signed");
    }
    const headers = new Headers(init.headers);
    const method = (init.method ?? (body != null ? "POST" : "GET")).toUpperCase();
    for (const [k, v] of Object.entries(await this.sign({ method, url: input, body: body as string | Uint8Array | null }))) headers.set(k, v);
    if (!headers.has("user-agent")) headers.set("user-agent", `messh-js/${VERSION}`);
    return fetch(input, { ...init, method, headers });
  }
}
