// Key sources. Keys are used locally; they never go to messh.
import { createHash, createPrivateKey, createPublicKey, sign as edSign, type KeyObject } from "node:crypto";
import { readFile } from "node:fs/promises";
import { connect } from "node:net";
import { homedir } from "node:os";

import { MesshError } from "./errors.js";
import { sshString } from "./wba.js";

/** Implement to sign in a KMS, HSM or ssh-agent. */
export interface Signer {
  /** Raw 32-byte Ed25519 public key. */
  publicKey(): Uint8Array | Promise<Uint8Array>;
  /** 64-byte Ed25519 signature over data. */
  sign(data: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

/** A Signer, or something that loads one. */
export type KeySource = Signer | (() => Promise<Signer>);

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

class LocalSigner implements Signer {
  readonly #key: KeyObject;
  readonly #pub: Uint8Array;
  constructor(key: KeyObject) {
    if (key.asymmetricKeyType !== "ed25519") throw new MesshError("invalid_key", "need an Ed25519 key");
    this.#key = key;
    const der = createPublicKey(key).export({ format: "der", type: "spki" });
    this.#pub = new Uint8Array(der.subarray(der.length - 32));
  }
  publicKey() { return this.#pub; }
  sign(data: Uint8Array) { return new Uint8Array(edSign(null, data, this.#key)); }
  toJSON() { return "messh.Signer(ed25519)"; }
}

function fromSeed(seed: Uint8Array): LocalSigner {
  if (seed.length !== 32) throw new MesshError("invalid_key", "seed must be 32 bytes");
  return new LocalSigner(createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: "der", type: "pkcs8" }));
}

/** Unpack the openssh-key-v1 container (PROTOCOL.key) to the Ed25519 seed. */
function fromOpenSSH(pem: string): LocalSigner {
  const buf = Buffer.from(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
  const magic = "openssh-key-v1\0";
  if (buf.subarray(0, magic.length).toString("latin1") !== magic) throw new MesshError("invalid_key", "not an OpenSSH private key");
  let off = magic.length;
  const take = (b: Buffer, o: number): [Buffer, number] => {
    if (o + 4 > b.length) throw new MesshError("invalid_key", "truncated OpenSSH key");
    const n = b.readUInt32BE(o);
    if (o + 4 + n > b.length) throw new MesshError("invalid_key", "truncated OpenSSH key");
    return [b.subarray(o + 4, o + 4 + n), o + 4 + n];
  };
  let cipher: Buffer;
  [cipher, off] = take(buf, off);
  if (cipher.toString() !== "none") throw new MesshError("invalid_key", "passphrase-protected key; load it into ssh-agent (ssh-add) and use sshAgent()");
  [, off] = take(buf, off);
  [, off] = take(buf, off);
  if (buf.readUInt32BE(off) !== 1) throw new MesshError("invalid_key", "expected one key");
  off += 4;
  [, off] = take(buf, off);
  const [priv] = take(buf, off);
  if (priv.readUInt32BE(0) !== priv.readUInt32BE(4)) throw new MesshError("invalid_key", "OpenSSH check bytes differ");
  let p = 8, type: Buffer, pub: Buffer, sk: Buffer;
  [type, p] = take(priv, p);
  if (type.toString() !== "ssh-ed25519") throw new MesshError("invalid_key", `need an ssh-ed25519 key, got ${type}`);
  [pub, p] = take(priv, p);
  [sk, p] = take(priv, p);
  if (sk.length !== 64 || !sk.subarray(32).equals(pub)) throw new MesshError("invalid_key", "malformed ssh-ed25519 private key");
  return fromSeed(sk.subarray(0, 32));
}

function parse(data: Buffer): LocalSigner {
  const text = data.toString("utf8");
  if (text.includes("OPENSSH PRIVATE KEY")) return fromOpenSSH(text);
  if (text.includes("ENCRYPTED PRIVATE KEY")) throw new MesshError("invalid_key", "encrypted keys aren't supported; load the key into ssh-agent and use sshAgent()");
  try {
    return new LocalSigner(text.includes("-----BEGIN") ? createPrivateKey(text) : createPrivateKey({ key: data, format: "der", type: "pkcs8" }));
  } catch (e) {
    if (e instanceof MesshError) throw e;
    throw new MesshError("invalid_key", (e as Error).message);
  }
}

/** Unencrypted ssh-ed25519 OpenSSH key or PKCS#8 PEM, e.g. ~/.ssh/id_ed25519. */
export function keyFile(path: string): () => Promise<Signer> {
  return async () => {
    const p = path.startsWith("~/") ? homedir() + path.slice(1) : path;
    let data: Buffer;
    try {
      data = await readFile(p);
    } catch (e) {
      const hint = (e as NodeJS.ErrnoException).code === "ENOENT" ? "; create one with ssh-keygen -t ed25519, then messh publish" : "";
      throw new MesshError("invalid_key", `read ${path}: ${(e as Error).message}${hint}`);
    }
    return parse(data);
  };
}

/**
 * A key held by ssh-agent, such as a passphrase-protected key you added with
 * ssh-add. The private key stays in the agent. With several Ed25519 keys
 * loaded, pass the fingerprint (SHA256:…) of the one you published.
 */
export function sshAgent(options: { fingerprint?: string; socket?: string } = {}): () => Promise<Signer> {
  return async () => {
    const path = options.socket ?? process.env.SSH_AUTH_SOCK ?? (process.platform === "win32" ? "\\\\.\\pipe\\openssh-ssh-agent" : "");
    if (!path) throw new MesshError("invalid_key", 'ssh-agent isn\'t running (SSH_AUTH_SOCK is not set); start it: eval "$(ssh-agent)" && ssh-add');
    const reply = await agentCall(path, Buffer.from([AGENTC_REQUEST_IDENTITIES]));
    if (reply[0] !== AGENT_IDENTITIES_ANSWER) throw new MesshError("invalid_key", "ssh-agent wouldn't list its keys");
    const keys: { blob: Buffer; pub: Buffer; fingerprint: string }[] = [];
    let off = 5;
    for (let i = reply.readUInt32BE(1); i > 0; i--) {
      const [blob, o1] = take(reply, off);
      [, off] = take(reply, o1); // comment
      const [type, o2] = take(blob, 0);
      if (type.toString() !== "ssh-ed25519") continue;
      const [pub] = take(blob, o2);
      keys.push({ blob, pub, fingerprint: "SHA256:" + createHash("sha256").update(blob).digest("base64").replace(/=+$/, "") });
    }
    const list = keys.map((k) => k.fingerprint).join(", ");
    if (!keys.length) throw new MesshError("invalid_key", "ssh-agent has no Ed25519 keys; add yours with ssh-add ~/.ssh/id_ed25519");
    const pick = options.fingerprint ? keys.filter((k) => k.fingerprint === options.fingerprint) : keys;
    if (!pick.length) throw new MesshError("invalid_key", `ssh-agent has no key ${options.fingerprint}; it has ${list}`);
    if (pick.length > 1) throw new MesshError("invalid_key", `ssh-agent has ${keys.length} Ed25519 keys; choose one with sshAgent({ fingerprint }): ${list}`);
    return new AgentSigner(path, pick[0].blob, new Uint8Array(pick[0].pub));
  };
}

// ssh-agent protocol (draft-miller-ssh-agent): uint32 length, message type, payload.
const AGENTC_REQUEST_IDENTITIES = 11, AGENT_IDENTITIES_ANSWER = 12, AGENTC_SIGN_REQUEST = 13, AGENT_SIGN_RESPONSE = 14;

class AgentSigner implements Signer {
  constructor(private readonly path: string, private readonly blob: Buffer, private readonly pub: Uint8Array) {}
  publicKey() { return this.pub; }
  async sign(data: Uint8Array) {
    const flags = Buffer.alloc(4);
    const reply = await agentCall(this.path, Buffer.concat([Buffer.from([AGENTC_SIGN_REQUEST]), sshString(this.blob), sshString(data), flags]));
    if (reply[0] !== AGENT_SIGN_RESPONSE) throw new Error("ssh-agent refused to sign; is the key still loaded (ssh-add -l)?");
    const [sigBlob] = take(reply, 1);
    const [type, o] = take(sigBlob, 0);
    const [sig] = take(sigBlob, o);
    if (type.toString() !== "ssh-ed25519" || sig.length !== 64) throw new Error("ssh-agent returned an unexpected signature");
    return new Uint8Array(sig);
  }
  toJSON() { return "messh.Signer(ssh-agent)"; }
}

function take(b: Buffer, o: number): [Buffer, number] {
  if (o + 4 > b.length || o + 4 + b.readUInt32BE(o) > b.length) throw new MesshError("invalid_key", "malformed ssh-agent reply");
  const n = b.readUInt32BE(o);
  return [b.subarray(o + 4, o + 4 + n), o + 4 + n];
}

function agentCall(path: string, msg: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const sock = connect(path);
    let buf = Buffer.alloc(0);
    sock.setTimeout(30_000, () => sock.destroy(new Error("ssh-agent timed out")));
    sock.on("connect", () => sock.write(sshString(msg)));
    sock.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)) {
        sock.end();
        resolve(buf.subarray(4, 4 + buf.readUInt32BE(0)));
      }
    });
    sock.on("error", (e) => reject(new MesshError("invalid_key", `ssh-agent at ${path}: ${e.message}`)));
    sock.on("close", () => reject(new MesshError("invalid_key", `ssh-agent at ${path} closed the connection`)));
  });
}

/** Key in an environment variable: PEM text, or base64 of PEM or PKCS#8 DER. */
export function keyEnv(name: string): () => Promise<Signer> {
  return async () => {
    const v = (process.env[name] ?? "").trim();
    if (!v) throw new MesshError("invalid_key", `environment variable ${name} is empty`);
    return parse(v.includes("-----BEGIN") ? Buffer.from(v) : Buffer.from(v, "base64"));
  };
}

/** Raw 32-byte Ed25519 seed. */
export function keySeed(seed: Uint8Array): () => Promise<Signer> {
  return async () => fromSeed(seed);
}

export async function resolveKey(source: KeySource): Promise<Signer> {
  const signer = typeof source === "function" ? await source() : source;
  if ((await signer.publicKey()).length !== 32) throw new MesshError("invalid_key", "signer has no Ed25519 public key");
  return signer;
}
