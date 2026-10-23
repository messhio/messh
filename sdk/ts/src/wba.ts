// Web Bot Auth wire format: RFC 9421 signature base, structured-field
// parsing, RFC 7638 thumbprints and RFC 9530 Content-Digest.
import { createHash } from "node:crypto";

export const TAG = "web-bot-auth";
export const LABEL = "sig1";
export const DIRECTORY_PATH = "/.well-known/http-message-signatures-directory";
export const MAX_LIFETIME = 300;

export interface JWK {
  kty: string;
  crv: string;
  x: string;
  kid?: string;
  messh_name?: string;
  messh_fingerprint?: string;
}

export interface Directory {
  keys: JWK[];
}

const b64url = (b: Uint8Array) => Buffer.from(b).toString("base64url");

export function thumbprint(publicKey: Uint8Array): string {
  return createHash("sha256").update(`{"crv":"Ed25519","kty":"OKP","x":"${b64url(publicKey)}"}`).digest("base64url");
}

/** SSH wire-format string: uint32 length, then the bytes. */
export function sshString(b: Uint8Array): Buffer {
  const n = Buffer.alloc(4);
  n.writeUInt32BE(b.length);
  return Buffer.concat([n, b]);
}

/** The key's SSH fingerprint, as ssh-keygen -l and messh print it: SHA256:… */
export function fingerprint(publicKey: Uint8Array): string {
  const blob = Buffer.concat([sshString(Buffer.from("ssh-ed25519")), sshString(publicKey)]);
  return "SHA256:" + createHash("sha256").update(blob).digest("base64").replace(/=+$/, "");
}

export function contentDigest(body: Uint8Array): string {
  return `sha-256=:${createHash("sha256").update(body).digest("base64")}:`;
}

export const quote = (s: string) => JSON.stringify(s);

export function params(names: string[], created: number, expires: number, keyid: string, nonce: string): string {
  return `(${names.map(quote).join(" ")});created=${created};expires=${expires};keyid=${quote(keyid)};alg="ed25519";nonce=${quote(nonce)};tag="${TAG}"`;
}

export function base(components: [string, string][], sigParams: string): Uint8Array {
  const lines = components.map(([n, v]) => `${quote(n)}: ${v}`);
  lines.push(`"@signature-params": ${sigParams}`);
  return Buffer.from(lines.join("\n"));
}

export interface SigParams {
  label: string;
  components: string[];
  params: Record<string, string>;
  raw: string;
}

function splitTop(s: string): string[] {
  const out: string[] = [];
  let depth = 0, inStr = false, start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr && c === "\\") { i++; continue; }
    if (c === '"') inStr = !inStr;
    else if (!inStr) {
      if (c === "(") depth++;
      else if (c === ")") depth--;
      else if (c === "," && depth === 0) { out.push(s.slice(start, i).trim()); start = i + 1; }
    }
  }
  out.push(s.slice(start).trim());
  return out;
}

const cut = (s: string, sep: string): [string, string, boolean] => {
  const i = s.indexOf(sep);
  return i < 0 ? [s, "", false] : [s.slice(0, i), s.slice(i + sep.length), true];
};

const unquote = (v: string) => (v.length >= 2 && v[0] === '"' && v[v.length - 1] === '"' ? JSON.parse(v) : v);

function member(label: string, raw: string): SigParams {
  if (!raw.startsWith("(")) throw new Error("Signature-Input member is not an inner list");
  const end = raw.indexOf(")");
  if (end < 0) throw new Error("unterminated inner list");
  const components = raw.slice(1, end).split(/\s+/).filter(Boolean).map((item) => {
    if (!item.startsWith('"') || !item.endsWith('"')) throw new Error(`bad component ${item}`);
    return JSON.parse(item) as string;
  });
  const ps: Record<string, string> = {};
  for (const p of raw.slice(end + 1).split(";").slice(1)) {
    const [k, v] = cut(p, "=");
    ps[k.trim()] = unquote(v);
  }
  return { label, components, params: ps, raw };
}

export function pickWebBotAuth(header: string): SigParams {
  for (const m of splitTop(header)) {
    const [label, raw, ok] = cut(m, "=");
    if (!ok) continue;
    const sp = member(label, raw);
    if (sp.params.tag === TAG) return sp;
  }
  throw new Error('no signature with tag="web-bot-auth"');
}

export function signatureBytes(header: string, label: string): Uint8Array {
  for (const m of splitTop(header)) {
    const [l, v] = cut(m, "=");
    if (l === label && v.length > 2 && v[0] === ":" && v[v.length - 1] === ":") return Buffer.from(v.slice(1, -1), "base64");
  }
  throw new Error(`no Signature for ${label}`);
}

export function parseAgent(header: string, label: string): string {
  const h = header.trim();
  if (h.startsWith('"')) return JSON.parse(h);
  for (const m of splitTop(h)) {
    const [l, v, ok] = cut(m, "=");
    if (ok && l === label) return JSON.parse(v);
  }
  throw new Error(`Signature-Agent has no value for ${label}`);
}

export function jwkPublicKey(jwk: JWK): Uint8Array | null {
  if (jwk?.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") return null;
  const pub = Buffer.from(jwk.x, "base64url");
  if (pub.length !== 32 || (jwk.kid && jwk.kid !== thumbprint(pub))) return null;
  return pub;
}
