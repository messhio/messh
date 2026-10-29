// Web Bot Auth constants and key formats: key directories, RFC 7638
// thumbprints, SSH fingerprints and RFC 9530 Content-Digest. Signatures are
// httpsig.ts.
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

export function jwkPublicKey(jwk: JWK): Uint8Array | null {
  if (jwk?.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") return null;
  const pub = Buffer.from(jwk.x, "base64url");
  if (pub.length !== 32 || (jwk.kid && jwk.kid !== thumbprint(pub))) return null;
  return pub;
}
