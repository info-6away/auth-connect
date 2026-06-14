import "server-only";
import { createHash, randomBytes } from "node:crypto";

export function base64url(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf).toString("base64url");
}

export function randomToken(bytes = 32): string {
  return base64url(randomBytes(bytes));
}

export function sha256(input: string): Buffer {
  return createHash("sha256").update(input).digest();
}

// PKCE S256: code_challenge = BASE64URL(SHA256(code_verifier))
export function makePkce(): { verifier: string; challenge: string } {
  const verifier = randomToken(32);
  const challenge = base64url(sha256(verifier));
  return { verifier, challenge };
}
