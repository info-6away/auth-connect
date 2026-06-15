// NOTE: no "server-only" import — this module is used by Next.js middleware
// (via "@6away/auth-connect/middleware"), which runs outside the RSC graph and
// may execute on the Edge runtime. It therefore uses the Web Crypto API
// (globalThis.crypto.subtle) instead of node:crypto, so the exact same HMAC the
// server signs with in session.ts can be verified in either runtime.

// Return type intentionally inferred (not annotated `Uint8Array`): under
// TS 5.7+ typed arrays are generic over their backing buffer, and an explicit
// `Uint8Array` annotation widens to `Uint8Array<ArrayBufferLike>`, which is not
// assignable to the `BufferSource` (ArrayBuffer-backed) that SubtleCrypto wants.
function b64urlToBytes(s: string) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64.padEnd(Math.ceil(b64.length / 4) * 4, "=");
  const bin = atob(padded);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export type VerifiedSession = { exp?: number; [k: string]: unknown };

/**
 * Verify the `value.mac` cookie produced by session.ts — where
 * `mac = base64url(HMAC-SHA256(secret, value))` — and the embedded `exp`.
 * Returns the decoded payload when the signature is valid AND the session has
 * not expired; otherwise null. Constant-time via SubtleCrypto.verify.
 */
export async function verifySessionCookie(
  signed: string,
  secret: string,
): Promise<VerifiedSession | null> {
  const i = signed.lastIndexOf(".");
  if (i < 0) return null;
  const value = signed.slice(0, i);
  const mac = signed.slice(i + 1);

  let ok = false;
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"],
    );
    ok = await crypto.subtle.verify("HMAC", key, b64urlToBytes(mac), new TextEncoder().encode(value));
  } catch {
    return null;
  }
  if (!ok) return null;

  try {
    const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(value))) as VerifiedSession;
    if (typeof payload.exp === "number" && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}
