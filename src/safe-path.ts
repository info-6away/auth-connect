// Same-origin path validation, shared by `safeReturnTo` (post-auth landing) and
// `errorPath` (branded callback-failure page).
//
// Deliberately dependency-free and WITHOUT the "server-only" import so it can be
// unit-tested in plain Node. The modules that consume it keep their own
// "server-only" guards.
//
// The naive `startsWith("/")` check is broken: protocol-relative inputs like
// "//evil.com/x" and "/\evil.com/x" pass it, and `new URL(dest, origin)` then
// resolves them to a fully cross-origin URL. Accept only same-origin paths:
//   - must begin with "/"
//   - the second character must not be "/" or "\" (rejects protocol-relative and
//     backslash-tricked variants that some URL parsers normalise)
//
// Anything not starting with "/" — "https://evil.com", "javascript:alert(1)",
// "//evil.com" — is rejected by the first two rules.
export function isSafeInternalPath(input: unknown): input is string {
  if (typeof input !== "string" || input.length === 0) return false;
  if (input[0] !== "/") return false;
  if (input.length > 1 && (input[1] === "/" || input[1] === "\\")) return false;
  return true;
}

// C0 + DEL control characters are never legitimate in a configured path, and
// CR/LF in particular is a header/redirect-splitting vector. Written as a
// char-code scan rather than a regex literal so the source stays free of raw
// control bytes.
export function hasControlChars(input: string): boolean {
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return true;
  }
  return false;
}

// Origin used only to resolve a candidate and compare. Never contacted.
const PROBE_ORIGIN = "https://auth-connect.invalid";

// The post-auth redirect rule (`safeReturnTo`): a same-origin relative
// application path, and nothing a URL parser could turn into anything else.
//
// `isSafeInternalPath` alone is not enough for a user-supplied value: the URL
// parser silently drops tab, CR and LF and treats "\" as "/", so
// "/\t/evil.com" passed the two-character check and `new URL(dest, origin)`
// resolved it to "https://evil.com/". On top of `isSafeInternalPath` this
// rejects:
//   - backslashes and control characters anywhere, literal or percent-encoded;
//   - a value whose decoded form is not itself a safe internal path
//     ("/%2F%2Fevil.com");
//   - anything that, resolved the way the callback resolves it, lands on
//     another origin. This is the authoritative check; the others state the
//     rule explicitly and catch forms a later decode could expose.
export function isSafeRedirectPath(input: unknown): input is string {
  if (!isSafeInternalPath(input)) return false;
  if (input.includes("\\") || hasControlChars(input)) return false;

  let decoded: string;
  try {
    decoded = decodeURIComponent(input);
  } catch {
    return false;
  }
  if (!isSafeInternalPath(decoded) || decoded.includes("\\") || hasControlChars(decoded)) {
    return false;
  }

  let resolved: URL;
  try {
    resolved = new URL(input, PROBE_ORIGIN);
  } catch {
    return false;
  }
  return resolved.origin === PROBE_ORIGIN;
}
