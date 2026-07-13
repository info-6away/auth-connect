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
