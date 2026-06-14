import "server-only";

// Validate a post-auth `returnTo` so it can never be turned into an open
// redirect. The naive `startsWith("/")` check is broken: protocol-relative
// inputs like "//evil.com/x" and "/\evil.com/x" pass it, and
// `new URL(dest, origin)` then resolves them to a fully cross-origin URL.
//
// Accept only same-origin paths:
//   - must begin with "/"
//   - the second character must not be "/" or "\" (rejects protocol-relative
//     and backslash-tricked variants that some URL parsers normalise)
//   - everything else falls back to `fallback`
export function safeReturnTo(
  input: string | null | undefined,
  fallback = "/",
): string {
  if (typeof input !== "string" || input.length === 0) return fallback;
  if (input[0] !== "/") return fallback;
  if (input.length > 1 && (input[1] === "/" || input[1] === "\\")) return fallback;
  return input;
}
