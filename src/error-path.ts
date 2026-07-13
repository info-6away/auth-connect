// Branded callback-error routing.
//
// By default a failed callback renders auth-connect's own self-contained error
// page (see `create.ts`). An app that wants to own the experience sets
// `errorPath` and we redirect there instead, carrying ONLY a sanitised reason
// slug from a fixed allowlist.
//
// Pure module — no "server-only", no next/* — so every rule below is unit-tested
// in plain Node.
import { isSafeInternalPath, hasControlChars } from "./safe-path";

/**
 * The only reasons that ever reach the browser. Deliberately coarse: the
 * internal failure points (bad nonce, id_token signature, sub mismatch, …) are
 * cryptographic detail an attacker would love and a user cannot act on, so they
 * collapse into `invalid_callback`. Never widen this without a security review.
 */
export const ERROR_REASONS = [
  "access_denied",
  "invalid_callback",
  "provider_unavailable",
  "session_failed",
  "configuration_error",
] as const;

export type ErrorReason = (typeof ERROR_REASONS)[number];

/**
 * Map an internal failure label (or a raw provider `error` query value) onto the
 * public allowlist. Anything unrecognised collapses to `invalid_callback` — the
 * raw string is never echoed, so a hostile IdP response cannot inject content
 * into the redirect.
 */
export function toPublicReason(internal: string | null | undefined): ErrorReason {
  switch (internal) {
    // The user declined consent at the IdP — the one case worth telling them.
    case "access_denied":
      return "access_denied";

    // Provider is reachable but unhealthy, or a hop failed. Retryable.
    case "server_error":
    case "temporarily_unavailable":
    case "token_exchange":
    case "userinfo":
      return "provider_unavailable";

    // We got a verified identity but could not persist a session for it.
    case "provision":
    case "session_create":
      return "session_failed";

    // The app/deploy is misconfigured (missing env, bad client id at the IdP).
    case "configuration_error":
      return "configuration_error";

    // Everything else — missing code/state, state mismatch, bad nonce, bad
    // id_token signature, userinfo/id_token sub mismatch, unknown provider
    // errors — is a generic invalid callback to the browser.
    default:
      return "invalid_callback";
  }
}

/**
 * Validate a configured `errorPath`. Throws on anything that is not a plain
 * same-origin path — configuration failures must fail closed rather than
 * silently produce an open redirect. Called once at `createAuthConnect()` time,
 * so a typo surfaces at boot, not on a user's failed sign-in.
 */
export function assertSafeErrorPath(errorPath: string): string {
  const bad = (why: string): never => {
    throw new Error(
      `[auth-connect] errorPath ${JSON.stringify(errorPath)} is not a safe internal path (${why}). ` +
        `Use a root-relative path such as "/auth/error".`,
    );
  };

  if (!isSafeInternalPath(errorPath)) {
    bad("must start with '/' and must not begin with '//' or '/\\'");
  }
  if (hasControlChars(errorPath)) bad("contains control characters");

  // Percent-encoded bypass: "/%2f%2fevil.com" decodes to "//evil.com", which a
  // permissive URL parser may treat as protocol-relative. Require the decoded
  // form to satisfy the same rules.
  let decoded: string;
  try {
    decoded = decodeURIComponent(errorPath);
  } catch {
    return bad("contains an invalid percent-encoding");
  }
  if (!isSafeInternalPath(decoded) || hasControlChars(decoded)) {
    bad("decodes to an unsafe path");
  }

  return errorPath;
}

/**
 * Build the redirect target for a failed callback: the app's own error page,
 * on the app's own origin, carrying only the sanitised reason.
 *
 * `errorPath` is already validated (see `assertSafeErrorPath`), and resolving it
 * against `origin` cannot escape that origin, so this cannot become an open
 * redirect. Any query string the app put in `errorPath` is preserved; `reason`
 * is appended/overwritten.
 */
export function buildErrorRedirect(errorPath: string, reason: ErrorReason, origin: string): string {
  const url = new URL(errorPath, origin);
  url.searchParams.set("reason", reason);
  return url.toString();
}

/**
 * Build the response for a failed callback.
 *
 * Lives here (rather than inline in `create.ts`) purely so it is reachable from
 * unit tests — `create.ts` imports "server-only" and next/headers and cannot be
 * loaded in plain Node.
 *
 * - With `errorPath`: 303 to the app's own error page, carrying only the
 *   sanitised reason.
 * - Without `errorPath`: the original self-contained HTML page, unchanged. A
 *   failed callback must NOT redirect into a gated app by default — every page
 *   would bounce back to sign-in → IdP (still has a session) → callback → fail,
 *   with no exit. Rendering here breaks the loop and offers a manual retry.
 */
export function buildFailureResponse(opts: {
  reason: string;
  status?: number;
  origin: string;
  signInPath: string;
  defaultReturnTo: string;
  errorPath?: string;
}): Response {
  const { reason, status = 400, origin, signInPath, defaultReturnTo, errorPath } = opts;

  if (errorPath) {
    return Response.redirect(buildErrorRedirect(errorPath, toPublicReason(reason), origin), 303);
  }

  const slug = reason.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 64) || "unknown";
  const retry = `${signInPath}?returnTo=${encodeURIComponent(defaultReturnTo)}`;
  const body =
    `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
    `<meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<title>Sign-in failed</title>` +
    `<style>body{margin:0;min-height:100vh;display:grid;place-items:center;` +
    `font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0b0b0c;color:#e8e8ea}` +
    `main{max-width:30rem;padding:2rem;text-align:center}h1{font-size:1.25rem;margin:0 0 .5rem}` +
    `p{margin:.25rem 0;color:#a1a1aa}code{color:#e8e8ea}` +
    `a{display:inline-block;margin-top:1.25rem;color:#fff;background:#3b82f6;` +
    `padding:.6rem 1rem;border-radius:.5rem;text-decoration:none}</style></head>` +
    `<body><main><h1>Sign-in couldn't be completed</h1>` +
    `<p>Something went wrong finishing your sign-in.</p>` +
    `<p>Reason: <code>${slug}</code></p>` +
    `<a href="${retry}">Try again</a></main></body></html>`;
  return new Response(body, {
    status,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  });
}
