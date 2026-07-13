// Plain shared constants. Imported by BOTH lib/auth.ts (server) and
// middleware.ts / proxy.ts — so keep this module free of any "server-only" imports.
//
// Rename the cookie to something app-unique so two 6away apps on neighbouring
// subdomains never collide.
export const SESSION_COOKIE = "myapp_session";

// Where signed-out users land after sign-in, and the default for requireSession.
export const DEFAULT_RETURN_TO = "/app";

// Path prefixes the middleware should guard. "/app/:path*" protects /app and
// everything under it. Auth routes + static assets are bypassed automatically.
//
// Do NOT add AUTH_ERROR_PATH here — see below.
export const PROTECTED_PATHS = ["/app/:path*"];

// Optional branded sign-in-failure page (see template/app/auth/error/page.tsx).
// Enable it by passing `errorPath: AUTH_ERROR_PATH` in lib/auth.ts.
//
// This path MUST remain PUBLIC. If it is gated, a failed callback redirects
// here, the gate bounces it to sign-in, the IdP still has a session, it calls
// back, it fails again — an infinite loop with no exit. That loop is exactly why
// auth-connect's default is a self-contained page rather than a redirect.
export const AUTH_ERROR_PATH = "/auth/error";
