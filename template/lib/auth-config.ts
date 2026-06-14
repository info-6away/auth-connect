// Plain shared constants. Imported by BOTH lib/auth.ts (server) and
// middleware.ts — so keep this module free of any "server-only" imports.
//
// Rename the cookie to something app-unique so two 6away apps on neighbouring
// subdomains never collide.
export const SESSION_COOKIE = "myapp_session";

// Where signed-out users land after sign-in, and the default for requireSession.
export const DEFAULT_RETURN_TO = "/app";

// Path prefixes the middleware should guard. "/app/:path*" protects /app and
// everything under it. Auth routes + static assets are bypassed automatically.
export const PROTECTED_PATHS = ["/app/:path*"];
