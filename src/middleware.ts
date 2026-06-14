// NOTE: no "server-only" import — this module is the entry point for Next.js
// middleware (imported from "@6away/auth-connect/middleware"), which runs
// outside the React Server Component graph.
import { NextResponse, type NextRequest } from "next/server";

export type MiddlewareConfig = {
  /** Session cookie name — must match the `cookieName` passed to createAuthConnect. */
  cookieName: string;
  /**
   * Path prefixes to protect. Accepts plain prefixes ("/app"), Next matcher
   * globs ("/app/:path*"), or wildcards ("/app/*") — all treated as
   * "this prefix and everything under it".
   */
  protect: string[];
  /** Sign-in route to bounce anonymous users to. Default "/api/auth/signin". */
  signInPath?: string;
};

// Reduce a protect entry to its literal prefix: "/app/:path*" -> "/app",
// "/app/*" -> "/app", "/app" -> "/app".
function toPrefix(pattern: string): string {
  let p = pattern.replace(/\/(:[^/]+\*?|\*)$/g, "");
  if (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
  return p || "/";
}

function isProtected(pathname: string, prefixes: string[]): boolean {
  return prefixes.some((prefix) => {
    if (prefix === "/") return true;
    return pathname === prefix || pathname.startsWith(`${prefix}/`);
  });
}

/**
 * Build a Next.js middleware that bounces anonymous users away from protected
 * paths. This is an *optimistic* gate — it only checks for the presence of the
 * session cookie, not its HMAC validity. Real verification happens server-side
 * in `getSession`/`requireSession`; a forged cookie passes the gate but is
 * rejected there. Auth routes, Next internals, and static assets are bypassed.
 */
export function createAuthMiddleware(config: MiddlewareConfig) {
  const { cookieName, signInPath = "/api/auth/signin" } = config;
  const prefixes = config.protect.map(toPrefix);

  return function middleware(req: NextRequest): NextResponse {
    const { pathname, search } = req.nextUrl;

    // Bypass auth routes, Next internals, and any file with an extension
    // (favicon.ico, *.png, *.css, ...).
    if (
      pathname.startsWith("/api/auth/") ||
      pathname.startsWith("/_next/") ||
      /\.[^/]+$/.test(pathname)
    ) {
      return NextResponse.next();
    }

    if (!isProtected(pathname, prefixes)) return NextResponse.next();

    if (req.cookies.get(cookieName)?.value) return NextResponse.next();

    const signInUrl = new URL(signInPath, req.url);
    signInUrl.searchParams.set("returnTo", pathname + search);
    return NextResponse.redirect(signInUrl);
  };
}
