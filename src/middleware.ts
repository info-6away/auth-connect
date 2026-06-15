// NOTE: no "server-only" import — this module is the entry point for Next.js
// middleware (imported from "@6away/auth-connect/middleware"), which runs
// outside the React Server Component graph.
import { NextResponse, type NextRequest } from "next/server";
import { verifySessionCookie } from "./session-verify";

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
  /**
   * HMAC secret used to verify the session cookie signature + expiry at the
   * edge. Defaults to `process.env.SESSION_SECRET` (the same value session.ts
   * signs with). When a secret is available the middleware performs FULL
   * verification — a forged or expired cookie is rejected here, not just
   * server-side. When no secret can be resolved it degrades to an optimistic
   * presence check and warns once.
   */
  sessionSecret?: string;
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

let warnedNoSecret = false;

/**
 * Build a Next.js middleware that bounces unauthenticated users away from
 * protected paths.
 *
 * When a session secret is available (config.sessionSecret or
 * process.env.SESSION_SECRET) the gate FULLY verifies the session cookie:
 * HMAC-SHA256 signature + `exp`. A forged, tampered, or expired cookie is
 * rejected at the edge and the user is redirected to sign-in. Server-side
 * `getSession`/`requireSession` remain the authoritative second line.
 *
 * If no secret can be resolved (misconfiguration) it degrades to an optimistic
 * presence check and logs a warning once, so a missing edge env var cannot
 * silently lock every user out — but verification is the intended path.
 *
 * Auth routes, Next internals, and static assets are always bypassed.
 */
export function createAuthMiddleware(config: MiddlewareConfig) {
  const { cookieName, signInPath = "/api/auth/signin" } = config;
  const prefixes = config.protect.map(toPrefix);

  return async function middleware(req: NextRequest): Promise<NextResponse> {
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

    const cookie = req.cookies.get(cookieName)?.value;

    const bounce = (): NextResponse => {
      const signInUrl = new URL(signInPath, req.url);
      signInUrl.searchParams.set("returnTo", pathname + search);
      return NextResponse.redirect(signInUrl);
    };

    if (!cookie) return bounce();

    const secret = config.sessionSecret ?? process.env.SESSION_SECRET;
    if (!secret) {
      if (!warnedNoSecret) {
        warnedNoSecret = true;
        console.warn(
          "[auth-connect] middleware: no SESSION_SECRET available at the edge — " +
            "falling back to an optimistic cookie-presence check. Set SESSION_SECRET " +
            "(or pass sessionSecret) to enable full HMAC + expiry verification.",
        );
      }
      return NextResponse.next();
    }

    const verified = await verifySessionCookie(cookie, secret);
    if (!verified) return bounce();

    return NextResponse.next();
  };
}
