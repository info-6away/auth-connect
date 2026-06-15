// EXAMPLE — composing the 6away auth gate into an app that ALREADY has proxy
// rewrite/host logic (Next.js 16 `proxy.ts`, named `proxy` export). This is NOT
// a drop-in: copy the relevant parts into your own proxy.ts. For a greenfield
// app with no existing proxy, use template/proxy.ts instead.
//
// The pattern (taken from a host-rewrite app where the site root is served from
// /app on the app host):
//   1. Let your existing logic compute the EFFECTIVE (post-rewrite) path.
//   2. Run the gate against that effective path — so protection matches what the
//      user is actually served, not the pre-rewrite URL.
//   3. If the gate returns a redirect (not authenticated), honour it; otherwise
//      apply your rewrite / continue.
import { NextResponse, NextRequest } from "next/server";
import { createAuthMiddleware } from "@6away/auth-connect/middleware";
import { SESSION_COOKIE, PROTECTED_PATHS } from "@/lib/auth-config";

const APP_HOST = "app.example.com";

const gate = createAuthMiddleware({
  cookieName: SESSION_COOKIE,
  protect: PROTECTED_PATHS,
});

export async function proxy(req: NextRequest) {
  const host = (req.headers.get("host") ?? "").toLowerCase();
  const url = req.nextUrl;

  // 1) Your existing rewrite logic → an effective path. Here: on the app host
  //    the root is served from /app, so "/movies" is really "/app/movies".
  let rewrite: URL | null = null;
  let effectivePath = url.pathname;
  if (host === APP_HOST && !url.pathname.startsWith("/app")) {
    rewrite = url.clone();
    rewrite.pathname = url.pathname === "/" ? "/app" : `/app${url.pathname}`;
    effectivePath = rewrite.pathname;
  }

  // 2) Gate the EFFECTIVE path. When rewritten, synthesize a request that carries
  //    the original headers so the session cookie stays visible to the gate.
  const gateReq =
    effectivePath === url.pathname
      ? req
      : new NextRequest(new URL(effectivePath + url.search, url.origin), { headers: req.headers });

  const gated = await gate(gateReq);

  // 3) A 3xx from the gate means "not authenticated" — honour the sign-in bounce.
  if (gated.status >= 300 && gated.status < 400) return gated;

  return rewrite ? NextResponse.rewrite(rewrite) : NextResponse.next();
}

export const config = {
  // Keep auth routes (/api/auth/*) and assets out of the matcher.
  matcher: ["/((?!_next/|api/|.*\\..*).*)"],
};
