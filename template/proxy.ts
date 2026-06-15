// Next.js 16 drop-in. Next 16 renamed the middleware file to `proxy.ts` and
// expects a **named** `proxy` export (on Next <=15 use `middleware.ts` with a
// default export instead — see template/middleware.ts). The factory return
// value is the handler, so exporting it as `proxy` is all that's needed.
//
// The gate verifies the session cookie's HMAC signature + expiry at the edge
// (using SESSION_SECRET) and bounces anonymous users on protected paths to
// sign-in. Auth routes, Next internals, and static assets are bypassed.
//
// If your app ALREADY has proxy rewrite/host logic, don't use this drop-in —
// compose the gate into your existing proxy instead. See
// template/proxy.composed.example.ts.
import { createAuthMiddleware } from "@6away/auth-connect/middleware";
import { SESSION_COOKIE, PROTECTED_PATHS } from "@/lib/auth-config";

export const proxy = createAuthMiddleware({
  cookieName: SESSION_COOKIE,
  protect: PROTECTED_PATHS,
});

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
