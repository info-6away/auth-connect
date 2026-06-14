import { createAuthMiddleware } from "@6away/auth-connect/middleware";
import { SESSION_COOKIE, PROTECTED_PATHS } from "@/lib/auth-config";

export default createAuthMiddleware({
  cookieName: SESSION_COOKIE,
  protect: PROTECTED_PATHS,
});

// Run middleware on everything except Next internals + static assets. The
// factory additionally bypasses /api/auth/* and any path with a file extension.
export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
