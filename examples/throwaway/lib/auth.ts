import { createAuthConnect } from "@6away/auth-connect";
import { SESSION_COOKIE, DEFAULT_RETURN_TO, AUTH_ERROR_PATH } from "@/lib/auth-config";

// Exercises the DB-backed path: onSignIn returns an extra { userId } that gets
// typed onto every session result.
type Extra = { userId: string };

export const { routes, getSession, requireSession, getCurrentUser, destroySession } =
  createAuthConnect<Extra>({
    cookieName: SESSION_COOKIE,
    defaultReturnTo: DEFAULT_RETURN_TO,
    // Exercises the optional branded-error routing.
    errorPath: AUTH_ERROR_PATH,
    onSignIn: async (profile) => {
      // Pretend to upsert a local users row keyed by the 6away `sub`.
      return { userId: `local_${profile.sub}` };
    },
  });
