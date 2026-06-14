import { createAuthConnect } from "@6away/auth-connect";
import { SESSION_COOKIE, DEFAULT_RETURN_TO } from "@/lib/auth-config";

// Configure the 6away Auth layer once; import these helpers everywhere else.
export const { routes, getSession, requireSession, getCurrentUser, destroySession } =
  createAuthConnect({
    cookieName: SESSION_COOKIE,
    defaultReturnTo: DEFAULT_RETURN_TO,

    // DB-LESS apps: leave this out. The session cookie is the whole user.
    //
    // DB-BACKED apps: provision here. Match on `profile.sub` (the 6away ID) —
    // NEVER on email — and return extra fields to embed in the session:
    //
    // onSignIn: async (profile) => {
    //   const user = await upsertUserBySub(profile.sub, {
    //     email: profile.email ?? null,
    //     name: profile.name ?? null,
    //   });
    //   return { userId: user.id };   // typed onto every getSession() result
    // },
  });
