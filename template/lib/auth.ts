import { createAuthConnect } from "@6away/auth-connect";
import { SESSION_COOKIE, DEFAULT_RETURN_TO } from "@/lib/auth-config";
// import { AUTH_ERROR_PATH } from "@/lib/auth-config";

// Configure the 6away Auth layer once; import these helpers everywhere else.
export const { routes, getSession, requireSession, getCurrentUser, destroySession } =
  createAuthConnect({
    cookieName: SESSION_COOKIE,
    defaultReturnTo: DEFAULT_RETURN_TO,

    // OPTIONAL — branded sign-in-failure page. Without this, a failed callback
    // renders auth-connect's own self-contained error page. With it, the failure
    // redirects to your page carrying only a sanitised `?reason=` slug (never
    // tokens, codes, state, nonce or raw provider errors).
    //
    // To enable: copy template/app/auth/error/page.tsx, uncomment the import
    // above and the line below. AUTH_ERROR_PATH must stay OUT of
    // PROTECTED_PATHS — a gated error page loops forever.
    //
    // errorPath: AUTH_ERROR_PATH,

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
