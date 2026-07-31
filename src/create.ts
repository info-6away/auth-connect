import "server-only";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { makePkce, randomToken } from "./pkce";
import {
  buildAuthorizeUrl,
  buildLogoutUrl,
  callbackUriForRequest,
  exchangeCode,
  fetchUserInfo,
  verifyIdToken,
  type TokenResponse,
  type UserInfo,
} from "./oidc";
import { makeSessionStore, type BaseSession } from "./session";
import { safeReturnTo } from "./return-to";
import { assertSafeErrorPath, buildFailureResponse } from "./error-path";

/** The standardized signed-in user every app reads via `getCurrentUser()`. */
export type CurrentUser = {
  sub: string;
  email: string | null;
  name: string | null;
};

export type AuthConnectConfig<S extends Record<string, unknown> = Record<string, never>> = {
  /** Name of the session cookie. Make it app-unique (e.g. "pgify_session"). */
  cookieName: string;
  /** Where to land after sign-in when no `returnTo` is supplied. Default "/". */
  defaultReturnTo?: string;
  /** OAuth scopes. Default "openid profile email". */
  scopes?: string;
  /** Prefix for the short-lived PKCE/state cookies. Default "ac". */
  cookiePrefix?: string;
  /** Path of the sign-in route. Default "/api/auth/signin". */
  signInPath?: string;
  /**
   * Optional hook run once per successful sign-in, before the session is
   * written. Apps with a local `users` table upsert here (matching on
   * `profile.sub`, never email) and return extra fields to embed in the
   * session — e.g. `{ userId }`. DB-less apps omit this entirely.
   */
  onSignIn?: (profile: UserInfo, tokens: TokenResponse) => Promise<S> | S;
  /**
   * Optional internal path that owns the sign-in-failure experience, e.g.
   * "/auth/error". When set, a failed callback redirects there with a single
   * sanitised query param — `?reason=<slug>` from a fixed allowlist (see
   * `ErrorReason`) — instead of rendering auth-connect's built-in page. No
   * tokens, codes, state, nonce or raw provider errors are ever included.
   *
   * IMPORTANT: this path MUST be publicly reachable (exclude it from your
   * proxy/middleware matcher). If the error page is itself gated, a failed
   * callback bounces to sign-in → IdP (still signed in) → callback → fail →
   * … forever. That loop is exactly why the default is a self-contained page
   * rather than a redirect.
   *
   * Validated at construction: a non-same-origin value throws rather than
   * silently becoming an open redirect.
   */
  errorPath?: string;
};

export type AuthConnect<S extends Record<string, unknown>> = {
  routes: {
    signin: (req: Request) => Promise<Response>;
    callback: (req: Request) => Promise<Response>;
    signout: () => Promise<Response>;
  };
  /** Full session payload, or null. */
  getSession: () => Promise<(BaseSession & S) | null>;
  /** Full session payload, or redirect to sign-in. Never returns null. */
  requireSession: (returnTo?: string) => Promise<BaseSession & S>;
  /** Standardized `{ sub, email, name }`, or null. */
  getCurrentUser: () => Promise<CurrentUser | null>;
  destroySession: () => Promise<void>;
};

export function createAuthConnect<S extends Record<string, unknown> = Record<string, never>>(
  config: AuthConnectConfig<S>,
): AuthConnect<S> {
  const {
    cookieName,
    defaultReturnTo = "/",
    scopes = "openid profile email",
    cookiePrefix = "ac",
    signInPath = "/api/auth/signin",
    onSignIn,
    errorPath,
  } = config;

  // Fail closed at construction: an unsafe errorPath throws at boot rather than
  // turning a user's failed sign-in into an open redirect.
  const safeErrorPath = errorPath === undefined ? undefined : assertSafeErrorPath(errorPath);

  const store = makeSessionStore<S>(cookieName);

  const SHORT_COOKIE = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    path: "/",
    maxAge: 10 * 60, // 10 min
  };

  const C = {
    pkce: `${cookiePrefix}_pkce`,
    state: `${cookiePrefix}_state`,
    nonce: `${cookiePrefix}_nonce`,
    return: `${cookiePrefix}_return`,
    redirect: `${cookiePrefix}_redirect`,
  };

  async function signin(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const returnTo = safeReturnTo(url.searchParams.get("returnTo"), defaultReturnTo);
    // Allowlisted opaque passthroughs to the IdP (never stored in cookies).
    // Length-capped so a hostile link can't smuggle an oversized blob.
    const inviteGrant = url.searchParams.get("invite_grant");
    const loginHint = url.searchParams.get("login_hint");
    const extra = {
      ...(inviteGrant && inviteGrant.length <= 2048
        ? { invite_grant: inviteGrant }
        : {}),
      ...(loginHint && loginHint.length <= 254 ? { login_hint: loginHint } : {}),
    };
    const redirectUri = callbackUriForRequest(req);

    const { verifier, challenge } = makePkce();
    const state = randomToken(16);
    // Nonce binds the id_token to this very sign-in attempt: the IdP echoes it
    // into the id_token, and the callback rejects any token whose nonce claim
    // doesn't match this cookie (replay / token-injection defense).
    const nonce = randomToken(16);

    const jar = await cookies();
    jar.set(C.pkce, verifier, SHORT_COOKIE);
    jar.set(C.state, state, SHORT_COOKIE);
    jar.set(C.nonce, nonce, SHORT_COOKIE);
    jar.set(C.return, returnTo, SHORT_COOKIE);
    // The exact redirect_uri sent to /authorize must be echoed byte-for-byte at
    // token exchange, so persist it rather than re-deriving on the callback.
    jar.set(C.redirect, redirectUri, SHORT_COOKIE);

    return Response.redirect(
      buildAuthorizeUrl({ state, nonce, challenge, redirectUri, scope: scopes, extra }),
      303,
    );
  }

  async function callback(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const oidcError = url.searchParams.get("error");

    const jar = await cookies();
    const verifier = jar.get(C.pkce)?.value ?? null;
    const cookieState = jar.get(C.state)?.value ?? null;
    const cookieNonce = jar.get(C.nonce)?.value ?? null;
    const returnTo = jar.get(C.return)?.value ?? defaultReturnTo;
    const redirectUri = jar.get(C.redirect)?.value ?? null;
    jar.delete(C.pkce);
    jar.delete(C.state);
    jar.delete(C.nonce);
    jar.delete(C.return);
    jar.delete(C.redirect);

    // By default, render a self-contained error page rather than redirecting:
    // redirecting a failed callback into the app loops forever on fully-gated
    // apps (every page bounces back to sign-in → IdP, which still has a session
    // → callback → fail → …, with no exit). The callback route is never gated,
    // so rendering here surfaces the reason and offers a manual retry.
    //
    // An app that sets `errorPath` opts into the redirect and takes on the
    // responsibility of keeping that path public. Both shapes are built by
    // `buildFailureResponse` (pure, unit-tested).
    const fail = (reason: string, status = 400): Response => {
      // Server-side diagnostic. The browser only ever sees a coarse, allowlisted
      // reason, so the precise internal label is logged here instead — and ONLY
      // the label: never the code, tokens, cookies, or the callback URL (whose
      // query string carries the authorization code).
      console.warn(`[auth-connect] callback failed: ${reason}`);

      return buildFailureResponse({
        reason,
        status,
        origin: url.origin,
        signInPath,
        defaultReturnTo,
        errorPath: safeErrorPath,
      });
    };

    if (oidcError) return fail(oidcError);
    if (!code || !state || !verifier || !redirectUri || state !== cookieState) {
      return fail("invalid_callback");
    }

    let tokens: TokenResponse;
    try {
      tokens = await exchangeCode({ code, codeVerifier: verifier, redirectUri });
    } catch {
      return fail("token_exchange");
    }

    // Verify the id_token's RS256 signature (JWKS), issuer, audience and expiry
    // before trusting anything in it.
    let idClaims;
    try {
      idClaims = await verifyIdToken(tokens.id_token);
    } catch {
      return fail("id_token");
    }
    // Bind the token to this sign-in attempt: its nonce must match the one we set.
    if (!cookieNonce || idClaims.nonce !== cookieNonce) {
      return fail("invalid_nonce");
    }

    let profile: UserInfo;
    try {
      profile = await fetchUserInfo(tokens.access_token);
    } catch {
      return fail("userinfo");
    }

    // The verified id_token is the source of identity truth; userinfo only
    // supplies profile fields. Reject any mismatch (token-substitution defense).
    if (profile.sub !== idClaims.sub) {
      return fail("sub_mismatch");
    }

    let extra: S;
    try {
      extra = onSignIn ? await onSignIn(profile, tokens) : ({} as S);
    } catch {
      return fail("provision");
    }

    // Writing the session is the last thing that can fail. Guard it too, so a
    // cookie-store error surfaces as a handled sign-in failure (and, with
    // `errorPath`, the app's branded page) rather than an unhandled 500.
    try {
      await store.create({
        sub: profile.sub,
        email: profile.email ?? null,
        name: profile.name ?? null,
        idToken: tokens.id_token,
        ...extra,
      } as Omit<BaseSession, "exp"> & S);
    } catch {
      return fail("session_create", 500);
    }

    const dest = safeReturnTo(returnTo, defaultReturnTo);
    return Response.redirect(new URL(dest, url.origin).toString(), 303);
  }

  async function signout(): Promise<Response> {
    const session = await store.get();
    await store.destroy();
    return Response.redirect(buildLogoutUrl({ idTokenHint: session?.idToken }), 303);
  }

  async function requireSession(returnTo?: string): Promise<BaseSession & S> {
    const session = await store.get();
    if (!session) {
      redirect(`${signInPath}?returnTo=${encodeURIComponent(returnTo ?? defaultReturnTo)}`);
    }
    return session;
  }

  async function getCurrentUser(): Promise<CurrentUser | null> {
    const s = await store.get();
    if (!s) return null;
    return { sub: s.sub, email: s.email, name: s.name };
  }

  return {
    routes: { signin, callback, signout },
    getSession: store.get,
    requireSession,
    getCurrentUser,
    destroySession: store.destroy,
  };
}
