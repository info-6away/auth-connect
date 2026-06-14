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
  type TokenResponse,
  type UserInfo,
} from "./oidc";
import { makeSessionStore, type BaseSession } from "./session";
import { safeReturnTo } from "./return-to";

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
  } = config;

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
    return: `${cookiePrefix}_return`,
    redirect: `${cookiePrefix}_redirect`,
  };

  async function signin(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const returnTo = safeReturnTo(url.searchParams.get("returnTo"), defaultReturnTo);
    const redirectUri = callbackUriForRequest(req);

    const { verifier, challenge } = makePkce();
    const state = randomToken(16);

    const jar = await cookies();
    jar.set(C.pkce, verifier, SHORT_COOKIE);
    jar.set(C.state, state, SHORT_COOKIE);
    jar.set(C.return, returnTo, SHORT_COOKIE);
    // The exact redirect_uri sent to /authorize must be echoed byte-for-byte at
    // token exchange, so persist it rather than re-deriving on the callback.
    jar.set(C.redirect, redirectUri, SHORT_COOKIE);

    return Response.redirect(buildAuthorizeUrl({ state, challenge, redirectUri, scope: scopes }), 303);
  }

  async function callback(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const oidcError = url.searchParams.get("error");

    const jar = await cookies();
    const verifier = jar.get(C.pkce)?.value ?? null;
    const cookieState = jar.get(C.state)?.value ?? null;
    const returnTo = jar.get(C.return)?.value ?? defaultReturnTo;
    const redirectUri = jar.get(C.redirect)?.value ?? null;
    jar.delete(C.pkce);
    jar.delete(C.state);
    jar.delete(C.return);
    jar.delete(C.redirect);

    // Same-origin error redirect. url.origin is the app's own origin, so it is
    // always a safe absolute base.
    const fail = (reason: string): Response =>
      Response.redirect(new URL(`/?auth_error=${encodeURIComponent(reason)}`, url.origin).toString(), 303);

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

    let profile: UserInfo;
    try {
      profile = await fetchUserInfo(tokens.access_token);
    } catch {
      return fail("userinfo");
    }

    let extra: S;
    try {
      extra = onSignIn ? await onSignIn(profile, tokens) : ({} as S);
    } catch {
      return fail("provision");
    }

    await store.create({
      sub: profile.sub,
      email: profile.email ?? null,
      name: profile.name ?? null,
      idToken: tokens.id_token,
      ...extra,
    } as Omit<BaseSession, "exp"> & S);

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
