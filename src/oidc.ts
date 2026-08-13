import "server-only";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import { authEnv, CALLBACK_PATH } from "./config";

export type TokenResponse = {
  access_token: string;
  id_token: string;
  refresh_token?: string;
  token_type: "Bearer";
  expires_in: number;
  scope?: string;
};

export type UserInfo = {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  picture?: string;
};

function basicAuthHeader(): string {
  const raw = `${authEnv.clientId}:${authEnv.clientSecret}`;
  return `Basic ${Buffer.from(raw).toString("base64")}`;
}

export async function exchangeCode(input: {
  code: string;
  codeVerifier: string;
  redirectUri: string;
}): Promise<TokenResponse> {
  const res = await fetch(`${authEnv.issuer}/oauth/token`, {
    method: "POST",
    headers: {
      authorization: basicAuthHeader(),
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: input.code,
      redirect_uri: input.redirectUri,
      code_verifier: input.codeVerifier,
    }),
    cache: "no-store",
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(`token exchange failed: ${res.status} ${detail.slice(0, 200)}`);
  }
  return (await res.json()) as TokenResponse;
}

// One short retry for a TRANSIENT userinfo failure. By the time userinfo
// runs, the user has already authenticated and been authorized and the code
// has been exchanged — a single network blip or 5xx on this last hop must
// not throw that completed sign-in away as `provider_unavailable`. We retry
// exactly ONCE, with the SAME access token, only for a network error or a
// 5xx. A 4xx (401/403/…) is a deterministic rejection of this token and is
// never retried. Terminal behaviour is unchanged: after the retry is
// exhausted this still throws and the caller maps it to `userinfo`.
const USERINFO_RETRY_DELAY_MS = 200;

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

export async function fetchUserInfo(accessToken: string): Promise<UserInfo> {
  const call = (): Promise<Response> =>
    fetch(`${authEnv.issuer}/oauth/userinfo`, {
      headers: { authorization: `Bearer ${accessToken}`, accept: "application/json" },
      cache: "no-store",
    });

  // Attempt 1.
  let res: Response | null = null;
  let networkError = false;
  try {
    res = await call();
  } catch {
    networkError = true; // fetch rejected — network/DNS/TLS/abort
  }

  if (res && res.ok) {
    // A malformed body on a 2xx is NOT retried (a retry can't fix it).
    return (await res.json()) as UserInfo;
  }

  // Retry only transient failures: a network error, or a 5xx. Anything else
  // (4xx incl. 401/403/429, or a deterministic reject) fails immediately —
  // the same token will get the same answer.
  const retryable = networkError || (res !== null && res.status >= 500 && res.status <= 599);
  if (!retryable) {
    // res is non-null here (the only non-retryable path with no response is
    // impossible: a fetch rejection sets networkError=true → retryable).
    throw new Error(`userinfo failed: ${res!.status}`);
  }

  // Attempt 2 — same access token, short fixed backoff. Log only the safe
  // reason; never the token, header, body, email or sub.
  console.warn(
    `[auth-connect] userinfo_retry attempt=2 reason=${networkError ? "network" : "5xx"}`,
  );
  await sleep(USERINFO_RETRY_DELAY_MS);

  let res2: Response;
  try {
    res2 = await call();
  } catch {
    throw new Error("userinfo failed: network");
  }
  if (res2.ok) {
    return (await res2.json()) as UserInfo;
  }
  throw new Error(`userinfo failed: ${res2.status}`);
}

// Extra authorize params an RP may forward. Allowlisted and opaque here:
// - invite_grant: a short-lived signed invitation assertion (see README).
//   The IdP verifies it and may permit account creation on an otherwise
//   invite-only client for that one interaction. This package never
//   inspects or trusts it.
// - login_hint: standard OIDC prefill for the IdP sign-in form.
export type AuthorizeExtraParams = Partial<
  Record<"invite_grant" | "login_hint", string>
>;

export function buildAuthorizeUrl(input: {
  state: string;
  nonce: string;
  challenge: string;
  redirectUri: string;
  scope?: string;
  extra?: AuthorizeExtraParams;
}): string {
  const url = new URL(`${authEnv.issuer}/oauth/authorize`);
  url.searchParams.set("client_id", authEnv.clientId);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", input.scope ?? "openid profile email");
  url.searchParams.set("redirect_uri", input.redirectUri);
  url.searchParams.set("state", input.state);
  url.searchParams.set("nonce", input.nonce);
  url.searchParams.set("code_challenge", input.challenge);
  url.searchParams.set("code_challenge_method", "S256");
  for (const key of ["invite_grant", "login_hint"] as const) {
    const value = input.extra?.[key];
    if (value) url.searchParams.set(key, value);
  }
  return url.toString();
}

// ID-token claims we rely on after verification. The 6away IdP issues only the
// standard claims (sub, iss, aud, exp, iat, nonce, auth_time, sid) in the
// authorization-code id_token — profile fields (email/name) come from the
// userinfo endpoint — so `sub` and `nonce` are what we read here.
export type IdTokenClaims = JWTPayload & { nonce?: string };

// createRemoteJWKSet caches and rotates the IdP's signing keys internally; build
// it once per issuer rather than refetching JWKS on every callback.
let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;
let jwksIssuer: string | null = null;
function getJwks(): ReturnType<typeof createRemoteJWKSet> {
  if (!jwks || jwksIssuer !== authEnv.issuer) {
    jwks = createRemoteJWKSet(new URL(`${authEnv.issuer}/.well-known/jwks.json`));
    jwksIssuer = authEnv.issuer;
  }
  return jwks;
}

/**
 * Cryptographically verify the id_token: RS256 signature against the IdP's
 * published JWKS, plus `iss` (must equal our issuer) and `aud` (must equal our
 * client id), and `exp`/`nbf` (enforced by jose). Throws on any failure.
 * Returns the verified claims; the caller must additionally bind `nonce` to the
 * value it sent and cross-check `sub` against userinfo.
 */
export async function verifyIdToken(idToken: string): Promise<IdTokenClaims> {
  const { payload } = await jwtVerify(idToken, getJwks(), {
    issuer: authEnv.issuer,
    audience: authEnv.clientId,
    algorithms: ["RS256"],
  });
  if (!payload.sub) throw new Error("id_token missing sub");
  return payload as IdTokenClaims;
}

// Derive the OIDC callback URL from the incoming request host so the flow works
// on whichever host it started on (the production app domain, a Vercel preview
// alias, or localhost). Every host that runs this app must have its
// `${host}${CALLBACK_PATH}` registered as a redirect URI on the client in
// auth.6away.ai.
export function callbackUriForRequest(req: Request): string {
  const host = req.headers.get("host") ?? new URL(req.url).host;
  const proto = host.startsWith("localhost") || host.startsWith("127.") ? "http" : "https";
  return `${proto}://${host}${CALLBACK_PATH}`;
}

export function buildLogoutUrl(input: { idTokenHint?: string }): string {
  const url = new URL(`${authEnv.issuer}/oauth/logout`);
  url.searchParams.set("client_id", authEnv.clientId);
  url.searchParams.set("post_logout_redirect_uri", authEnv.appOrigin);
  if (input.idTokenHint) url.searchParams.set("id_token_hint", input.idTokenHint);
  return url.toString();
}
