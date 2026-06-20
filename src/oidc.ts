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

export async function fetchUserInfo(accessToken: string): Promise<UserInfo> {
  const res = await fetch(`${authEnv.issuer}/oauth/userinfo`, {
    headers: { authorization: `Bearer ${accessToken}`, accept: "application/json" },
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(`userinfo failed: ${res.status}`);
  }
  return (await res.json()) as UserInfo;
}

export function buildAuthorizeUrl(input: {
  state: string;
  nonce: string;
  challenge: string;
  redirectUri: string;
  scope?: string;
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
