# @6away/auth-connect

Plug-and-play **6away Auth** for Next.js App Router apps. One small package + a
handful of thin files, and your app authenticates against `auth.6away.ai` as a
first-party OIDC relying party — PKCE, signed-cookie sessions, and RP-initiated
logout included.

It replaces the copy-paste integration dance (the one Ritual and GCP Pro each
did by hand, and drifted apart doing) with a single versioned source of truth.

**Connect a new app in ~15 minutes:** 5 env vars → 4 files → done.

---

## Install

```bash
npm install "github:info-6away/auth-connect#v1.0.4"
# package.json:  "@6away/auth-connect": "github:info-6away/auth-connect#v1.0.4"
```

Pin a tag (`#v1.0.4`, `#v1.1.0`, …) so upgrades are deliberate.

### Package visibility — read this before you `npm install @6away/auth-connect`

| | |
| --- | --- |
| **Distribution** | **Public GitHub repository**, installed by git URL |
| **npm registry** | **NOT published** — not on public npm, not on a private registry |
| **Scope name** | `@6away/…` is just the package's *name*. It does **not** imply an npm scope exists. |

`npm install @6away/auth-connect` **will fail** — there is no registry entry to
resolve. Always install from the git URL above, pinned to a tag. The install
environment therefore needs `git` (present on Vercel and CI by default).

> **Built on install.** `dist/` is **not** committed. npm runs the package's
> `prepare` script after cloning the git ref, which builds `dist/` from source
> (`tsc`). npm installs this package's `devDependencies` (TypeScript, Next, React
> types) for that build automatically, then ships only `dist/`, `template/`, and
> this README to your `node_modules`. The only runtime dependency that lands in
> your tree is `jose` (JWKS verification); `next`/`react` are peer deps you
> already have. Requires git available in the install environment (it is on
> Vercel and CI by default).

## 1. Environment variables

The whole contract is five vars (copy `template/.env.example`):

| Var | Secret? | Example |
| --- | --- | --- |
| `AUTH_CLIENT_ID` | ✅ | `pgify` |
| `AUTH_CLIENT_SECRET` | ✅ | `…` |
| `SESSION_SECRET` | ✅ | 32-byte base64url |
| `NEXT_PUBLIC_AUTH_URL` | — | `https://auth.6away.ai` |
| `NEXT_PUBLIC_APP_URL` | — | `https://your-app.com` |

```bash
# generate a SESSION_SECRET
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

> ### Need a client ID?
>
> **`AUTH_CLIENT_ID` / `AUTH_CLIENT_SECRET` are issued per app — and for now,
> registration is manual.** Until `auth.6away.ai/admin` (self-service) is live,
> email **support@6away.ai** with:
>
> - app name
> - production app URL
> - callback URL — `https://<your-app-origin>/api/auth/callback/6away`
> - post-logout URL — usually your app origin
> - whether signup is **open** or **invite-only**
> - support email
>
> You'll get back your `AUTH_CLIENT_ID`, `AUTH_CLIENT_SECRET`, and confirmation
> that your callback URLs are registered. *(Temporary — this whole step becomes
> self-serve once `/admin` ships.)*

## 2. Configure once

Copy `template/lib/auth-config.ts` and `template/lib/auth.ts`. Set your cookie
name and protected paths:

```ts
// lib/auth-config.ts        (plain constants — no server-only imports)
export const SESSION_COOKIE  = "pgify_session";
export const DEFAULT_RETURN_TO = "/app";
export const PROTECTED_PATHS = ["/app/:path*"];
```

> **Customize these to your app** — the `/app` values are just PGify's. Set
> `PROTECTED_PATHS` to whatever you want gated and `DEFAULT_RETURN_TO` to where
> users land after sign-in. Make `SESSION_COOKIE` app-unique. Examples:
>
> ```ts
> // a dashboard app
> export const DEFAULT_RETURN_TO = "/dashboard";
> export const PROTECTED_PATHS = ["/dashboard/:path*", "/settings/:path*"];
>
> // protect everything except marketing + auth routes
> export const PROTECTED_PATHS = ["/((?!api/auth|_next|^/$).*)"];
> ```

```ts
// lib/auth.ts
import { createAuthConnect } from "@6away/auth-connect";
import { SESSION_COOKIE, DEFAULT_RETURN_TO } from "@/lib/auth-config";

export const { routes, getSession, requireSession, getCurrentUser, destroySession } =
  createAuthConnect({
    cookieName: SESSION_COOKIE,
    defaultReturnTo: DEFAULT_RETURN_TO,
  });
```

## 3. Three route handlers

Copy the three files under `template/app/api/auth/`. Each is one line of glue:

```ts
// app/api/auth/signin/route.ts
import { routes } from "@/lib/auth";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const GET = routes.signin;
```

…and likewise `callback/6away/route.ts` (`routes.callback`) and
`signout/route.ts` (`routes.signout`, as both `GET` and `POST`).

> **Register `https://<app-origin>/api/auth/callback/6away`** as a redirect URI
> on your client in `auth.6away.ai` — plus your localhost and any preview hosts.

## 4. Protect routes (middleware)

Copy `template/middleware.ts`:

```ts
import { createAuthMiddleware } from "@6away/auth-connect/middleware";
import { SESSION_COOKIE, PROTECTED_PATHS } from "@/lib/auth-config";

export default createAuthMiddleware({ cookieName: SESSION_COOKIE, protect: PROTECTED_PATHS });
export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };
```

Anonymous hits to a protected path are bounced to sign-in with a `returnTo`.
Auth routes and static assets are bypassed automatically. The middleware fully
**verifies the session cookie's HMAC signature and expiry at the edge** (using
`SESSION_SECRET`), so forged or expired cookies are rejected here too — see
[Security notes](#security-notes). Server-side `getSession`/`requireSession`
remain the authoritative check.

> **Edge env:** `SESSION_SECRET` must be available to the middleware runtime
> (it already is on Vercel, where server env vars are injected). If it is ever
> missing the gate degrades to an optimistic presence check and logs a warning
> once — it never silently locks everyone out.

### `middleware.ts` (Next ≤15) vs `proxy.ts` (Next 16)

The gate function is the same; only the file name and export shape differ by
Next.js version:

| Next.js | File | Export | Template |
| --- | --- | --- | --- |
| ≤ 15 | `middleware.ts` | `export default createAuthMiddleware(...)` | `template/middleware.ts` |
| 16 | `proxy.ts` | `export const proxy = createAuthMiddleware(...)` (named) | `template/proxy.ts` |

Use the file/template that matches your Next version — having a `middleware.ts`
default export on Next 16 (or a `proxy.ts` on ≤15) means the gate silently never
runs.

**Already have a `proxy.ts` / `middleware.ts` with rewrite or host logic?** The
drop-in replaces the whole file, so instead *compose* the gate into your existing
handler: compute your effective (post-rewrite) path, run the gate against it, and
honour a 3xx (sign-in bounce) before applying your rewrite. Full worked example:
`template/proxy.composed.example.ts`.

## 5. Read the user

```ts
// the common case — standardized { sub, email, name } | null
const user = await getCurrentUser();

// in a protected Server Component — redirects to sign-in if absent
const session = await requireSession();   // never null

// when you want to branch on auth without redirecting
const session = await getSession();        // full payload | null
```

Done.

## Verify it works (smoke test)

With your client registered (above), run `npm run dev` and check, in order:

1. **Gate** — open a protected path while signed out (e.g. `/app`). You're redirected to `/api/auth/signin`, then on to `auth.6away.ai`.
2. **Sign in** — complete Google sign-in. You land back on your app at the path you started from, signed in.
3. **Session persists** — refresh. You stay signed in (no re-auth).
4. **Public stays public** — your marketing/landing routes load with no redirect.
5. **Open-redirect guard** — `…/api/auth/signin?returnTo=//evil.com` must land on your app, never off-origin.
6. **Sign out** — hit `/api/auth/signout`. The session clears, you're returned to your app origin, and revisiting the protected path redirects to sign-in again.

> Testing a Vercel **preview**? Register that preview host's callback too
> (`https://<preview-host>/api/auth/callback/6away`) and make sure Deployment
> Protection isn't fronting the deployment (it 401s before your app runs).

---

## DB-less vs DB-backed apps

The only real fork between integrations. The layer handles both through one
optional hook.

- **DB-less** (the session cookie *is* the user): omit `onSignIn`.
- **DB-backed** (you keep a local `users` row): provide `onSignIn`, match on
  `profile.sub` (**never email** — `sub` is the stable identity), and return
  extra fields. They're type-merged into every session result:

```ts
createAuthConnect<{ userId: string }>({
  cookieName: SESSION_COOKIE,
  onSignIn: async (profile) => {
    const user = await upsertUserBySub(profile.sub, {
      email: profile.email ?? null,
      name: profile.name ?? null,
    });
    return { userId: user.id };
  },
});

// later:  const { userId } = await requireSession();  // typed
```

## API

| Export | Purpose |
| --- | --- |
| `createAuthConnect(config)` | Returns `{ routes, getSession, requireSession, getCurrentUser, destroySession }` |
| `createAuthMiddleware(config)` | `@6away/auth-connect/middleware` — route-protection gate |
| `safeReturnTo(input, fallback?)` | Open-redirect-safe path validator |
| `ERROR_REASONS` / `ErrorReason` | The allowlist of sanitised failure slugs |
| types | `AuthConnectConfig`, `CurrentUser`, `BaseSession`, `UserInfo`, `TokenResponse` |

`createAuthConnect` config: `cookieName` (required), `defaultReturnTo`,
`scopes`, `cookiePrefix`, `signInPath`, `onSignIn`, `errorPath`.

## Branded error page (`errorPath`) — optional

By default a failed sign-in callback renders auth-connect's own self-contained
error page. To own that experience, point `errorPath` at an internal route:

```ts
// lib/auth.ts
export const { routes, getSession, requireSession } = createAuthConnect({
  cookieName: SESSION_COOKIE,
  defaultReturnTo: DEFAULT_RETURN_TO,
  errorPath: "/auth/error",          // ← opt in
});
```

A failed callback then redirects (303) to:

```
/auth/error?reason=invalid_callback
```

Copy `template/app/auth/error/page.tsx` and render your own copy from the slug.

**`reason` is the only thing passed, and it comes from a fixed allowlist:**

| Slug | Means |
| --- | --- |
| `access_denied` | The user declined consent at the IdP |
| `invalid_callback` | Missing/mismatched `code`/`state`, bad `nonce`, bad `id_token`, `sub` mismatch |
| `provider_unavailable` | Token exchange or userinfo failed; IdP unhealthy. Retryable |
| `session_failed` | Identity verified, but the session couldn't be created |
| `configuration_error` | The app/deploy is misconfigured |

Tokens, authorization codes, `state`, `nonce`, raw provider errors, exception
messages and stack traces are **never** included. Internal cryptographic
failures deliberately collapse into `invalid_callback` — an attacker must not be
able to distinguish "bad signature" from "bad nonce". The precise internal
reason is written to the **server** log instead.

> ### ⚠️ The error path MUST be public
> Do **not** include it in `PROTECTED_PATHS`. A gated error page redirects to
> sign-in → the IdP still has a session → it calls back → the callback fails
> again → … an infinite loop with no exit. This is precisely why the *default*
> behaviour renders a page instead of redirecting.

**Fails closed.** `errorPath` is validated at `createAuthConnect()` time and
**throws at boot** if it isn't a plain same-origin path — `https://evil.com`,
`//evil.com`, `/\evil.com`, `/%2f%2fevil.com`, `javascript:…` and paths with
control characters are all rejected. It can never become an open redirect. Apps
that don't set `errorPath` are completely unaffected.

## Security notes

- **ID token is cryptographically verified.** On every sign-in the `id_token`'s
  RS256 signature is checked against the IdP's published JWKS
  (`/.well-known/jwks.json`), along with `iss` (must be your `NEXT_PUBLIC_AUTH_URL`),
  `aud` (your `AUTH_CLIENT_ID`), and expiry. The verified token — not the
  userinfo response — is the source of identity truth.
- **Nonce replay protection.** Each sign-in sends a single-use `nonce`; the
  callback rejects any `id_token` whose `nonce` claim doesn't match, defeating
  token replay/injection. PKCE (S256) and `state` are also enforced.
- **`sub` cross-check.** The userinfo `sub` must equal the verified `id_token`
  `sub`, blocking token-substitution.
- **Match identity by `sub`, never email.** Email can change at the IdP; `sub`
  is stable for the life of the account.
- **`returnTo` is open-redirect-safe.** `safeReturnTo` rejects `//evil.com` and
  `/\evil.com`, applied both when storing and when reading.
- **Sessions are HMAC-signed** (`SESSION_SECRET`), `httpOnly`, `secure` in
  production, and expiry-enforced on every read.
- **Callback failures render an error page, never redirect into the app** (by
  default). A failed sign-in callback (bad token exchange, id_token, nonce, etc.)
  returns a self-contained error page with a manual "Try again" link — it does
  **not** redirect to `/`. On a fully-gated app (e.g. one whose host serves
  everything under a protected prefix), redirecting a failure into the app would
  loop forever (page → sign-in → IdP → callback → fail → page → …). Rendering at
  the callback URL (which is never gated) breaks that loop. Apps that opt into
  `errorPath` take on the responsibility of keeping that page public.
- **Failure reasons shown to the browser are sanitised.** With `errorPath`, only
  an allowlisted slug is passed (`access_denied`, `invalid_callback`,
  `provider_unavailable`, `session_failed`, `configuration_error`). Raw provider
  errors, tokens, codes, `state`, `nonce` and exception text never reach the
  client; internal crypto failures collapse into one indistinguishable slug. The
  configured `errorPath` itself is validated at boot and cannot become an open
  redirect.
- **Middleware verifies, not just sniffs.** The gate checks the cookie's
  HMAC-SHA256 signature and `exp` at the edge (Web Crypto, Edge/Node compatible),
  so a forged or expired cookie is rejected there. `getSession`/`requireSession`
  remain the authoritative server-side boundary; still don't rely on the gate
  alone for the most sensitive operations.

## Troubleshooting

| Symptom | Cause & fix |
| --- | --- |
| `invalid redirect_uri`, or the IdP rejects the callback | The `redirect_uri` must match what's registered on the client **byte-for-byte**. Check for a trailing slash on `NEXT_PUBLIC_APP_URL`, `http` vs `https`, and `www.` vs apex. Register both your localhost and production callbacks. |
| Env var looks right but behaves as if it's wrong (bad URL, session never validates) | **Hidden whitespace or a BOM.** On Windows PowerShell, piping a value into `vercel env add` can prepend a byte-order mark, so `https://auth.6away.ai` is stored as `﻿https://…`. **Paste secrets into the Vercel dashboard instead** of piping them. Never `echo` a secret into your shell history. |
| Changed an env var but nothing changed | **Redeploy.** Env vars are read at build/boot — editing them does not update a running deployment. |
| Sign-in page shows the wrong product name | That's the **display name** on the client record in `auth.6away.ai/admin`, not your client ID. Fix it there. |
| Infinite redirect loop after a failed sign-in | Your `errorPath` is **gated**. Remove it from `PROTECTED_PATHS`. |
| Protected pages are public, or public pages demand sign-in | The `PROTECTED_PATHS` matcher. `"/app/:path*"` covers `/app` **and** everything under it; a bare `"/app"` does not. |
| Your existing `middleware.ts` / `proxy.ts` stopped working | You dropped in the template over it. **Compose** the gate into your existing handler instead — see `template/proxy.composed.example.ts`. |
| Signed in, but the session cookie isn't set | Cookies are `secure` in production — the app must be served over **https**. Also confirm the cookie's domain matches the host you're browsing. |
| Sign-out lands on the wrong domain | `NEXT_PUBLIC_APP_URL` builds the post-logout redirect; it differs between local and production. |
| `npm install @6away/auth-connect` fails | The package is **not on npm**. Install from the git URL — see [Package visibility](#package-visibility--read-this-before-you-npm-install-6awayauth-connect). |

## Versioning & upgrades

Tagged releases (`v1`, `v1.1.0`, …). Bump the `#tag` in `package.json` to
upgrade on your schedule — every app shares this code, so a fix lands
everywhere on the next bump instead of being hand-ported (which is exactly how
the GCP open-redirect drift happened).

## Local development of this package

```bash
npm install
npm run build       # tsc -> dist/  (+ .d.ts)
npm run validate    # typecheck examples/throwaway against src (the "new app" flow)
```

---

> **Roadmap:** today, registering a client still means manual SQL + secrets +
> redirect URIs in `auth.6away.ai`. Next phase is self-service:
> `auth.6away.ai/admin` → Create Client → generate secret → copy these five env
> vars → done. This package is the client half of that story.
