# Changelog

## v1.0.7

Security fix. Backwards compatible: no API or configuration change.

### Fixed
- **Open redirect after sign-in via `returnTo`.** `?returnTo=/%09/evil.example`
  decodes to `/<tab>/evil.example`. That passed the old first-two-characters
  check, and the callback's `new URL(dest, origin)` dropped the tab and
  redirected to `https://evil.example/`. Carriage return and line feed did the
  same.
  - `returnTo` now accepts only a same-origin relative application path.
    The new `isSafeRedirectPath` in `safe-path.ts` enforces this. It rejects:
    - backslashes and control characters anywhere, literal or
      percent-encoded;
    - values whose decoded form is unsafe;
    - anything that resolves to another origin, which is the
      authoritative check.
  - A rejected value still quietly falls back to the default landing page.
  - The check applies at sign-in and again at the callback.
  - `errorPath` validation is unchanged.
  - Regression tests: `src/return-to.test.ts`.

## v1.0.4

Backwards compatible. Apps on v1.0.3 can upgrade without code changes.

### Added
- **Optional branded error routing — `errorPath`.** Point it at an internal page
  (e.g. `"/auth/error"`) and a failed sign-in callback redirects there with a
  single sanitised `?reason=` slug instead of rendering the built-in page.
  - Reasons come from a fixed allowlist: `access_denied`, `invalid_callback`,
    `provider_unavailable`, `session_failed`, `configuration_error`.
  - Tokens, authorization codes, `state`, `nonce`, raw provider errors and
    exception text are never exposed to the browser. Internal cryptographic
    failures (bad signature, bad nonce, `sub` mismatch) deliberately collapse
    into a single indistinguishable `invalid_callback`.
  - `errorPath` is validated at `createAuthConnect()` time and **throws at boot**
    if it is not a plain same-origin path — it cannot become an open redirect.
  - The precise internal reason is now written to the server log (label only —
    never the code, tokens, cookies, or the callback URL).
  - **The error page must be public.** A gated one loops forever.
- `ERROR_REASONS` / `ErrorReason` exported.
- Template: `app/auth/error/page.tsx`, plus `AUTH_ERROR_PATH` in
  `lib/auth-config.ts`.
- Test suite (`npm test`) covering path validation, open-redirect rejection,
  reason sanitisation, and default-behaviour preservation.

### Changed
- Session creation is now guarded: a cookie-store failure fails closed as a
  handled sign-in failure (`session_failed`) rather than an unhandled 500.
- Same-origin path validation moved to `safe-path.ts` and is shared by
  `safeReturnTo` and `errorPath`. `safeReturnTo` behaviour is unchanged.
- Docs: package visibility (git-URL only, **not on npm**), `errorPath`, and a
  troubleshooting table (BOM/whitespace in env vars, redeploy-after-env-change,
  callback mismatch, matcher scope, middleware/proxy conflicts).

### Unchanged
- Apps that do not set `errorPath` keep the exact previous behaviour: the
  self-contained HTML error page, same status, same copy.
- PKCE S256, `state`, `nonce`, RS256 id_token verification, JWKS, issuer/audience
  checks, userinfo `sub` cross-check, session signing and cookie flags are all
  untouched.

## v1.0.3 and earlier
See the git tags.
