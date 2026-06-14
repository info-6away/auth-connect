import "server-only";

// Runtime config for the 6away Auth relying-party layer, read from a single
// canonical env-var set. Secrets are read straight from `process.env` via lazy
// getters that throw *late* (only when first used) so a deploy missing one
// fails loudly at request time rather than silently at import.
//
// Canonical env contract (the only five an app must set):
//   AUTH_CLIENT_ID        — OAuth client id          (secret)
//   AUTH_CLIENT_SECRET    — OAuth client secret       (secret, server-only)
//   SESSION_SECRET        — 32-byte cookie HMAC key   (secret, server-only)
//   NEXT_PUBLIC_AUTH_URL  — issuer origin, e.g. https://auth.6away.ai
//   NEXT_PUBLIC_APP_URL   — this app's origin, e.g. https://app.pgify.guru

function need(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`[auth-connect] env ${name} is not set`);
  return v;
}

// Strip trailing slashes so interpolated callback/issuer URLs match the exact
// strings registered at the OAuth provider (a stray "/" silently breaks the
// redirect_uri exact-match check).
function normalizeOrigin(raw: string): string {
  return raw.replace(/\/+$/, "");
}

export const authEnv = {
  get clientId(): string {
    return need("AUTH_CLIENT_ID");
  },
  get clientSecret(): string {
    return need("AUTH_CLIENT_SECRET");
  },
  get sessionSecret(): string {
    return need("SESSION_SECRET");
  },
  get issuer(): string {
    return normalizeOrigin(need("NEXT_PUBLIC_AUTH_URL"));
  },
  get appOrigin(): string {
    return normalizeOrigin(need("NEXT_PUBLIC_APP_URL"));
  },
};

// The callback path is fixed across the ecosystem. The `/6away` suffix leaves
// room for additional providers (`/callback/<provider>`) without colliding.
export const CALLBACK_PATH = "/api/auth/callback/6away";
