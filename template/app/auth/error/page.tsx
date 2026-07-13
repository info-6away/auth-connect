// Branded sign-in error page (OPTIONAL). Enable it by uncommenting `errorPath`
// in lib/auth.ts. auth-connect then redirects a failed callback here with a
// single sanitised query param — `?reason=<slug>` from a fixed allowlist. It
// never carries tokens, authorization codes, state, nonce, or raw provider
// errors.
//
// TWO RULES:
//  1. This path MUST stay public. Do NOT add it to PROTECTED_PATHS. A gated
//     error page bounces to sign-in → IdP (still signed in) → callback → fail →
//     … forever.
//  2. Render copy from the slug via a lookup, as below. Never print the raw
//     `reason` value into the page.
const MESSAGES: Record<string, string> = {
  access_denied: "You cancelled the sign-in, or access was declined.",
  invalid_callback: "That sign-in attempt was invalid or expired. Please try again.",
  provider_unavailable: "The sign-in service is temporarily unavailable. Please try again shortly.",
  session_failed: "We verified your identity but couldn't start your session.",
  configuration_error: "Sign-in isn't configured correctly. Please contact support.",
};

export default async function AuthErrorPage({
  searchParams,
}: {
  searchParams: Promise<{ reason?: string }>;
}) {
  const { reason } = await searchParams;
  // Unknown/absent slugs fall back to generic copy — the raw value is never rendered.
  const message = (reason && MESSAGES[reason]) ?? "Sign-in couldn't be completed.";

  return (
    <main>
      <h1>Sign-in failed</h1>
      <p>{message}</p>
      <a href="/api/auth/signin">Try again</a>
    </main>
  );
}
