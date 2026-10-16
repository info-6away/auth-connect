import "server-only";
import { isSafeRedirectPath } from "./safe-path";

// Validate a post-auth `returnTo` so it can never be turned into an open
// redirect. The rule itself, `isSafeRedirectPath`, lives in `safe-path.ts`.
// It is applied both when sign-in stores the value and when the callback
// redirects to it.
//
// This wrapper adds the fall-back-to-default semantics a *user-supplied*
// `returnTo` needs: an attacker-controlled value must quietly degrade to the
// app's default landing page, never fail the sign-in. (A *configured*
// `errorPath`, by contrast, throws — see `assertSafeErrorPath`.)
export function safeReturnTo(input: string | null | undefined, fallback = "/"): string {
  return isSafeRedirectPath(input) ? input : fallback;
}
