import "server-only";
import { isSafeInternalPath } from "./safe-path";

// Validate a post-auth `returnTo` so it can never be turned into an open
// redirect. The rule itself lives in `safe-path.ts` — shared with `errorPath`
// and unit-tested there, since this module's "server-only" import makes it
// unloadable outside a bundler.
//
// This wrapper adds the fall-back-to-default semantics a *user-supplied*
// `returnTo` needs: an attacker-controlled value must quietly degrade to the
// app's default landing page, never fail the sign-in. (A *configured*
// `errorPath`, by contrast, throws — see `assertSafeErrorPath`.)
export function safeReturnTo(input: string | null | undefined, fallback = "/"): string {
  return isSafeInternalPath(input) ? input : fallback;
}
