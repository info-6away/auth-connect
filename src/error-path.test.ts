import { test, describe } from "node:test";
import assert from "node:assert/strict";

import {
  ERROR_REASONS,
  assertSafeErrorPath,
  buildErrorRedirect,
  buildFailureResponse,
  toPublicReason,
} from "./error-path";
import { isSafeInternalPath, hasControlChars } from "./safe-path";

const ORIGIN = "https://app.example.com";
const BASE = { origin: ORIGIN, signInPath: "/api/auth/signin", defaultReturnTo: "/" };

// Control characters, built by code so the test source stays free of raw bytes.
const NUL = String.fromCharCode(0);
const LF = String.fromCharCode(10);
const CR = String.fromCharCode(13);
const DEL = String.fromCharCode(127);

describe("safe-path", () => {
  test("accepts plain same-origin paths", () => {
    for (const p of ["/", "/auth/error", "/a/b?x=1", "/auth/error#frag"]) {
      assert.equal(isSafeInternalPath(p), true, p);
    }
  });

  test("rejects non-paths and cross-origin forms", () => {
    for (const p of [
      "",
      "https://evil.com",
      "http://evil.com",
      "//evil.com",
      "/\\evil.com",
      "javascript:alert(1)",
      "data:text/html,x",
      null,
      undefined,
      42,
    ]) {
      assert.equal(isSafeInternalPath(p as unknown), false, String(p));
    }
  });

  test("detects control characters", () => {
    assert.equal(hasControlChars("/ok"), false);
    for (const c of [NUL, LF, CR, DEL]) {
      assert.equal(hasControlChars(`/auth/error${c}x`), true);
    }
  });
});

describe("assertSafeErrorPath — fails closed, never an open redirect", () => {
  test("accepts a valid internal path", () => {
    assert.equal(assertSafeErrorPath("/auth/error"), "/auth/error");
    assert.equal(assertSafeErrorPath("/auth/error?brand=1"), "/auth/error?brand=1");
  });

  test("rejects absolute external URLs", () => {
    assert.throws(() => assertSafeErrorPath("https://evil.com/x"), /not a safe internal path/);
    assert.throws(() => assertSafeErrorPath("http://evil.com/x"), /not a safe internal path/);
  });

  test("rejects protocol-relative //example.com", () => {
    assert.throws(() => assertSafeErrorPath("//example.com"), /not a safe internal path/);
    assert.throws(() => assertSafeErrorPath("//example.com/x"), /not a safe internal path/);
  });

  test("rejects backslash-based bypasses", () => {
    assert.throws(() => assertSafeErrorPath("/\\evil.com"), /not a safe internal path/);
  });

  test("rejects percent-encoded external redirects", () => {
    // "/%2f%2fevil.com" decodes to "//evil.com" — protocol-relative once decoded.
    assert.throws(() => assertSafeErrorPath("/%2f%2fevil.com"), /decodes to an unsafe path/);
    assert.throws(() => assertSafeErrorPath("/%2F%2Fevil.com"), /decodes to an unsafe path/);
  });

  test("rejects javascript: and other schemes", () => {
    assert.throws(() => assertSafeErrorPath("javascript:alert(1)"), /not a safe internal path/);
  });

  test("rejects control characters (CRLF / redirect splitting)", () => {
    for (const c of [NUL, LF, CR, DEL]) {
      assert.throws(() => assertSafeErrorPath(`/auth/error${c}`), /control characters/);
    }
  });

  test("rejects empty and malformed encodings", () => {
    assert.throws(() => assertSafeErrorPath(""), /not a safe internal path/);
    assert.throws(() => assertSafeErrorPath("/%E0%A4%A"), /invalid percent-encoding/);
  });
});

describe("toPublicReason — sanitised allowlist", () => {
  test("every mapped value is on the allowlist", () => {
    const inputs = [
      "access_denied",
      "invalid_callback",
      "token_exchange",
      "id_token",
      "invalid_nonce",
      "sub_mismatch",
      "userinfo",
      "provision",
      "session_create",
      "configuration_error",
      "server_error",
      "temporarily_unavailable",
      "totally_unknown",
      "",
    ];
    for (const i of inputs) {
      assert.ok(
        (ERROR_REASONS as readonly string[]).includes(toPublicReason(i)),
        `${i} -> ${toPublicReason(i)} not on allowlist`,
      );
    }
    assert.ok((ERROR_REASONS as readonly string[]).includes(toPublicReason(null)));
  });

  test("collapses cryptographic/internal detail into invalid_callback", () => {
    // These must NOT be distinguishable to the browser.
    for (const i of ["id_token", "invalid_nonce", "sub_mismatch", "invalid_callback"]) {
      assert.equal(toPublicReason(i), "invalid_callback", i);
    }
  });

  test("maps the meaningful cases", () => {
    assert.equal(toPublicReason("access_denied"), "access_denied");
    assert.equal(toPublicReason("token_exchange"), "provider_unavailable");
    assert.equal(toPublicReason("userinfo"), "provider_unavailable");
    assert.equal(toPublicReason("server_error"), "provider_unavailable");
    assert.equal(toPublicReason("provision"), "session_failed");
    assert.equal(toPublicReason("session_create"), "session_failed");
    assert.equal(toPublicReason("configuration_error"), "configuration_error");
  });

  test("an unknown/hostile provider error never passes through verbatim", () => {
    const hostile = "<script>alert(1)</script>";
    assert.equal(toPublicReason(hostile), "invalid_callback");
    const tokenish = "eyJhbGciOiJIUzI1NiJ9.payload.sig";
    assert.equal(toPublicReason(tokenish), "invalid_callback");
  });
});

describe("buildErrorRedirect — cannot escape the app origin", () => {
  test("resolves against the app origin and sets reason", () => {
    const u = new URL(buildErrorRedirect("/auth/error", "access_denied", ORIGIN));
    assert.equal(u.origin, ORIGIN);
    assert.equal(u.pathname, "/auth/error");
    assert.equal(u.searchParams.get("reason"), "access_denied");
  });

  test("preserves an existing query and overwrites reason", () => {
    const u = new URL(buildErrorRedirect("/auth/error?brand=1", "session_failed", ORIGIN));
    assert.equal(u.searchParams.get("brand"), "1");
    assert.equal(u.searchParams.get("reason"), "session_failed");
  });
});

describe("buildFailureResponse — default behaviour is unchanged", () => {
  test("without errorPath: renders the self-contained HTML page (no redirect)", async () => {
    const res = buildFailureResponse({ ...BASE, reason: "invalid_callback" });
    assert.equal(res.status, 400);
    assert.equal(res.headers.get("content-type"), "text/html; charset=utf-8");
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(res.headers.get("location"), null, "must not redirect by default");
    const body = await res.text();
    assert.match(body, /Sign-in couldn't be completed/);
    assert.match(body, /invalid_callback/);
    assert.match(body, /\/api\/auth\/signin\?returnTo=/);
  });

  test("without errorPath: preserves the custom status", () => {
    const res = buildFailureResponse({ ...BASE, reason: "session_create", status: 500 });
    assert.equal(res.status, 500);
  });

  test("without errorPath: the page slug is sanitised of markup", async () => {
    const res = buildFailureResponse({ ...BASE, reason: "<script>alert(1)</script>" });
    const body = await res.text();
    assert.doesNotMatch(body, /<script>/);
  });
});

describe("buildFailureResponse — branded errorPath routing", () => {
  test("with errorPath: 303 to the app's page with a sanitised reason", () => {
    const res = buildFailureResponse({
      ...BASE,
      reason: "invalid_nonce",
      errorPath: "/auth/error",
    });
    assert.equal(res.status, 303);
    const loc = new URL(res.headers.get("location")!);
    assert.equal(loc.origin, ORIGIN);
    assert.equal(loc.pathname, "/auth/error");
    // The internal reason (invalid_nonce) is collapsed, not echoed.
    assert.equal(loc.searchParams.get("reason"), "invalid_callback");
    assert.doesNotMatch(loc.toString(), /nonce/i);
  });

  test("raw provider errors never reach the browser", () => {
    const res = buildFailureResponse({
      ...BASE,
      reason: "unauthorized_client: bad things happened at the IdP",
      errorPath: "/auth/error",
    });
    const loc = res.headers.get("location")!;
    assert.doesNotMatch(loc, /unauthorized_client/);
    assert.doesNotMatch(loc, /bad things/);
    assert.match(loc, /reason=invalid_callback/);
  });

  test("token-like values never reach the redirect", () => {
    const secretish = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig";
    const res = buildFailureResponse({ ...BASE, reason: secretish, errorPath: "/auth/error" });
    const loc = res.headers.get("location")!;
    assert.doesNotMatch(loc, /eyJ/);
    assert.equal(new URL(loc).searchParams.get("reason"), "invalid_callback");
  });

  test("access_denied is surfaced (the one actionable case)", () => {
    const res = buildFailureResponse({ ...BASE, reason: "access_denied", errorPath: "/auth/error" });
    assert.match(res.headers.get("location")!, /reason=access_denied/);
  });

  test("state-validation failure stays closed (no session, generic reason)", () => {
    const res = buildFailureResponse({ ...BASE, reason: "invalid_callback", errorPath: "/auth/error" });
    assert.equal(res.status, 303);
    assert.match(res.headers.get("location")!, /reason=invalid_callback/);
    assert.equal(res.headers.get("set-cookie"), null, "must never set a session on failure");
  });

  test("session-creation failure stays closed and reports session_failed", () => {
    const res = buildFailureResponse({
      ...BASE,
      reason: "session_create",
      status: 500,
      errorPath: "/auth/error",
    });
    assert.match(res.headers.get("location")!, /reason=session_failed/);
    assert.equal(res.headers.get("set-cookie"), null);
  });

  test("the redirect only ever carries the reason param", () => {
    const res = buildFailureResponse({ ...BASE, reason: "token_exchange", errorPath: "/auth/error" });
    const params = [...new URL(res.headers.get("location")!).searchParams.keys()];
    assert.deepEqual(params, ["reason"]);
  });
});
