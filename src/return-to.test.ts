import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { safeReturnTo } from "./return-to";

// REGRESSION — open redirect after sign-in (v1.0.6). `?returnTo=/%09/evil.example`
// decodes to "/\t/evil.example". The old check only looked at the first two
// characters ("/" then not "/" or "\"), so it passed; the callback's
// `new URL(dest, origin)` then dropped the tab and resolved "//evil.example" to
// https://evil.example/. Tab, CR and LF all did this.
//
// `landing()` follows create.ts exactly: signin() reads ?returnTo through
// URLSearchParams and runs safeReturnTo; the value round-trips through a cookie;
// callback() runs safeReturnTo again and redirects to new URL(dest, url.origin).

const ORIGIN = "https://app.example.com";
const DEFAULT = "/";

// The tests go through `safeReturnTo` only, the function sign-in and the
// callback both call, so the same file runs against the old and the fixed code.
const FALLBACK = "/__fallback__";
const accepted = (v: unknown): boolean => safeReturnTo(v as string, FALLBACK) === v;

function landing(rawQueryValue: string): string {
  const fromQuery = new URL(`${ORIGIN}/api/auth/signin?returnTo=${rawQueryValue}`).searchParams.get(
    "returnTo",
  );
  const stored = safeReturnTo(fromQuery, DEFAULT); // signin(): cookie value
  const dest = safeReturnTo(stored, DEFAULT); // callback(): re-validated
  return new URL(dest, ORIGIN).href;
}

// Control characters, built by code so the test source stays free of raw bytes.
const TAB = String.fromCharCode(9);
const LF = String.fromCharCode(10);
const CR = String.fromCharCode(13);
const NUL = String.fromCharCode(0);
const DEL = String.fromCharCode(127);

describe("returnTo — the reported exploit", () => {
  test("?returnTo=/%09/evil.example lands on the app, not evil.example", () => {
    assert.equal(landing("/%09/evil.example"), `${ORIGIN}/`);
  });

  test("the decoded value is rejected outright", () => {
    assert.equal(accepted(`/${TAB}/evil.example`), false);
    assert.equal(safeReturnTo(`/${TAB}/evil.example`, DEFAULT), DEFAULT);
  });
});

describe("returnTo — rejects everything that could leave the origin", () => {
  test("scheme-relative URLs", () => {
    for (const raw of ["//evil.example", "//evil.example/x", "///evil.example", "/%2F%2Fevil.example", "/%2f/evil.example"]) {
      assert.equal(landing(raw), `${ORIGIN}/`, raw);
    }
  });

  test("absolute URLs and other schemes", () => {
    for (const raw of [
      "https://evil.example",
      "http://evil.example/x",
      "https%3A%2F%2Fevil.example",
      "javascript:alert(1)",
      "data:text/html,x",
    ]) {
      assert.equal(landing(raw), `${ORIGIN}/`, raw);
    }
  });

  test("encoded tabs, newlines and other control characters", () => {
    for (const raw of [
      "/%09/evil.example",
      "/%0a/evil.example",
      "/%0A/evil.example",
      "/%0d/evil.example",
      "/%0D%0A/evil.example",
      "/%09%09/evil.example",
      "/home%0A",
      "/%00/evil.example",
      "/%7F/evil.example",
      // Double-encoded: arrives as a literal "%09" and must not survive a
      // later decode either.
      "/%2509/evil.example",
      "/%250a/evil.example",
    ]) {
      assert.equal(landing(raw), `${ORIGIN}/`, raw);
    }
  });

  test("literal control characters anywhere in the value", () => {
    for (const c of [TAB, LF, CR, NUL, DEL]) {
      for (const v of [`/${c}/evil.example`, `/home${c}`, `/a${c}b`, `/${c}${c}evil.example`]) {
        assert.equal(accepted(v), false, JSON.stringify(v));
      }
    }
  });

  test("backslash variants, literal and encoded", () => {
    for (const v of ["/\\evil.example", "/\\/evil.example", "/a\\b", "\\\\evil.example", "/%5Cevil.example", "/%5C%5Cevil.example", "/%5c/evil.example"]) {
      assert.equal(accepted(v), false, v);
    }
    for (const raw of ["/%5Cevil.example", "/%5C%5Cevil.example", "/%5c/evil.example"]) {
      assert.equal(landing(raw), `${ORIGIN}/`, raw);
    }
  });

  test("malformed percent-encoding and non-strings", () => {
    for (const v of ["/%E0%A4%A", "/%", "", null, undefined, 42, {}]) {
      assert.equal(accepted(v), false, String(v));
    }
  });
});

describe("returnTo — legitimate application paths still work", () => {
  test("plain paths, queries and fragments land where asked", () => {
    for (const p of [
      "/",
      "/home",
      "/search?q=x",
      "/calendar",
      "/member/0f1e2d3c-4b5a-4968-8776-655443322110/edit",
      "/search?q=rotary%20club",
      "/search?q=https%3A%2F%2Fexample.com",
      "/messages/abc?after=2026-10-16T00%3A00%3A00Z",
      "/onboarding/basic?event=j1NkSPyDDpsxNq51Aes3dfqF",
      "/onboarding/basic?invite=Ab3_-xYz09Qw&name=Jos%C3%A9+M%C3%BCller",
      "/a#frag",
    ]) {
      assert.equal(accepted(p), true, p);
      assert.equal(landing(encodeURIComponent(p)), new URL(p, ORIGIN).href, p);
    }
  });

  test("an unsafe value degrades to the configured default, never fails", () => {
    assert.equal(safeReturnTo("/%09/evil.example".replace("%09", TAB), "/dashboard"), "/dashboard");
    assert.equal(safeReturnTo(null, "/dashboard"), "/dashboard");
    assert.equal(safeReturnTo(undefined, "/dashboard"), "/dashboard");
  });
});
