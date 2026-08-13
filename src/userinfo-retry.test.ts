import { test, describe, beforeEach, afterEach, mock } from "node:test";
import assert from "node:assert/strict";

// fetchUserInfo retries a TRANSIENT userinfo failure exactly once (network
// error or 5xx), with the SAME access token, and never retries a
// deterministic 4xx. These tests mock global fetch and console.warn; no
// network is touched and no secret is logged.

// authEnv reads NEXT_PUBLIC_AUTH_URL lazily on first use.
process.env.NEXT_PUBLIC_AUTH_URL = "https://auth.example.com";

const { fetchUserInfo } = await import("./oidc");

const TOKEN = "access-token-abc123";
const OK_BODY = { sub: "s-1", email: "a@b.com", email_verified: true, name: "A" };

type Attempt =
  | { kind: "ok"; body?: unknown }
  | { kind: "status"; status: number }
  | { kind: "network" };

let calls: Array<{ url: string; authorization: string | undefined }>;
let warnings: string[];
let realFetch: typeof globalThis.fetch;
let realWarn: typeof console.warn;

function program(attempts: Attempt[]) {
  let i = 0;
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    const headers = (init?.headers ?? {}) as Record<string, string>;
    calls.push({ url: String(url), authorization: headers.authorization });
    const step = attempts[Math.min(i, attempts.length - 1)];
    i++;
    if (step.kind === "network") throw new TypeError("fetch failed");
    if (step.kind === "status") {
      return { ok: false, status: step.status, json: async () => ({}) } as unknown as Response;
    }
    return {
      ok: true,
      status: 200,
      json: async () => step.body ?? OK_BODY,
    } as unknown as Response;
  }) as unknown as typeof globalThis.fetch;
}

beforeEach(() => {
  calls = [];
  warnings = [];
  realFetch = globalThis.fetch;
  realWarn = console.warn;
  console.warn = ((...a: unknown[]) => {
    warnings.push(a.map(String).join(" "));
  }) as typeof console.warn;
});
afterEach(() => {
  globalThis.fetch = realFetch;
  console.warn = realWarn;
  mock.reset();
});

describe("fetchUserInfo transient retry", () => {
  test("1. first attempt succeeds → one request, no retry", async () => {
    program([{ kind: "ok" }]);
    const out = await fetchUserInfo(TOKEN);
    assert.deepEqual(out, OK_BODY);
    assert.equal(calls.length, 1);
    assert.equal(warnings.length, 0);
  });

  test("2. network error then success → two requests, resolves", async () => {
    program([{ kind: "network" }, { kind: "ok" }]);
    const out = await fetchUserInfo(TOKEN);
    assert.deepEqual(out, OK_BODY);
    assert.equal(calls.length, 2);
    assert.ok(warnings.some((w) => w.includes("userinfo_retry attempt=2 reason=network")));
  });

  test("3. 500 then success → two requests, resolves", async () => {
    program([{ kind: "status", status: 500 }, { kind: "ok" }]);
    const out = await fetchUserInfo(TOKEN);
    assert.deepEqual(out, OK_BODY);
    assert.equal(calls.length, 2);
    assert.ok(warnings.some((w) => w.includes("userinfo_retry attempt=2 reason=5xx")));
  });

  test("4. network error twice → throws, two requests", async () => {
    program([{ kind: "network" }, { kind: "network" }]);
    await assert.rejects(() => fetchUserInfo(TOKEN), /userinfo failed/);
    assert.equal(calls.length, 2);
  });

  test("5. 500 twice → throws, two requests", async () => {
    program([{ kind: "status", status: 500 }, { kind: "status", status: 503 }]);
    await assert.rejects(() => fetchUserInfo(TOKEN), /userinfo failed: 503/);
    assert.equal(calls.length, 2);
  });

  test("6. 401 → one request only, no retry", async () => {
    program([{ kind: "status", status: 401 }]);
    await assert.rejects(() => fetchUserInfo(TOKEN), /userinfo failed: 401/);
    assert.equal(calls.length, 1);
    assert.equal(warnings.length, 0);
  });

  test("7. 403 → one request only, no retry", async () => {
    program([{ kind: "status", status: 403 }]);
    await assert.rejects(() => fetchUserInfo(TOKEN), /userinfo failed: 403/);
    assert.equal(calls.length, 1);
    assert.equal(warnings.length, 0);
  });

  test("8. deterministic 4xx (400, 429) → no retry", async () => {
    for (const status of [400, 429]) {
      calls = [];
      warnings = [];
      program([{ kind: "status", status }]);
      await assert.rejects(() => fetchUserInfo(TOKEN), new RegExp(`userinfo failed: ${status}`));
      assert.equal(calls.length, 1, `status ${status} must not retry`);
    }
  });

  test("9. retry reuses the SAME access token (asserted via header, token not printed)", async () => {
    program([{ kind: "status", status: 500 }, { kind: "ok" }]);
    await fetchUserInfo(TOKEN);
    assert.equal(calls.length, 2);
    // Both attempts carried an identical Authorization header.
    assert.equal(calls[0].authorization, calls[1].authorization);
    assert.equal(calls[0].authorization, `Bearer ${TOKEN}`);
  });

  test("10. no sensitive value (token, header, email, sub, body) reaches logging", async () => {
    program([{ kind: "network" }, { kind: "ok" }]);
    await fetchUserInfo(TOKEN);
    const log = warnings.join("\n");
    for (const secret of [TOKEN, "Bearer", "authorization", "a@b.com", "s-1", "email"]) {
      assert.ok(!log.includes(secret), `log must not contain "${secret}"`);
    }
    // Only the safe retry marker is present.
    assert.ok(/userinfo_retry attempt=2 reason=(network|5xx)/.test(log));
  });

  test("malformed body on a 2xx is not retried (a retry cannot fix it)", async () => {
    let i = 0;
    globalThis.fetch = (async () => {
      i++;
      return {
        ok: true,
        status: 200,
        json: async () => {
          throw new SyntaxError("Unexpected token");
        },
      } as unknown as Response;
    }) as unknown as typeof globalThis.fetch;
    await assert.rejects(() => fetchUserInfo(TOKEN), /Unexpected token/);
    assert.equal(i, 1);
  });
});
