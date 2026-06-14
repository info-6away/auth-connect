import "server-only";
import { createHmac, timingSafeEqual } from "node:crypto";
import { cookies } from "next/headers";
import { authEnv } from "./config";

// The base session every app gets. `sub` is the 6away ID (the OIDC `sub`) and
// the only persistent identifier the layer requires. `idToken` is retained
// solely so RP-initiated logout can pass it as `id_token_hint` to
// auth.6away.ai. Apps that keep a local users row extend this with their own
// fields via the generic `S` parameter (e.g. `{ userId: string }`).
export type BaseSession = {
  sub: string;
  email: string | null;
  name: string | null;
  idToken: string;
  exp: number; // unix seconds
};

const MAX_AGE = 30 * 24 * 60 * 60; // 30 days

function sign(value: string): string {
  const mac = createHmac("sha256", authEnv.sessionSecret).update(value).digest("base64url");
  return `${value}.${mac}`;
}

function verify(signed: string): string | null {
  const i = signed.lastIndexOf(".");
  if (i < 0) return null;
  const value = signed.slice(0, i);
  const mac = signed.slice(i + 1);
  const expected = createHmac("sha256", authEnv.sessionSecret).update(value).digest("base64url");
  try {
    const a = Buffer.from(mac, "base64url");
    const b = Buffer.from(expected, "base64url");
    if (a.length === b.length && timingSafeEqual(a, b)) return value;
  } catch {
    // fall through
  }
  return null;
}

export type SessionStore<S extends Record<string, unknown>> = {
  create(payload: Omit<BaseSession, "exp"> & S): Promise<void>;
  get(): Promise<(BaseSession & S) | null>;
  destroy(): Promise<void>;
};

export function makeSessionStore<S extends Record<string, unknown> = Record<string, never>>(
  cookieName: string,
): SessionStore<S> {
  type Session = BaseSession & S;

  return {
    async create(payload) {
      const exp = Math.floor(Date.now() / 1000) + MAX_AGE;
      const full = { ...payload, exp } as Session;
      const value = Buffer.from(JSON.stringify(full)).toString("base64url");
      const jar = await cookies();
      jar.set(cookieName, sign(value), {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
        maxAge: MAX_AGE,
      });
    },

    async get() {
      const jar = await cookies();
      const cookie = jar.get(cookieName)?.value;
      if (!cookie) return null;
      const value = verify(cookie);
      if (!value) return null;
      try {
        const payload = JSON.parse(Buffer.from(value, "base64url").toString()) as Session;
        if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
        return payload;
      } catch {
        return null;
      }
    },

    async destroy() {
      const jar = await cookies();
      jar.delete(cookieName);
    },
  };
}
