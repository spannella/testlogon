/**
 * Auth setup: mint HS256 JWT access-token cookies for test users directly,
 * bypassing the real login flow (DEV_MODE=1).
 *
 * The backend's mint_access_token() issues:
 *   { sub, sid, iat, exp } signed with UI_ACCESS_TOKEN_SECRET using HS256.
 *
 * We replicate this in Node so tests can inject cookies without going through
 * the login page.
 */
import { createHmac } from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";

const UI_ACCESS_TOKEN_SECRET =
  "ufeuNsYvb0u-eseP7UUCqFWiNwiEcDfJnIKGZ3kPPlTJeSBK6ZZh0VVRzue-RZly";
const COOKIE_NAME = "ui_access_token";

function base64UrlEncode(buf: Buffer): string {
  return buf.toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

export function mintJwt(userSub: string): string {
  const now = Math.floor(Date.now() / 1000);
  const header = base64UrlEncode(Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const payload = base64UrlEncode(
    Buffer.from(JSON.stringify({ sub: userSub, sid: "e2e-session", iat: now, exp: now + 3600 }))
  );
  const sig = createHmac("sha256", UI_ACCESS_TOKEN_SECRET)
    .update(`${header}.${payload}`)
    .digest();
  return `${header}.${payload}.${base64UrlEncode(sig)}`;
}

/** Cookie object suitable for browser.addCookies() */
export function authCookie(userSub: string, domain = "localhost") {
  return {
    name: COOKIE_NAME,
    value: mintJwt(userSub),
    domain,
    path: "/",
    httpOnly: true,
    secure: false,
    sameSite: "Lax" as const,
    expires: Math.floor(Date.now() / 1000) + 3600,
  };
}
