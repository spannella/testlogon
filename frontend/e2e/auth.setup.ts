/**
 * Auth setup (W2) — REAL cpp login, not Python-JWT minting.
 *
 * The previous version of this file minted HS256 JWTs with the *Python*
 * backend's UI_ACCESS_TOKEN_SECRET and a fabricated {sub,sid,iat,exp} payload.
 * That is invalid against the C++ backend, which:
 *   - signs ui_access_token with a DIFFERENT secret, and
 *   - uses a REVOCABLE server-side session (ui_session) — a hand-minted JWT
 *     has no matching session row, so cpp rejects it.
 *
 * Instead we perform a REAL login against cpp for each fixture identity and
 * capture the Set-Cookie trio (ui_session / ui_access_token / ui_csrf), exactly
 * as a browser would. The result is written as a Playwright storageState per
 * project so specs authenticate with genuine cpp cookies.
 *
 * cpp auth contract:
 *   POST ${API}/ui/session/start {challenge_context:{username,password}}
 *     -> 200 + Set-Cookie: ui_session, ui_access_token (JWT), ui_csrf
 *   GET  ${API}/ui/me -> {user_sub, session_id}
 *
 * When E2E_API_BASE points at cpp (through the vite same-origin proxy, i.e.
 * baseURL http://localhost:3000 which proxies /ui -> https://192.168.0.82:8443)
 * we log in at run time. The vite proxy makes cpp same-origin as the app, so the
 * cookies land on the localhost:3000 domain — which is what storageState needs.
 *
 * Fallback (no live cpp reachable at setup time): load the F2 seeder's
 * storageState JSONs from e2e/.cpp-auth/ and retarget the cookie domain.
 */
import { test as setup, expect, request } from "@playwright/test";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { API } from "./cpp.config";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CPP_AUTH_DIR = path.join(__dirname, ".cpp-auth");
const PASSWORD = process.env.E2E_PASSWORD ?? "Passw0rd!123";

/**
 * Fixture-identity -> cpp account mapping.
 *
 * The legacy suite speaks in terms of root/alice/bob/charlie_admin (seeded by
 * the Python e2e_admin_session_setup.py). cpp's F2 seeder provides three real
 * accounts. We map:
 *   root          -> e2e_admin  (role=admin; covers require_admin gates)
 *   charlie_admin -> e2e_admin  (same admin account)
 *   alice         -> e2e_alice
 *   bob           -> e2e_bob
 *
 * NOTE on true-root: the Python fixture distinguishes role="root" from
 * role="admin". cpp's require_admin gate is satisfied by role=admin, so mapping
 * root->e2e_admin unblocks all admin-gated specs. Genuinely root-ONLY routes
 * (cpp checks g_root_user_sub) are NOT covered by this mapping and must be
 * quarantined in W3 (they need the cpp server started with g_root_user_sub set
 * to e2e_admin's sub + a restart — out of scope for W2).
 */
export interface CppUser {
  /** cpp login email */
  email: string;
  /** short storageState basename under e2e/.cpp-auth/ */
  file: string;
  /** role as seeded in cpp (informational) */
  role: "user" | "admin";
}

/** Fixture identity key -> cpp account. */
export const IDENTITY_MAP: Record<string, CppUser> = {
  bob: { email: "e2e_bob@test.local", file: "bob", role: "user" },
  alice: { email: "e2e_alice@test.local", file: "alice", role: "user" },
  admin: { email: "e2e_admin@test.local", file: "admin", role: "admin" },
  // Legacy fixture aliases that resolve onto the cpp admin account.
  root: { email: "e2e_admin@test.local", file: "admin", role: "admin" },
  charlie_admin: { email: "e2e_admin@test.local", file: "admin", role: "admin" },
};

/** The three distinct cpp accounts (dedup of IDENTITY_MAP by email). */
export const CPP_ACCOUNTS: CppUser[] = [
  IDENTITY_MAP.bob,
  IDENTITY_MAP.alice,
  IDENTITY_MAP.admin,
];

export interface CppCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: "Lax" | "Strict" | "None";
  expires: number;
}

export interface CppStorageState {
  cookies: CppCookie[];
  origins: Array<{ origin: string; localStorage: Array<{ name: string; value: string }> }>;
}

const COOKIE_NAMES = ["ui_session", "ui_access_token", "ui_csrf"] as const;

/**
 * Perform a real cpp login and return the three auth cookies (domain-less; the
 * caller assigns a domain). Uses a Playwright APIRequestContext so it honours
 * the same ignoreHTTPSErrors config as the browser (cpp uses a self-signed
 * cert). Returns null on any non-2xx / missing-cookie so callers can fall back.
 */
export async function cppLogin(
  apiBase: string,
  email: string,
  password: string,
  domain: string,
): Promise<CppCookie[] | null> {
  const ctx = await request.newContext({
    baseURL: apiBase,
    ignoreHTTPSErrors: true,
  });
  try {
    const resp = await ctx.post("/ui/session/start", {
      data: { challenge_context: { username: email, password } },
      headers: { "Content-Type": "application/json" },
    });
    if (!resp.ok()) return null;
    // Prefer parsing Set-Cookie response headers (robust regardless of the
    // context's cookie-store domain heuristics).
    const setCookies = resp.headersArray().filter((h) => h.name.toLowerCase() === "set-cookie");
    const byName = new Map<string, string>();
    for (const h of setCookies) {
      const first = h.value.split(";", 1)[0];
      const eq = first.indexOf("=");
      if (eq > 0) byName.set(first.slice(0, eq).trim(), first.slice(eq + 1).trim());
    }
    const now = Math.floor(Date.now() / 1000);
    const out: CppCookie[] = [];
    for (const name of COOKIE_NAMES) {
      const value = byName.get(name);
      if (!value) return null;
      out.push({
        name,
        value,
        domain,
        path: "/",
        httpOnly: name !== "ui_csrf", // ui_csrf must be readable by JS
        secure: false,
        sameSite: "Lax",
        expires: now + 86400,
      });
    }
    return out;
  } catch {
    return null;
  } finally {
    await ctx.dispose();
  }
}

/**
 * Wrap a cookie trio in a Playwright storageState, additionally seeding the
 * client Zustand auth-store in localStorage for the app origin so the SPA's
 * ProtectedRoute guard passes (cookies alone authenticate API calls, not the
 * client router). `userSub` may be undefined if unknown.
 */
export function buildStorageState(
  cookies: CppCookie[],
  appOrigin: string,
  userSub?: string,
): CppStorageState {
  const origins: CppStorageState["origins"] = [];
  if (userSub) {
    origins.push({
      origin: appOrigin,
      localStorage: [
        {
          name: "auth-store",
          value: JSON.stringify({
            state: { userId: userSub, accessToken: null, isAuthenticated: true },
            version: 0,
          }),
        },
      ],
    });
  }
  return { cookies, origins };
}

/** Retarget the F2 storageState JSON's cookie domain (fallback path). */
function loadFallbackStorageState(file: string, domain: string): CppStorageState | null {
  const p = path.join(CPP_AUTH_DIR, `${file}.storageState.json`);
  if (!fs.existsSync(p)) return null;
  const raw = JSON.parse(fs.readFileSync(p, "utf8")) as CppStorageState;
  for (const c of raw.cookies) c.domain = domain;
  return raw;
}

/**
 * Produce a storageState for a cpp account: try a live login first, fall back to
 * the F2 seeder JSON. `domain` is the cookie domain (e.g. "localhost" for the
 * vite dev server on localhost:3000).
 */
export async function storageStateForAccount(
  apiBase: string,
  acct: CppUser,
  domain: string,
  appOrigin: string,
): Promise<{ state: CppStorageState; source: "cpp-login" | "fallback-json" } | null> {
  const cookies = await cppLogin(apiBase, acct.email, PASSWORD, domain);
  if (cookies) {
    const at = cookies.find((c) => c.name === "ui_access_token")?.value;
    return {
      state: buildStorageState(cookies, appOrigin, subFromJwt(at)),
      source: "cpp-login",
    };
  }
  const fb = loadFallbackStorageState(acct.file, domain);
  if (fb) {
    // Seed the client auth-store from the fallback JWT's sub too.
    const at = fb.cookies.find((c) => c.name === "ui_access_token")?.value;
    const sub = subFromJwt(at);
    if (sub && fb.origins.length === 0) {
      fb.origins.push({
        origin: appOrigin,
        localStorage: [
          {
            name: "auth-store",
            value: JSON.stringify({
              state: { userId: sub, accessToken: null, isAuthenticated: true },
              version: 0,
            }),
          },
        ],
      });
    }
    return { state: fb, source: "fallback-json" };
  }
  return null;
}

/** Decode the `sub` claim from a JWT (base64url middle segment); "" on failure. */
function subFromJwt(jwt?: string): string | undefined {
  if (!jwt) return undefined;
  try {
    const payload = JSON.parse(Buffer.from(jwt.split(".")[1], "base64").toString("utf8"));
    return typeof payload.sub === "string" ? payload.sub : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Playwright setup project entrypoint. Logs in each distinct cpp account and
 * writes e2e/.cpp-auth/<file>.storageState.json (real cpp cookies retargeted to
 * the run's cookie domain). playwright.config wires per-project storageState to
 * these files.
 */
setup("authenticate cpp fixture identities", async ({ baseURL }) => {
  const domain = process.env.E2E_COOKIE_DOMAIN ?? "localhost";
  const appOrigin = baseURL ?? "http://localhost:3000";
  fs.mkdirSync(CPP_AUTH_DIR, { recursive: true });

  for (const acct of CPP_ACCOUNTS) {
    const result = await storageStateForAccount(API, acct, domain, appOrigin);
    expect(result, `no auth for ${acct.email} (login + fallback both failed)`).not.toBeNull();
    const outPath = path.join(CPP_AUTH_DIR, `${acct.file}.storageState.json`);
    fs.writeFileSync(outPath, JSON.stringify(result!.state, null, 2));
    // eslint-disable-next-line no-console
    console.log(`[auth.setup] ${acct.email} -> ${outPath} (${result!.source})`);
  }
});

/** Absolute path to a project's storageState file (used by playwright.config). */
export function storageStatePath(identityFile: string): string {
  return path.join(CPP_AUTH_DIR, `${identityFile}.storageState.json`);
}
