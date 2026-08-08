/**
 * Shared E2E session helpers.
 *
 * Provides cookie-based auth injection for the admin/role test identities
 * (root, alice, bob, charlie_admin, charlie_scoped, compliance_admin) seeded by
 * `e2e_admin_session_setup.py`. This module was referenced by several specs
 * (connection-profiles, post-hide) but had never been created; it implements the
 * canonical pattern used inline by the rest of the suite.
 *
 * W2 (cpp harness): when the suite targets the C++ backend, the Python seeder's
 * hand-minted JWTs are invalid (different secret + revocable-session model).
 * With E2E_USE_CPP=1 (or when E2E_API_BASE points away from the Python default)
 * loadSessions() instead performs REAL cpp logins for the fixture identities and
 * returns genuine cpp cookies, mapping root/charlie_admin -> e2e_admin,
 * alice -> e2e_alice, bob -> e2e_bob. Falls back to the F2 storageState JSONs in
 * e2e/.cpp-auth/ if a live login is unreachable.
 */
import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import type { Page, APIRequestContext } from "@playwright/test";
import { request as pwRequest } from "@playwright/test";

// Repo root, derived from the Playwright run cwd (always frontend/) so the
// session seeders resolve in CI (/home/runner/...) and any host, not just the
// dev box. Override with E2E_REPO_ROOT if invoked from elsewhere.
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");
const CPP_AUTH_DIR = path.resolve(process.cwd(), "e2e", ".cpp-auth");

export interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string;
    value: string;
    domain: string;
    path: string;
    httpOnly: boolean;
    secure: boolean;
    sameSite: "Lax" | "Strict" | "None";
    expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;

// ── cpp real-login path (W2) ─────────────────────────────────────────────────

/** True when the suite is pointed at the C++ backend. */
function usingCpp(): boolean {
  if (process.env.E2E_USE_CPP === "1") return true;
  const api = process.env.E2E_API_BASE ?? "";
  // Python default is http://localhost:8000; anything else set explicitly and
  // non-empty means a repointed backend (cpp via proxy or direct :8443).
  return api !== "" && !/localhost:8000\/?$/.test(api);
}

const CPP_API = process.env.E2E_API_BASE ?? "https://192.168.0.82:8443";
const CPP_PASSWORD = process.env.E2E_PASSWORD ?? "Passw0rd!123";
const CPP_COOKIE_DOMAIN = process.env.E2E_COOKIE_DOMAIN ?? "localhost";
// Specs reach cpp two ways: some hit the API base host DIRECTLY (e.g.
// admin-roles -> https://192.168.0.82:8443) while others go through the vite
// dev server at http://localhost:3000 which PROXIES /calendar,/mock,... to cpp
// (changeOrigin). A cookie is only sent if its domain matches the REQUEST host,
// so inject each session cookie under BOTH the API host and localhost.
function _cppApiHost(): string {
  try { return new URL(CPP_API).hostname || "localhost"; } catch { return "localhost"; }
}
const CPP_COOKIE_DOMAINS: string[] = Array.from(
  new Set([CPP_COOKIE_DOMAIN, _cppApiHost(), "localhost"]),
);

/** identity key -> {cpp email, F2 fallback file}. */
const CPP_IDENTITY: Record<string, { email: string; file: string }> = {
  bob: { email: "e2e_bob@test.local", file: "bob" },
  alice: { email: "e2e_alice@test.local", file: "alice" },
  admin: { email: "e2e_admin@test.local", file: "admin" },
  // ROOT is a DISTINCT cpp identity: its sub is the fixed literal
  // "root.admin@testdev.local" (seed_cpp.py direct-writes the row with that PK)
  // so the admin-roles / admin-compute / admin-rate-limits specs' hardcoded
  // ROOT_SUB matches the live audit-key + actor_sub. It is role=root ONLY when
  // cpp runs with ROOT_USER_SUB=root.admin@testdev.local. Distinct from
  // charlie_admin (below), which stays the general-admin e2e_admin account so
  // the require_root-vs-require_admin boundary tests exercise a real 403.
  root: { email: "root.admin@testdev.local", file: "root" },
  charlie_admin: { email: "e2e_admin@test.local", file: "admin" },
  // charlie is a distinct cpp fixture (role=admin, separate sub) used by the
  // catalog/subscription scoping tests as a non-subscriber / isolated creator.
  charlie: { email: "e2e_charlie@test.local", file: "charlie" },
  // compliance_admin / charlie_scoped are ADMIN-role identities the moderation /
  // messaging-compliance / payment-disputes specs index by name. cpp has no
  // per-name scoped fixture, so alias them to the general e2e_admin account: the
  // specs only need an admin-authenticated session to exercise the admin gate,
  // and this prevents getSessions()[name] -> undefined -> ".cookies" NPEs on the
  // cpp path (Python path unchanged; loadCppSessions is cpp-only).
  // C1 messaging-compliance: compliance_admin must be BOTH admin AND the group
  // participant/creator that setupConversationsAndMessages uses (CHARLIE_ID).
  // e2e_charlie is role=admin, so it passes require_admin AND require_participant_active.
  compliance_admin: { email: "e2e_charlie@test.local", file: "charlie" },
  // charlie_scoped is a DEDICATED scoped-admin fixture (role=admin,
  // admin_profile={type:"scoped",scopes:["auth_support"]}, NO billing_support)
  // provisioned by seed_cpp.py so cpp's require_admin_scope("billing_support")
  // gate returns a real 403 (payment-disputes 83.2). It MUST be a distinct
  // login from the general e2e_admin/e2e_charlie admins (both hold all scopes).
  charlie_scoped: { email: "e2e_charlie_scoped@test.local", file: "charlie_scoped" },
};

/** Synchronous real cpp login via curl (loadSessions is sync/execSync-based). */
function cppLoginSync(email: string): SessionData | null {
  try {
    // -k: self-signed cert. -D -: dump headers so we can read Set-Cookie.
    const body = JSON.stringify({ challenge_context: { username: email, password: CPP_PASSWORD } });
    const raw = execSync(
      `curl -k -s -D - -o /dev/null -X POST ${CPP_API}/ui/session/start ` +
        `-H 'Content-Type: application/json' --data-binary @-`,
      { input: body, timeout: 30_000 },
    ).toString();
    const jar: Record<string, string> = {};
    for (const line of raw.split(/\r?\n/)) {
      const m = /^set-cookie:\s*([^=]+)=([^;]+)/i.exec(line);
      if (m) jar[m[1].trim()] = m[2].trim();
    }
    const sid = jar["ui_session"];
    const at = jar["ui_access_token"];
    const csrf = jar["ui_csrf"];
    if (!sid || !at || !csrf) return null;
    // Decode the JWT payload for the sub (base64url middle segment).
    let sub = "";
    try {
      const payload = JSON.parse(Buffer.from(at.split(".")[1], "base64").toString("utf8"));
      sub = payload.sub ?? "";
    } catch {
      /* leave sub empty */
    }
    const now = Math.floor(Date.now() / 1000);
    const mk = (name: string, value: string, httpOnly: boolean) =>
      CPP_COOKIE_DOMAINS.map((domain) => ({
        name,
        value,
        domain,
        path: "/",
        httpOnly,
        secure: false,
        sameSite: "Lax" as const,
        expires: now + 86400,
      }));
    return {
      user_sub: sub,
      session_id: sid,
      csrf_token: csrf,
      access_token: at,
      cookies: [
        ...mk("ui_session", sid, true),
        ...mk("ui_access_token", at, true),
        ...mk("ui_csrf", csrf, false),
      ],
    };
  } catch {
    return null;
  }
}

/**
 * Register a fresh THROWAWAY cpp user (unique per call) and return its live
 * SessionData. Used by destructive specs (account-deletion, MFA-enroll) so they
 * mutate/delete a disposable account instead of the shared e2e_alice/e2e_bob
 * fixtures — a hard-delete or leftover MFA factor then never poisons the shared
 * cohort's login. cpp-only (returns null off the cpp path). The caller injects
 * the result into its own getSessions() map under whatever key it used to use.
 */
export function cppRegisterThrowaway(
  tag = "tw",
): { email: string; session: SessionData } | null {
  if (!usingCpp()) return null;
  const rand = Math.random().toString(36).slice(2, 8);
  const email = `e2e_${tag}_${Date.now()}_${rand}@test.local`;
  try {
    const body = JSON.stringify({
      email,
      password: CPP_PASSWORD,
      full_name: `E2E Throwaway ${tag}`,
    });
    execSync(
      `curl -k -s -o /dev/null -X POST ${CPP_API}/ui/register/start ` +
        `-H 'Content-Type: application/json' --data-binary @-`,
      { input: body, timeout: 30_000 },
    );
  } catch {
    return null;
  }
  const session = cppLoginSync(email);
  if (!session) return null;
  return { email, session };
}

/** Fallback: read the F2 storageState JSON, retarget domain, shape as SessionData. */
function cppFallbackSession(file: string): SessionData | null {
  const p = path.join(CPP_AUTH_DIR, `${file}.storageState.json`);
  if (!fs.existsSync(p)) return null;
  try {
    const ss = JSON.parse(fs.readFileSync(p, "utf8")) as {
      cookies: SessionData["cookies"];
    };
    const cookies = ss.cookies.flatMap((c) => CPP_COOKIE_DOMAINS.map((domain) => ({ ...c, domain })));
    const at = cookies.find((c) => c.name === "ui_access_token")?.value ?? "";
    const sid = cookies.find((c) => c.name === "ui_session")?.value ?? "";
    const csrf = cookies.find((c) => c.name === "ui_csrf")?.value ?? "";
    let sub = "";
    try {
      sub = JSON.parse(Buffer.from(at.split(".")[1], "base64").toString("utf8")).sub ?? "";
    } catch {
      /* ignore */
    }
    return { user_sub: sub, session_id: sid, csrf_token: csrf, access_token: at, cookies };
  } catch {
    return null;
  }
}

function loadCppSessions(): Record<string, SessionData> {
  const out: Record<string, SessionData> = {};
  const byEmail = new Map<string, SessionData>();
  for (const [key, { email, file }] of Object.entries(CPP_IDENTITY)) {
    let sess = byEmail.get(email);
    if (!sess) {
      // Retry the live login a few times before falling back: cppLoginSync
      // occasionally returns null on a transient curl/Set-Cookie miss, which
      // would otherwise leave this identity absent for the whole worker and
      // NPE any spec's beforeAll (getSessions()[id].cookies).
      for (let attempt = 0; attempt < 6 && !sess; attempt++) {
        sess = cppLoginSync(email) || undefined!;
        // Short backoff between attempts to ride out the --workers=4 connect
        // storm on cpp's /ui/session/start (transient curl exit 000).
        if (!sess && attempt < 5) {
          try { execSync("sleep 0.4"); } catch { /* ignore */ }
        }
      }
      sess = sess || cppFallbackSession(file) || undefined!;
      if (sess) byEmail.set(email, sess);
    }
    if (sess) out[key] = sess;
  }
  // Email-keyed aliases: many specs index getSessions() by the raw test
  // email (e2e_alice@test.local) rather than the short name, mirroring the
  // Python seeders' _ALIASES. Register each identity under its email too.
  for (const [key, { email }] of Object.entries(CPP_IDENTITY)) {
    if (out[key] && !out[email]) out[email] = out[key];
  }
  // Sub-keyed aliases: cpp is SUB-based, so specs that use resolveIdentityId()
  // to swap email→sub for URL paths / assertions then still need getSessions()
  // to resolve that same value back to a session. Register each identity under
  // its user_sub too so `getSessions()[<sub>]` works uniformly.
  for (const sess of Object.values({ ...out })) {
    if (sess.user_sub && !out[sess.user_sub]) out[sess.user_sub] = sess;
  }
  if (Object.keys(out).length === 0) {
    throw new Error(
      "loadSessions(cpp): every fixture login + fallback failed. Is cpp reachable at " +
        CPP_API +
        " and are e2e/.cpp-auth/*.storageState.json present?",
    );
  }
  return out;
}

export function loadSessions(): Record<string, SessionData> {
  if (!_sessions) {
    if (usingCpp()) {
      _sessions = loadCppSessions();
    } else {
      const raw = execSync(`python3 ${REPO_ROOT}/e2e_admin_session_setup.py`, {
        cwd: REPO_ROOT,
        timeout: 30_000,
      }).toString();
      // The script prints human-readable "Created session ..." lines before the JSON.
      const start = raw.indexOf("{");
      if (start < 0) throw new Error("e2e_admin_session_setup.py produced no JSON");
      _sessions = JSON.parse(raw.slice(start)) as Record<string, SessionData>;
    }
  }
  return _sessions!;
}

// Tracks which identity's session was injected into a given page so that
// getSession(page) can return the correct CSRF token per page.
const _pageSession = new WeakMap<Page, SessionData>();

/** Inject the cookies for identity `key` (default "alice") into the page's context. */
export async function injectAuth(page: Page, key = "alice"): Promise<void> {
  const sess = loadSessions()[key];
  if (!sess) throw new Error(`No seeded session for identity "${key}"`);
  await page.context().addCookies(sess.cookies);
  // The client router gates protected routes on the persisted Zustand auth-store
  // (ProtectedRoute → useAuthStore.isAuthenticated). Cookies alone authenticate
  // API calls but not the SPA, so seed the auth-store before any page load to
  // avoid a redirect to /login. addInitScript runs on every navigation in this
  // context, so it survives reloads too.
  await page.addInitScript((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, sess.user_sub);
  _pageSession.set(page, sess);
}

/** Return the SessionData for a page (previously injected) or for an identity key. */
export function getSession(pageOrKey: Page | string): SessionData {
  if (typeof pageOrKey === "string") {
    const s = loadSessions()[pageOrKey];
    if (!s) throw new Error(`No seeded session for identity "${pageOrKey}"`);
    return s;
  }
  const s = _pageSession.get(pageOrKey);
  if (!s) throw new Error("getSession(page): call injectAuth(page, key) before getSession(page)");
  return s;
}

// ── cpp identity + CSRF + unauth helpers (auth-harness track) ────────────────

/**
 * True when the suite targets the C++ backend (E2E_USE_CPP=1, or a non-Python
 * E2E_API_BASE). Exported so specs can gate cpp-only behavior (sub-vs-email
 * identity, cookie+CSRF auth) without duplicating the detection logic. The
 * default Python path always returns false, leaving those specs unchanged.
 */
export function isCpp(): boolean {
  return usingCpp();
}

/**
 * Resolve an identity key/email to the id the backend actually reports.
 *
 * The Python backend keys creators/subscribers by their EMAIL, so specs were
 * written to assert `creator_id === "e2e_alice@test.local"` and to send
 * `X-User-Id: <email>`. The cpp backend is SUB-based: it stores and returns the
 * JWT `sub` (e.g. alice -> "7QXYV1Ot5A2VOph9"), never the email. When targeting
 * cpp we therefore map the identity to its real logged-in sub (from the live
 * session), preserving the test's intent ("the creator is alice") while
 * comparing against what cpp genuinely returns. On the Python path the email is
 * returned verbatim, so existing runs are byte-for-byte unchanged.
 */
export function resolveIdentityId(keyOrEmail: string): string {
  if (!usingCpp()) return keyOrEmail;
  const sessions = loadSessions();
  const sess = sessions[keyOrEmail];
  if (sess?.user_sub) return sess.user_sub;
  // keyOrEmail may be a short key (e.g. "alice") whose session is registered
  // only under the email alias, or vice-versa. Fall back to a scan by matching
  // the CPP_IDENTITY email for the given short key.
  const ident = CPP_IDENTITY[keyOrEmail as keyof typeof CPP_IDENTITY];
  if (ident) {
    const viaEmail = sessions[ident.email];
    if (viaEmail?.user_sub) return viaEmail.user_sub;
  }
  return keyOrEmail;
}

/** Return the ui_csrf token for an identity key/email (from its live session). */
export function csrfFor(keyOrEmail: string): string {
  const sess = loadSessions()[keyOrEmail];
  return sess?.csrf_token ?? "";
}

/**
 * Create a genuinely UNAUTHENTICATED APIRequestContext.
 *
 * In the cpp Playwright project every test inherits `storageState: admin` at
 * the project level, so the built-in `request` fixture is silently admin-
 * authenticated — which makes "unauthenticated -> 401/403" assertions observe a
 * 200 and fail spuriously. This context is constructed with NO storageState and
 * NO cookies, so cpp's correct 401/403 is actually exercised. `ignoreHTTPSErrors`
 * mirrors the project config so the self-signed cpp cert is accepted when a spec
 * points straight at :8443. Caller must `await ctx.dispose()`.
 */
export async function unauthContext(baseURL?: string): Promise<APIRequestContext> {
  return pwRequest.newContext({
    baseURL: baseURL ?? process.env.E2E_API_BASE ?? undefined,
    ignoreHTTPSErrors: true,
    // Force an explicitly EMPTY jar. Omitting storageState is not always enough:
    // if the config's project-level storageState leaks in, cpp sees a session
    // cookie and returns 403 (missing-CSRF) instead of the intended 401. An
    // explicit empty state guarantees a truly anonymous request.
    storageState: { cookies: [], origins: [] },
  });
}
