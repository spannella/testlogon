/**
 * Shared E2E session helpers.
 *
 * Provides cookie-based auth injection for the admin/role test identities
 * (root, alice, bob, charlie_admin, charlie_scoped, compliance_admin) seeded by
 * `e2e_admin_session_setup.py`. This module was referenced by several specs
 * (connection-profiles, post-hide) but had never been created; it implements the
 * canonical pattern used inline by the rest of the suite.
 */
import { execSync } from "child_process";
import type { Page } from "@playwright/test";

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

export function loadSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
    // The script prints human-readable "Created session ..." lines before the JSON.
    const start = raw.indexOf("{");
    if (start < 0) throw new Error("e2e_admin_session_setup.py produced no JSON");
    _sessions = JSON.parse(raw.slice(start)) as Record<string, SessionData>;
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
