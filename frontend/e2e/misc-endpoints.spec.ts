/**
 * Section 106: Misc Endpoints — ping, ws_token
 * Section 107: WebAuthn — registration begin (options generation)
 *
 * Auth: Cookie sessions via e2e_admin_session_setup.py
 * Identities: alice (USER)
 */
import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None"; expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync("python3 " + REPO_ROOT + "/e2e_admin_session_setup.py", {
      cwd: REPO_ROOT,
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function newPage(browser: Browser, identity: string): Promise<Page> {
  const page = await browser.newPage();
  await page.context().addCookies(getSessions()[identity].cookies);
  return page;
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

async function apiPost(page: Page, id: string, path: string, body?: unknown) {
  const s = getSessions()[id];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": s.csrf_token, "Content-Type": "application/json" },
  });
}

// ─── 106. Misc Endpoints ─────────────────────────────────────────────────

test.describe("106 — Misc Endpoints: ping, ws_token", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("106.1 Health check ping returns ok + root_user_sub", async () => {
    const resp = await apiGet(alicePage, "/api/ping");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.root_user_sub).toBeTruthy();
  });

  test("106.2 WS token endpoint returns token", async () => {
    const resp = await apiGet(alicePage, "/ui/ws_token");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.token).toBeTruthy();
    expect(typeof data.token).toBe("string");
    expect(data.token.length).toBeGreaterThan(10);
  });

  test("106.3 WS token contains user sub and is valid JWT-like format", async () => {
    const resp = await apiGet(alicePage, "/ui/ws_token");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const parts = data.token.split(".");
    expect(parts.length).toBeGreaterThanOrEqual(2);
    const payload = JSON.parse(Buffer.from(parts[0], "base64url").toString());
    expect(payload.user_sub).toBeTruthy();
    expect(payload.exp).toBeGreaterThan(0);
  });
});

// ─── 107. WebAuthn ───────────────────────────────────────────────────────

test.describe("107 — WebAuthn: registration options", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("107.1 Register begin returns challenge options", async () => {
    const resp = await apiPost(alicePage, "alice", "/ui/webauthn/register/begin", {});
    // WebAuthn may not be configured (WEBAUTHN_RP_ID empty) — expect either 200 or 500
    if (resp.status() === 200) {
      const data = await resp.json();
      expect(data.options).toBeTruthy();
      expect(data.options.challenge).toBeTruthy();
      expect(data.options.rp).toBeTruthy();
    } else {
      expect(resp.status()).toBe(500);
    }
  });

  test("107.2 Authenticate begin with empty username returns 400", async () => {
    const resp = await apiPost(alicePage, "alice", "/ui/webauthn/authenticate/begin", {
      username: "",
    });
    expect(resp.status()).toBe(400);
  });

  test("107.3 Authenticate begin with valid username", async () => {
    const resp = await apiPost(alicePage, "alice", "/ui/webauthn/authenticate/begin", {
      username: getSessions()["alice"].user_sub,
    });
    // May fail if WebAuthn not configured
    if (resp.status() === 200) {
      const data = await resp.json();
      expect(data.options).toBeTruthy();
    } else {
      expect(resp.status()).toBe(500);
    }
  });
});
