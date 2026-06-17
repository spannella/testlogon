/**
 * E2E tests for OAU-001..OAU-005: OAuth2/OIDC Consumer App Registry.
 *
 * Sections:
 *   70 — Consumer CRUD — API (list, create, get, update, delete)
 *   71 — Enable / disable — API
 *   72 — Secret rotation — API
 *   73 — Authorization server endpoints (OIDC discovery, JWKS) — API
 *   74 — OAuthClientsPage UI
 *   75 — OAuthClientDetailPage UI
 *
 * Auth: uses e2e_admin_session_setup.py (alice = regular user, root = admin).
 *
 * NOTE: All endpoints are gated on OPEN_BANK_PROJECT_ENABLED=true AND
 * OAUTH_PROVIDER_ENABLED=1. If either flag is off the tests in sections
 * 70-73 will receive 404/503 and gracefully skip assertions.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";
const TS       = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface AdminSessionData {
  user_sub:     string;
  session_id:   string;
  csrf_token:   string;
  access_token: string;
  cookies: Array<{
    name:     string;
    value:    string;
    domain:   string;
    path:     string;
    httpOnly: boolean;
    secure:   boolean;
    sameSite: "Lax" | "Strict" | "None";
    expires:  number;
  }>;
}

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _adminSessions = JSON.parse(raw);
  }
  return _adminSessions!;
}

// ─── Page factory ─────────────────────────────────────────────────────────────

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

// ─── Auth inject for UI tests ─────────────────────────────────────────────────

async function injectAuth(page: Page, identity: string): Promise<void> {
  const session = getAdminSessions()[identity];
  if (!session) throw new Error(`No session for identity: ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate(
    ([userId, accessToken]: [string, string]) => {
      const state = { userId, accessToken, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    [session.user_sub, session.access_token],
  );
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

async function apiPatch(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.patch(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getAdminSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

// ─── Flag-aware helper ────────────────────────────────────────────────────────

/** Returns true when the OBP OAuth feature flags are off (404/503). */
function flagsOff(status: number): boolean {
  return status === 404 || status === 503;
}

// ─── Module-level state shared across sections ────────────────────────────────

let aliceClientId = "";
let aliceClientSecret = "";

// ─────────────────────────────────────────────────────────────────────────────
// Section 70 — Consumer CRUD — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 70: Consumer CRUD — API", () => {
  let alicePage: Page;
  let bobPage:   Page;
  const APP_NAME = `E2E OAuth App ${TS}`;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    alicePage = await newIdentityPage(browser, "alice");
    bobPage   = await newIdentityPage(browser, "bob");
  });

  test("70.1 List consumers — empty or array", async () => {
    const resp = await apiGet(alicePage, "ui/oauth/consumers");
    if (flagsOff(resp.status())) {
      console.log("Section 70: flags off — skipping");
      return;
    }
    expect(resp.status()).toBe(200);
    const data = await resp.json() as unknown[];
    expect(Array.isArray(data)).toBe(true);
  });

  test("70.2 Create consumer → 200, returns client_id + one-time secret", async () => {
    const resp = await apiPost(alicePage, "alice", "ui/oauth/consumers", {
      name: APP_NAME,
      description: "E2E test consumer",
      redirect_uris: ["https://example.com/cb"],
      allowed_scopes: ["openid", "profile", "email"],
      is_confidential: true,
    });
    if (flagsOff(resp.status())) return;
    expect(resp.status()).toBe(200);
    const data = await resp.json() as {
      client_id: string;
      client_secret: string;
      client_secret_prefix: string;
      name: string;
      created_at: number;
    };
    expect(typeof data.client_id).toBe("string");
    expect(data.client_id.length).toBeGreaterThan(0);
    expect(data.client_secret).toMatch(/^oc_/);
    expect(data.name).toBe(APP_NAME);
    aliceClientId     = data.client_id;
    aliceClientSecret = data.client_secret;
  });

  test("70.3 Get consumer by client_id → 200, fields present", async () => {
    if (!aliceClientId) return;
    const resp = await apiGet(alicePage, `ui/oauth/consumers/${aliceClientId}`);
    if (flagsOff(resp.status())) return;
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Record<string, unknown>;
    expect(data.client_id).toBe(aliceClientId);
    expect(data.enabled).toBe(true);
    expect(Array.isArray(data.redirect_uris)).toBe(true);
    expect(Array.isArray(data.allowed_scopes)).toBe(true);
    // client_secret_hash must NOT be exposed
    expect(data.client_secret_hash).toBeUndefined();
  });

  test("70.4 Get consumer — another user returns 404", async () => {
    if (!aliceClientId) return;
    const resp = await apiGet(bobPage, `ui/oauth/consumers/${aliceClientId}`);
    if (flagsOff(resp.status())) return;
    expect(resp.status()).toBe(404);
  });

  test("70.5 List after create — includes new consumer", async () => {
    if (!aliceClientId) return;
    const resp = await apiGet(alicePage, "ui/oauth/consumers");
    if (flagsOff(resp.status())) return;
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Array<{ client_id: string }>;
    const found = data.find((c) => c.client_id === aliceClientId);
    expect(found).toBeTruthy();
  });

  test("70.6 PATCH consumer — update name + description", async () => {
    if (!aliceClientId) return;
    const resp = await apiPatch(alicePage, "alice", `ui/oauth/consumers/${aliceClientId}`, {
      name: `${APP_NAME} updated`,
      description: "Updated E2E description",
    });
    if (flagsOff(resp.status())) return;
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Record<string, unknown>;
    expect(data.name).toBe(`${APP_NAME} updated`);
    expect(data.description).toBe("Updated E2E description");
  });

  test("70.7 PATCH by non-owner → 404", async () => {
    if (!aliceClientId) return;
    const resp = await apiPatch(bobPage, "bob", `ui/oauth/consumers/${aliceClientId}`, {
      name: "hacked",
    });
    if (flagsOff(resp.status())) return;
    expect(resp.status()).toBe(404);
  });

  test("70.8 PATCH with invalid redirect_uri → 400", async () => {
    if (!aliceClientId) return;
    const resp = await apiPatch(alicePage, "alice", `ui/oauth/consumers/${aliceClientId}`, {
      redirect_uris: ["not-a-url"],
    });
    if (flagsOff(resp.status())) return;
    expect([400, 422]).toContain(resp.status());
  });

  test("70.9 Create with fragment in redirect_uri → 400", async () => {
    const resp = await apiPost(alicePage, "alice", "ui/oauth/consumers", {
      name: "Fragment test",
      redirect_uris: ["https://example.com/cb#fragment"],
      allowed_scopes: ["openid"],
    });
    if (flagsOff(resp.status())) return;
    expect([400, 422]).toContain(resp.status());
  });

  test("70.10 Create with unknown scope → 400", async () => {
    const resp = await apiPost(alicePage, "alice", "ui/oauth/consumers", {
      name: "Bad scope test",
      redirect_uris: ["https://example.com/cb"],
      allowed_scopes: ["nonexistent_scope_xyz"],
    });
    if (flagsOff(resp.status())) return;
    expect([400, 422]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 71 — Enable / disable — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 71: Enable / disable — API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test("71.1 Disable consumer → enabled=false", async () => {
    if (!aliceClientId) return;
    const resp = await apiPost(alicePage, "alice", `ui/oauth/consumers/${aliceClientId}/disable`);
    if (flagsOff(resp.status())) return;
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Record<string, unknown>;
    expect(data.enabled).toBe(false);
  });

  test("71.2 Get after disable → enabled=false", async () => {
    if (!aliceClientId) return;
    const resp = await apiGet(alicePage, `ui/oauth/consumers/${aliceClientId}`);
    if (flagsOff(resp.status())) return;
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Record<string, unknown>;
    expect(data.enabled).toBe(false);
  });

  test("71.3 Re-enable consumer → enabled=true", async () => {
    if (!aliceClientId) return;
    const resp = await apiPost(alicePage, "alice", `ui/oauth/consumers/${aliceClientId}/enable`);
    if (flagsOff(resp.status())) return;
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Record<string, unknown>;
    expect(data.enabled).toBe(true);
  });

  test("71.4 Enable non-existent consumer → 404", async () => {
    const resp = await apiPost(alicePage, "alice", "ui/oauth/consumers/nonexistent_id_xyz/enable");
    if (flagsOff(resp.status())) return;
    expect(resp.status()).toBe(404);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 72 — Secret rotation — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 72: Secret rotation — API", () => {
  let alicePage: Page;
  let bobPage:   Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    bobPage   = await newIdentityPage(browser, "bob");
  });

  test("72.1 Rotate secret → returns new client_secret (oc_ prefix)", async () => {
    if (!aliceClientId) return;
    const resp = await apiPost(alicePage, "alice", `ui/oauth/consumers/${aliceClientId}/rotate-secret`);
    if (flagsOff(resp.status())) return;
    expect(resp.status()).toBe(200);
    const data = await resp.json() as {
      client_id: string;
      client_secret: string;
      client_secret_prefix: string;
      secret_rotated_at: number;
    };
    expect(data.client_id).toBe(aliceClientId);
    expect(data.client_secret).toMatch(/^oc_/);
    expect(data.client_secret).not.toBe(aliceClientSecret);
    expect(data.secret_rotated_at).toBeGreaterThan(0);
  });

  test("72.2 Rotate by non-owner → 404", async () => {
    if (!aliceClientId) return;
    const resp = await apiPost(bobPage, "bob", `ui/oauth/consumers/${aliceClientId}/rotate-secret`);
    if (flagsOff(resp.status())) return;
    expect(resp.status()).toBe(404);
  });

  test("72.3 secret_rotated_at updated after rotation", async () => {
    if (!aliceClientId) return;
    const beforeTs = Math.floor(Date.now() / 1000) - 5;
    const resp = await apiPost(alicePage, "alice", `ui/oauth/consumers/${aliceClientId}/rotate-secret`);
    if (flagsOff(resp.status())) return;
    const data = await resp.json() as { secret_rotated_at: number };
    expect(data.secret_rotated_at).toBeGreaterThan(beforeTs);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 73 — Authorization server endpoints — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 73: Authorization server endpoints — API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test("73.1 OIDC discovery — /.well-known/openid-configuration", async () => {
    const resp = await alicePage.request.get(`${API}/.well-known/openid-configuration`);
    // May 404 if OIDC not enabled — both cases acceptable
    if (flagsOff(resp.status())) return;
    if (resp.status() !== 200) return; // oidc_enabled may be off
    const doc = await resp.json() as Record<string, unknown>;
    expect(typeof doc.issuer).toBe("string");
    expect(typeof doc.authorization_endpoint).toBe("string");
    expect(typeof doc.token_endpoint).toBe("string");
    expect(typeof doc.jwks_uri).toBe("string");
    expect(Array.isArray(doc.response_types_supported)).toBe(true);
    expect(Array.isArray(doc.grant_types_supported)).toBe(true);
    expect(Array.isArray(doc.scopes_supported)).toBe(true);
  });

  test("73.2 JWKS — /oauth/jwks", async () => {
    const resp = await alicePage.request.get(`${API}/oauth/jwks`);
    if (flagsOff(resp.status())) return;
    if (resp.status() !== 200) return;
    const doc = await resp.json() as Record<string, unknown>;
    expect(Array.isArray(doc.keys)).toBe(true);
  });

  test("73.3 /oauth/authorize with unknown client_id → 400", async () => {
    const resp = await alicePage.request.get(`${API}/oauth/authorize`, {
      params: {
        response_type: "code",
        client_id: "nonexistent_client_xyz",
        redirect_uri: "https://example.com/cb",
        scope: "openid",
        state: "test",
        code_challenge: "abc",
        code_challenge_method: "S256",
      },
    });
    if (flagsOff(resp.status())) return;
    expect([400, 302]).toContain(resp.status());
  });

  test("73.4 /oauth/token with missing grant_type → 422", async () => {
    const resp = await alicePage.request.post(`${API}/oauth/token`, {
      form: { client_id: "test" },
    });
    if (flagsOff(resp.status())) return;
    expect([400, 422]).toContain(resp.status());
  });

  test("73.5 /oauth/token with unsupported grant_type → 400", async () => {
    const resp = await alicePage.request.post(`${API}/oauth/token`, {
      form: { grant_type: "implicit", client_id: "test" },
    });
    if (flagsOff(resp.status())) return;
    expect(resp.status()).toBe(400);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 74 — OAuthClientsPage UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 74: OAuthClientsPage UI", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, "alice");
  });

  test("74.1 Navigates to /bank/oauth-clients", async () => {
    await alicePage.goto(`${BASE}/bank/oauth-clients`, { waitUntil: "domcontentloaded" });
    // Either the real page or the feature-off message
    const heading = alicePage.getByRole("heading", { name: "OAuth2/OIDC Apps", exact: true });
    await expect(heading).toBeVisible({ timeout: 10_000 });
  });

  test("74.2 Page shows 'Register App' button or feature-off state", async () => {
    const registerBtn = alicePage.getByRole("button", { name: /register app/i });
    const featureOff  = alicePage.getByText(/not enabled/i);
    const either = registerBtn.or(featureOff);
    await expect(either).toBeVisible({ timeout: 8_000 });
  });

  test("74.3 Authorization Server card shows discovery URL", async () => {
    // Only present when flags are on
    const discoveryUrl = alicePage.getByText(/openid-configuration/i);
    // If not present (flags off), skip gracefully
    const featureOff = alicePage.getByText(/not enabled/i);
    const either = discoveryUrl.or(featureOff);
    await expect(either).toBeVisible({ timeout: 8_000 });
  });

  test("74.4 Register App dialog opens on button click", async () => {
    const registerBtn = alicePage.getByRole("button", { name: /register app/i }).first();
    const isDisabled = await registerBtn.count() === 0;
    if (isDisabled) {
      console.log("Section 74.4: Register App button not present — flags off, skipping");
      return;
    }
    await registerBtn.click();
    const dialog = alicePage.getByRole("dialog");
    await expect(dialog).toBeVisible({ timeout: 5_000 });
    const dialogTitle = dialog.getByText(/register oauth app/i);
    await expect(dialogTitle).toBeVisible();
    // Close
    await alicePage.keyboard.press("Escape");
    await expect(dialog).not.toBeVisible({ timeout: 3_000 });
  });

  test("74.5 Empty state shown when no apps (or list shown)", async () => {
    // Either shows list of apps or the empty-state prompt
    const noApps  = alicePage.getByText(/no apps registered yet/i);
    const listRow  = alicePage.locator(".rounded-lg.border").first();
    const featureOff = alicePage.getByText(/not enabled/i);
    // At least one of these three must be visible
    const countNoApps    = await noApps.count();
    const countListRow   = await listRow.count();
    const countFeatureOff = await featureOff.count();
    expect(countNoApps + countListRow + countFeatureOff).toBeGreaterThan(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 75 — OAuthClientDetailPage UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 75: OAuthClientDetailPage UI", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, "alice");
  });

  test("75.1 Direct nav to /bank/oauth-clients/:id with unknown id shows 404 state", async () => {
    await alicePage.goto(`${BASE}/bank/oauth-clients/nonexistent_id_xyz`, {
      waitUntil: "domcontentloaded",
    });
    // May show "not found" or the feature-off state
    const notFound   = alicePage.getByText(/not found|not enabled/i);
    await expect(notFound).toBeVisible({ timeout: 10_000 });
  });

  test("75.2 If app exists in list, clicking detail link navigates to detail page", async () => {
    await alicePage.goto(`${BASE}/bank/oauth-clients`, { waitUntil: "domcontentloaded" });

    // If there are any listed apps, click the first chevron link
    const chevronLink = alicePage.getByTitle("View / edit").first();
    const hasChevron = (await chevronLink.count()) > 0;
    if (!hasChevron) {
      console.log("Section 75.2: No apps listed — skipping navigation sub-test");
      return;
    }

    await chevronLink.click();
    // URL should now include /bank/oauth-clients/
    await alicePage.waitForURL(/\/bank\/oauth-clients\/.+/, { timeout: 5_000 });
    const backBtn = alicePage.getByRole("button", { name: /back/i });
    await expect(backBtn).toBeVisible();
  });

  test("75.3 Back button navigates to list page", async () => {
    // Already on detail page (or list) from 75.2
    const backBtn = alicePage.getByRole("button", { name: /back/i }).first();
    const hasBtnBack = (await backBtn.count()) > 0;
    if (!hasBtnBack) return;
    await backBtn.click();
    await alicePage.waitForURL(/\/bank\/oauth-clients$/, { timeout: 5_000 });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Cleanup — delete the test consumer
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Cleanup", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test("Cleanup: delete test consumer if created", async () => {
    if (!aliceClientId) return;
    const resp = await apiDelete(alicePage, "alice", `ui/oauth/consumers/${aliceClientId}`);
    if (flagsOff(resp.status())) return;
    expect([200, 404]).toContain(resp.status());
  });
});
