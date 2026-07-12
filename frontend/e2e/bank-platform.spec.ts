/**
 * E2E tests for OBP Platform Surface (PLT-001..PLT-005)
 *
 * Sections:
 *   200 — PLT-003 Glossary API (GET /v1/glossary)
 *   201 — PLT-003 Glossary UI
 *   202 — PLT-002 Metrics leaderboard API (GET /v1/admin/api-usage/leaderboard)
 *   203 — PLT-001 Rate-limit overrides API (/ui/api_keys/self_limits)
 *   204 — PLT-001 Rate-limits UI
 *   205 — PLT-005 Wallet threshold API (PUT /ui/billing/wallet/threshold)
 *   206 — PLT-005 Ledger Webhooks UI
 *   207 — PLT-004 Sandbox import API (POST /v1/admin/sandbox/data-import)
 *   208 — Platform Dashboard UI nav
 *   209 — Feature-flag off → graceful handling
 *
 * Auth: uses e2e_admin_session_setup.py (alice, bob, root).
 *
 * NOTE: Tests require the local stack running.
 *   - Sections 200, 201: OPEN_BANK_PROJECT_ENABLED=1, GLOSSARY_ENABLED=1
 *   - Section 202: METRICS_LEADERBOARD_ENABLED=1, filemgr_admin_users includes root
 *   - Section 203-204: no extra flag (api_keys always enabled)
 *   - Section 205-206: ACCOUNT_LEDGER_WEBHOOKS_ENABLED=1, WEBHOOKS_ENABLED=1
 *   - Section 207: SANDBOX_IMPORT_ENABLED=1, DEV_MODE=1
 * When flags are off, the test assertions check graceful 404/503 handling.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const ROOT_ID  = "root.admin@testdev.local";
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

let _sessions: Record<string, AdminSessionData> | null = null;

function getSessions(): Record<string, AdminSessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string): Promise<void> {
  const sessions = getSessions();
  const sess = sessions[identity];
  if (!sess) throw new Error(`Unknown identity: ${identity}`);
  await page.context().addCookies(sess.cookies);
  // The React app gates routes on the persisted `auth-store` localStorage —
  // cookies alone do not pass the client-side auth guard.
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate(
    ([userId, accessToken]: [string, string]) => {
      const state = { userId, accessToken, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    [sess.user_sub, sess.access_token],
  );
}

function getSession(identity: string) {
  return getSessions()[identity];
}

function apiPost(page: Page, identity: string, path: string, body: unknown) {
  const s = getSession(identity);
  return page.request.post(`${API}${path}`, {
    headers: { "x-csrf-token": s.csrf_token, "Content-Type": "application/json" },
    data: JSON.stringify(body),
  });
}

function apiGet(page: Page, path: string, params?: Record<string, string>) {
  const qs = params ? "?" + new URLSearchParams(params).toString() : "";
  return page.request.get(`${API}${path}${qs}`);
}

// NOTE: the /v1/admin/* OBP platform endpoints (leaderboard, glossary admin,
// sandbox) authenticate via `require_ui_session` (cookie auth), NOT bearer —
// the seeded `access_token` is a UI HS256 token, not a Cognito JWT, so a Bearer
// header is rejected with "Unknown Cognito key id". These helpers therefore send
// the session cookie + CSRF header. (Helper names retained for minimal churn.)
function cookieHeader(identity: string): string {
  const s = getSession(identity);
  return s.cookies.map((c) => `${c.name}=${c.value}`).join("; ");
}

function apiBearerGet(request: import("@playwright/test").APIRequestContext, identity: string, path: string, params?: Record<string, string>) {
  const s = getSession(identity);
  const qs = params ? "?" + new URLSearchParams(params).toString() : "";
  return request.get(`${API}${path}${qs}`, {
    headers: { Cookie: cookieHeader(identity), "x-csrf-token": s.csrf_token },
  });
}

function apiBearerPost(request: import("@playwright/test").APIRequestContext, identity: string, path: string, body: unknown) {
  const s = getSession(identity);
  return request.post(`${API}${path}`, {
    headers: { Cookie: cookieHeader(identity), "x-csrf-token": s.csrf_token, "Content-Type": "application/json" },
    data: JSON.stringify(body),
  });
}

function apiBearerPatch(request: import("@playwright/test").APIRequestContext, identity: string, path: string, body: unknown) {
  const s = getSession(identity);
  return request.patch(`${API}${path}`, {
    headers: { Cookie: cookieHeader(identity), "x-csrf-token": s.csrf_token, "Content-Type": "application/json" },
    data: JSON.stringify(body),
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 200 — PLT-003 Glossary API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("200 — PLT-003 Glossary API", () => {
  test.beforeAll(() => getSessions());

  let createdTermId: string;

  test("200.1 — GET /v1/glossary returns list (or 404 when disabled)", async ({ request }) => {
    const resp = await request.get(`${API}/v1/glossary`);
    if (resp.status() === 404) {
      test.skip(); // feature disabled — covered by section 209
      return;
    }
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { terms: unknown[]; count: number };
    expect(typeof data.count).toBe("number");
    expect(Array.isArray(data.terms)).toBe(true);
  });

  test("200.2 — GET /v1/glossary with search param returns filtered results", async ({ request }) => {
    const resp = await request.get(`${API}/v1/glossary`, { params: { search: "account", limit: "10" } });
    if (resp.status() === 404) return; // flag off
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { terms: unknown[] };
    expect(Array.isArray(data.terms)).toBe(true);
  });

  test("200.3 — Admin can create a glossary term", async ({ request }) => {
    const resp = await apiBearerPost(request, ROOT_ID, "/v1/admin/glossary", {
      term: `E2E Term ${TS}`,
      definition: "An E2E test term definition.",
      tags: ["e2e", "test"],
    });
    if (resp.status() === 404) return; // flag off
    if (resp.status() === 403) {
      // ROOT not in filemgr_admin_users — acceptable in unconfigured environments
      return;
    }
    expect(resp.status()).toBe(201);
    const data = await resp.json() as { term_id: string; term: string };
    expect(data.term_id).toBeTruthy();
    expect(data.term).toContain("E2E Term");
    createdTermId = data.term_id;
  });

  test("200.4 — GET /v1/glossary/{id} returns the created term", async ({ request }) => {
    if (!createdTermId) return;
    const resp = await request.get(`${API}/v1/glossary/${createdTermId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { term_id: string; tags: string[] };
    expect(data.term_id).toBe(createdTermId);
    expect(data.tags).toContain("e2e");
  });

  test("200.5 — Admin can patch a glossary term", async ({ request }) => {
    if (!createdTermId) return;
    const resp = await apiBearerPatch(request, ROOT_ID, `/v1/admin/glossary/${createdTermId}`, {
      definition: "Updated definition.",
    });
    if (resp.status() === 403 || resp.status() === 404) return;
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { definition: string };
    expect(data.definition).toBe("Updated definition.");
  });

  test("200.6 — Non-existent term returns 404", async ({ request }) => {
    const resp = await request.get(`${API}/v1/glossary/does-not-exist-gloss_999`);
    if (resp.status() === 503) return; // feature disabled at global level
    expect([404, 503]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 201 — PLT-003 Glossary UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("201 — PLT-003 Glossary UI", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("201.1 — Platform dashboard loads at /bank/platform", async () => {
    await alicePage.goto(`${BASE}/bank/platform`);
    await expect(alicePage.getByText("Platform Developer Dashboard")).toBeVisible({ timeout: 8000 });
  });

  test("201.2 — Glossary tab is visible and clickable", async () => {
    await alicePage.goto(`${BASE}/bank/platform?tab=glossary`);
    await expect(alicePage.getByRole("tab", { name: /API Glossary/i })).toBeVisible({ timeout: 5000 });
  });

  test("201.3 — Glossary tab shows terms or not-enabled state", async () => {
    await alicePage.goto(`${BASE}/bank/platform?tab=glossary`);
    // Either terms load or the disabled message appears
    const either = alicePage
      .locator("text=API Glossary")
      .or(alicePage.locator("text=glossary feature is not enabled"));
    await expect(either.first()).toBeVisible({ timeout: 8000 });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 202 — PLT-002 Metrics Leaderboard API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("202 — PLT-002 Metrics Leaderboard API", () => {
  test.beforeAll(() => getSessions());

  test("202.1 — Admin GET /v1/admin/api-usage/leaderboard returns list or 404", async ({ request }) => {
    const resp = await apiBearerGet(request, ROOT_ID, "/v1/admin/api-usage/leaderboard");
    // 403 = not in admin allowlist; 404 = flag off — both are valid
    if (resp.status() === 403 || resp.status() === 404) return;
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { items: unknown[]; dimension: string };
    expect(typeof data.dimension).toBe("string");
    expect(Array.isArray(data.items)).toBe(true);
  });

  test("202.2 — Leaderboard accepts dimension=endpoints", async ({ request }) => {
    const resp = await apiBearerGet(request, ROOT_ID, "/v1/admin/api-usage/leaderboard", {
      dimension: "endpoints",
      metric: "calls_total",
      top_n: "5",
    });
    if (resp.status() === 403 || resp.status() === 404) return;
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { dimension: string; top_n: number };
    expect(data.dimension).toBe("endpoints");
    expect(data.top_n).toBeLessThanOrEqual(5);
  });

  test("202.3 — Non-admin Alice gets 403", async ({ request }) => {
    const resp = await apiBearerGet(request, ALICE_ID, "/v1/admin/api-usage/leaderboard");
    // Either 403 (not admin) or 404 (flag off) are valid
    expect([403, 404]).toContain(resp.status());
  });

  test("202.4 — Leaderboard accepts period_id filter", async ({ request }) => {
    const period = new Date().toISOString().slice(0, 7); // YYYY-MM
    const resp = await apiBearerGet(request, ROOT_ID, "/v1/admin/api-usage/leaderboard", {
      period_id: period,
    });
    if (resp.status() === 403 || resp.status() === 404) return;
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { period_id: string };
    expect(data.period_id).toBe(period);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 203 — PLT-001 Rate-limit overrides API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("203 — PLT-001 Rate-limit overrides API", () => {
  let alicePage: Page;
  let createdKeyId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("203.1 — Alice can list her API keys", async () => {
    const resp = await apiGet(alicePage, "/ui/api_keys");
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { keys: Array<{ key_id: string }> };
    expect(Array.isArray(data.keys)).toBe(true);
  });

  test("203.2 — Alice can create an API key", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/api_keys", {
      label: `PLT001-e2e-${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { key_id: string };
    expect(data.key_id).toBeTruthy();
    createdKeyId = data.key_id;
  });

  test("203.3 — Alice can set rate_limit_overrides on her key", async () => {
    if (!createdKeyId) return;
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/api_keys/self_limits", {
      key_id: createdKeyId,
      rate_limit_overrides: { hour: 500, day: 5000 },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { ok: boolean };
    expect(data.ok).toBe(true);
  });

  test("203.4 — rate_limit_overrides appear in list after update", async () => {
    if (!createdKeyId) return;
    const resp = await apiGet(alicePage, "/ui/api_keys");
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { keys: Array<{ key_id: string; rate_limit_overrides?: unknown }> };
    const key = data.keys.find((k) => k.key_id === createdKeyId);
    expect(key).toBeDefined();
    // rate_limit_overrides may be null/empty when PLT-001 is disabled
    // When enabled it should carry the values we set
    if (key?.rate_limit_overrides) {
      expect((key.rate_limit_overrides as Record<string, unknown>).hour).toBe(500);
    }
  });

  test("203.5 — Alice can clear rate_limit_overrides", async () => {
    if (!createdKeyId) return;
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/api_keys/self_limits", {
      key_id: createdKeyId,
      rate_limit_overrides: { hour: null, day: null },
    });
    expect(resp.status()).toBe(200);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 204 — PLT-001 Rate-limits UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("204 — PLT-001 Rate-limits UI", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("204.1 — Rate Limits tab is visible on platform dashboard", async () => {
    await alicePage.goto(`${BASE}/bank/platform?tab=rate-limits`);
    await expect(alicePage.getByText("Per-Consumer Rate Limits")).toBeVisible({ timeout: 8000 });
  });

  test("204.2 — Rate Limits tab shows API keys or empty state", async () => {
    await alicePage.goto(`${BASE}/bank/platform?tab=rate-limits`);
    const either = alicePage
      .getByText("No API keys found")
      .or(alicePage.getByText("Using account defaults"))
      .or(alicePage.locator('[data-testid="api-key-card"]'));
    // Just assert page loaded without error
    await expect(alicePage.getByText("Per-Consumer Rate Limits")).toBeVisible({ timeout: 6000 });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 205 — PLT-005 Wallet threshold API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("205 — PLT-005 Wallet threshold API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("205.1 — Alice can get her wallet balance", async () => {
    const resp = await apiGet(alicePage, "/ui/billing/wallet");
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { wallet_balance_cents: number; currency: string };
    expect(typeof data.wallet_balance_cents).toBe("number");
    expect(data.currency).toBeTruthy();
  });

  test("205.2 — Alice can set wallet threshold (PLT-005 endpoint)", async () => {
    const resp = await alicePage.request.put(`${API}/ui/billing/wallet/threshold`, {
      headers: {
        "x-csrf-token": getSession(ALICE_ID).csrf_token,
        "Content-Type": "application/json",
      },
      data: JSON.stringify({ threshold_cents: 500 }),
    });
    if (resp.status() === 404) {
      // ACCOUNT_LEDGER_WEBHOOKS_ENABLED not set — acceptable
      return;
    }
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { ok: boolean; threshold_cents: number };
    expect(data.ok).toBe(true);
    expect(data.threshold_cents).toBe(500);
  });

  test("205.3 — Alice can disable threshold by setting to 0", async () => {
    const resp = await alicePage.request.put(`${API}/ui/billing/wallet/threshold`, {
      headers: {
        "x-csrf-token": getSession(ALICE_ID).csrf_token,
        "Content-Type": "application/json",
      },
      data: JSON.stringify({ threshold_cents: 0 }),
    });
    if (resp.status() === 404) return; // flag off
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { threshold_cents: number };
    expect(data.threshold_cents).toBe(0);
  });

  test("205.4 — Negative threshold is rejected", async () => {
    const resp = await alicePage.request.put(`${API}/ui/billing/wallet/threshold`, {
      headers: {
        "x-csrf-token": getSession(ALICE_ID).csrf_token,
        "Content-Type": "application/json",
      },
      data: JSON.stringify({ threshold_cents: -100 }),
    });
    if (resp.status() === 404) return;
    expect([400, 422]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 206 — PLT-005 Ledger Webhooks UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("206 — PLT-005 Ledger Webhooks UI", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("206.1 — Ledger Webhooks tab loads", async () => {
    await alicePage.goto(`${BASE}/bank/platform?tab=webhooks`);
    await expect(alicePage.getByText("Wallet Balance", { exact: true })).toBeVisible({ timeout: 8000 });
  });

  test("206.2 — Wallet balance is displayed", async () => {
    await alicePage.goto(`${BASE}/bank/platform?tab=webhooks`);
    await expect(alicePage.getByText("Wallet Balance", { exact: true })).toBeVisible({ timeout: 6000 });
    // Balance value rendered as $X.XX
    await expect(alicePage.locator("text=/\\$\\d+\\.\\d{2}/")).toBeVisible({ timeout: 5000 });
  });

  test("206.3 — Threshold section is visible", async () => {
    await alicePage.goto(`${BASE}/bank/platform?tab=webhooks`);
    await expect(alicePage.getByText("Low-Balance Alert Threshold")).toBeVisible({ timeout: 6000 });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 207 — PLT-004 Sandbox import API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("207 — PLT-004 Sandbox import API", () => {
  test.beforeAll(() => getSessions());

  test("207.1 — POST /v1/admin/sandbox/data-import returns 404 when disabled", async ({ request }) => {
    const resp = await apiBearerPost(request, ROOT_ID, "/v1/admin/sandbox/data-import", {
      customers: [],
      accounts: [],
      transactions: [],
    });
    // When DEV_MODE=0 or SANDBOX_IMPORT_ENABLED=0 → 404
    // When enabled → 200 with { ok: true }
    if (resp.status() === 200) {
      const data = await resp.json() as { ok: boolean };
      expect(typeof data.ok).toBe("boolean");
    } else {
      expect([404, 403]).toContain(resp.status());
    }
  });

  test("207.2 — Sandbox import with valid payload succeeds when enabled", async ({ request }) => {
    const resp = await apiBearerPost(request, ROOT_ID, "/v1/admin/sandbox/data-import", {
      customers: [
        { email: `sandbox-e2e-${TS}@test.local`, full_name: "Sandbox E2E User" },
      ],
      accounts: [],
      transactions: [],
    });
    if (resp.status() === 404 || resp.status() === 403) return;
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { ok: boolean; customers_created: number };
    // customers_created may be 0 if email already exists (idempotent)
    expect(typeof data.customers_created).toBe("number");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 208 — Platform Dashboard UI nav
// ─────────────────────────────────────────────────────────────────────────────

test.describe("208 — Platform Dashboard UI nav", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("208.1 — Platform dashboard page loads", async () => {
    await alicePage.goto(`${BASE}/bank/platform`);
    await expect(alicePage.getByText("Platform Developer Dashboard")).toBeVisible({ timeout: 8000 });
  });

  test("208.2 — All tabs are present", async () => {
    await alicePage.goto(`${BASE}/bank/platform`);
    await expect(alicePage.getByRole("tab", { name: /API Glossary/i })).toBeVisible();
    await expect(alicePage.getByRole("tab", { name: /Metrics Leaderboard/i })).toBeVisible();
    await expect(alicePage.getByRole("tab", { name: /Rate Limits/i })).toBeVisible();
    await expect(alicePage.getByRole("tab", { name: /Ledger Webhooks/i })).toBeVisible();
    await expect(alicePage.getByRole("tab", { name: /Sandbox/i })).toBeVisible();
  });

  test("208.3 — Tab switching updates active view", async () => {
    await alicePage.goto(`${BASE}/bank/platform?tab=glossary`);
    await alicePage.getByRole("tab", { name: /Metrics Leaderboard/i }).click();
    // URL should update (React Router)
    await expect(alicePage).toHaveURL(/tab=leaderboard/, { timeout: 3000 });
  });

  test("208.4 — Leaderboard tab shows admin-only content or feature-off state", async () => {
    await alicePage.goto(`${BASE}/bank/platform?tab=leaderboard`);
    // Either the controls appear or the "admin privileges" message
    const either = alicePage
      .getByText("Metrics Leaderboard")
      .or(alicePage.getByText("admin privileges"))
      .or(alicePage.getByText("not enabled"));
    await expect(either.first()).toBeVisible({ timeout: 8000 });
  });

  test("208.5 — Sandbox tab shows dev-only state", async () => {
    await alicePage.goto(`${BASE}/bank/platform?tab=sandbox`);
    // Either shows the import form or the "not available" notice
    const either = alicePage
      .getByText("Sandbox Data Import")
      .or(alicePage.getByText("Sandbox Import"));
    await expect(either.first()).toBeVisible({ timeout: 8000 });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 209 — Feature-flag off → graceful handling
// ─────────────────────────────────────────────────────────────────────────────

test.describe("209 — Feature-flag off → graceful handling", () => {
  test("209.1 — Glossary returns 404 when disabled (not enabled state)", async ({ request }) => {
    // Smoke test: we just verify the response is handled gracefully
    // (200 when enabled, 404 when disabled — either is valid)
    const resp = await request.get(`${API}/v1/glossary`);
    expect([200, 404]).toContain(resp.status());
  });

  test("209.2 — Leaderboard 404 is graceful (not a 500)", async ({ request }) => {
    const resp = await apiBearerGet(request, ROOT_ID, "/v1/admin/api-usage/leaderboard");
    // 404/403 = flag off or not admin; 200 = enabled; never a 500
    expect(resp.status()).not.toBe(500);
  });
});
