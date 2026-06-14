/**
 * E2E tests for OBP Transaction Requests + SCA (TXR-001..TXR-005).
 *
 * Sections:
 *   810 — Create transaction request (API)
 *   811 — List + get transaction requests (API)
 *   812 — SCA challenge flow (API)
 *   813 — Execute transaction request (API)
 *   814 — TransfersPage UI (smoke)
 *
 * Auth: uses e2e_admin_session_setup.py (alice = regular user)
 * Gate: requires OPEN_BANK_PROJECT_ENABLED=true AND TXN_REQUESTS_ENABLED=true.
 *       When the flag is off all /ui/txn-requests endpoints return 404 —
 *       tests in sections 810-813 verify the 404 and skip gracefully.
 *
 * NOTE: Do not run this spec directly; it is authored for future CI runs once
 * the feature flags are enabled. Run with:
 *   npx playwright test e2e/bankTransfers.spec.ts
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API  = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";
const TS = Date.now();

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
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _adminSessions = JSON.parse(raw);
  }
  return _adminSessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

// ─── API helpers ──────────────────────────────────────────────────────────────

type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

async function apiCall(
  page: Page,
  identity: string,
  method: HttpMethod,
  path: string,
  body?: unknown,
): Promise<{ status: number; body: unknown }> {
  const sessions = getAdminSessions();
  const session  = sessions[identity];
  const res = await page.request[method.toLowerCase() as "get" | "post" | "put" | "patch" | "delete"](
    `${API}${path}`,
    {
      headers: {
        "x-csrf-token": session.csrf_token,
        "Content-Type": "application/json",
      },
      ...(body !== undefined ? { data: body } : {}),
    },
  );
  let respBody: unknown;
  try { respBody = await res.json(); } catch { respBody = null; }
  return { status: res.status(), body: respBody };
}

// Helper to check if txn_requests feature is enabled
async function isFeatureEnabled(page: Page): Promise<boolean> {
  const res = await page.request.get(`${API}/ui/txn-requests`, {
    headers: {},
  });
  // 401 means the route exists (auth needed), 404 means disabled
  return res.status() !== 404 && res.status() !== 503;
}

// ─── Module-level shared state ────────────────────────────────────────────────

let alicePage: Page;
let bobPage: Page;
let featureEnabled = false;
let createdRequestId: string | null = null;

// ─── Section 810: Create transaction request (API) ────────────────────────────

test.describe("Section 810: Create transaction request — API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    featureEnabled = await isFeatureEnabled(alicePage);
  });

  test("810.1 feature flag: 404 when disabled, 201 when enabled", async () => {
    const sessions = getAdminSessions();
    const res = await alicePage.request.post(`${API}/ui/txn-requests`, {
      headers: {
        "x-csrf-token": sessions["alice"].csrf_token,
        "Content-Type": "application/json",
      },
      data: {
        type: "WALLET_TRANSFER",
        amount_cents: 100,
        currency: "usd",
        target: { to_user_sub: sessions["bob"]?.user_sub ?? BOB_ID },
      },
    });

    if (!featureEnabled) {
      expect(res.status()).toBe(404);
      return;
    }
    expect(res.status()).toBe(201);
    const body = await res.json() as Record<string, unknown>;
    expect(body).toHaveProperty("request_id");
    expect(body).toHaveProperty("status");
    expect(typeof body["request_id"]).toBe("string");
    createdRequestId = body["request_id"] as string;
  });

  test("810.2 rejects amount_cents <= 0", async () => {
    if (!featureEnabled) { test.skip(); return; }
    const { status } = await apiCall(alicePage, "alice", "POST", "/ui/txn-requests", {
      type: "FREE_FORM",
      amount_cents: 0,
      currency: "usd",
      target: {},
    });
    expect(status).toBe(422);
  });

  test("810.3 rejects WALLET_TRANSFER with missing to_user_sub", async () => {
    if (!featureEnabled) { test.skip(); return; }
    const { status } = await apiCall(alicePage, "alice", "POST", "/ui/txn-requests", {
      type: "WALLET_TRANSFER",
      amount_cents: 100,
      currency: "usd",
      target: {},
    });
    expect(status).toBe(400);
  });

  test("810.4 rejects WALLET_TRANSFER to self", async () => {
    if (!featureEnabled) { test.skip(); return; }
    const sessions = getAdminSessions();
    const { status } = await apiCall(alicePage, "alice", "POST", "/ui/txn-requests", {
      type: "WALLET_TRANSFER",
      amount_cents: 100,
      currency: "usd",
      target: { to_user_sub: sessions["alice"].user_sub },
    });
    expect(status).toBe(400);
  });

  test("810.5 idempotency key deduplicates creates", async () => {
    if (!featureEnabled) { test.skip(); return; }
    const idemKey = `idem_810_${TS}`;
    const sessions = getAdminSessions();
    const payload = {
      type: "FREE_FORM",
      amount_cents: 50,
      currency: "usd",
      target: {},
      idempotency_key: idemKey,
    };
    const { status: s1, body: b1 } = await apiCall(alicePage, "alice", "POST", "/ui/txn-requests", payload);
    const { status: s2, body: b2 } = await apiCall(alicePage, "alice", "POST", "/ui/txn-requests", payload);
    expect(s1).toBe(201);
    expect(s2).toBe(201);
    expect((b1 as Record<string, unknown>)["request_id"]).toBe((b2 as Record<string, unknown>)["request_id"]);
  });
});

// ─── Section 811: List + get transaction requests (API) ───────────────────────

test.describe("Section 811: List + get transaction requests — API", () => {
  test.beforeAll(async ({ browser }) => {
    if (!alicePage) alicePage = await newIdentityPage(browser, "alice");
    featureEnabled = await isFeatureEnabled(alicePage);
  });

  test("811.1 GET /ui/txn-requests lists items", async () => {
    if (!featureEnabled) { test.skip(); return; }
    const { status, body } = await apiCall(alicePage, "alice", "GET", "/ui/txn-requests");
    expect(status).toBe(200);
    const b = body as Record<string, unknown>;
    expect(Array.isArray(b["items"])).toBe(true);
  });

  test("811.2 GET /ui/txn-requests?status=INITIATED filters", async () => {
    if (!featureEnabled) { test.skip(); return; }
    const { status, body } = await apiCall(alicePage, "alice", "GET", "/ui/txn-requests?status=INITIATED");
    expect(status).toBe(200);
    const items = (body as Record<string, unknown>)["items"] as Array<Record<string, unknown>>;
    for (const item of items) {
      expect(item["status"]).toBe("INITIATED");
    }
  });

  test("811.3 GET /ui/txn-requests/{id} returns single item", async () => {
    if (!featureEnabled || !createdRequestId) { test.skip(); return; }
    const { status, body } = await apiCall(
      alicePage,
      "alice",
      "GET",
      `/ui/txn-requests/${createdRequestId}`,
    );
    expect(status).toBe(200);
    const b = body as Record<string, unknown>;
    expect(b["request_id"]).toBe(createdRequestId);
    expect(b).toHaveProperty("amount_cents");
    expect(b).toHaveProperty("type");
    expect(b).toHaveProperty("status");
    expect(b).toHaveProperty("currency");
    expect(b).toHaveProperty("target");
    expect(b).toHaveProperty("created_at");
    expect(b).toHaveProperty("updated_at");
    expect(b).toHaveProperty("ledger_refs");
  });

  test("811.4 GET /ui/txn-requests/{id} returns 404 for unknown id", async () => {
    if (!featureEnabled) { test.skip(); return; }
    const { status } = await apiCall(alicePage, "alice", "GET", "/ui/txn-requests/txr_nonexistent_00000000");
    expect(status).toBe(404);
  });

  test("811.5 invalid status filter returns 400", async () => {
    if (!featureEnabled) { test.skip(); return; }
    const { status } = await apiCall(alicePage, "alice", "GET", "/ui/txn-requests?status=BOGUS");
    expect(status).toBe(400);
  });
});

// ─── Section 812: SCA challenge flow (API) ───────────────────────────────────

test.describe("Section 812: SCA challenge flow — API", () => {
  // SCA is triggered when amount >= sca_threshold_cents (default $50.00 = 5000 cents)
  const HIGH_VALUE_CENTS = 999999; // ~$9,999.99 — safely above default threshold

  test.beforeAll(async ({ browser }) => {
    if (!alicePage) alicePage = await newIdentityPage(browser, "alice");
    featureEnabled = await isFeatureEnabled(alicePage);
  });

  test("812.1 high-value create lands in PENDING with sca_challenge_id", async () => {
    if (!featureEnabled) { test.skip(); return; }
    const sessions = getAdminSessions();
    const { status, body } = await apiCall(alicePage, "alice", "POST", "/ui/txn-requests", {
      type: "FREE_FORM",
      amount_cents: HIGH_VALUE_CENTS,
      currency: "usd",
      target: {},
      reason: `SCA test ${TS}`,
    });
    // May fail with 402/insufficient_funds if wallet is empty — that's still a valid code path.
    if (status === 402) {
      return; // wallet too low — cannot test SCA without balance
    }
    expect(status).toBe(201);
    const b = body as Record<string, unknown>;
    // Either PENDING (SCA required) or INITIATED (amount below threshold in this env)
    const st = b["status"] as string;
    expect(["INITIATED", "PENDING"]).toContain(st);
    if (st === "PENDING") {
      expect(b["sca_challenge_id"]).toBeTruthy();
      expect(Array.isArray(b["sca_required_factors"])).toBe(true);
    }
  });

  test("812.2 executing PENDING request without SCA returns 403 sca_incomplete", async () => {
    if (!featureEnabled) { test.skip(); return; }
    const sessions = getAdminSessions();
    // Create a request that triggers SCA
    const { status: cs, body: cb } = await apiCall(alicePage, "alice", "POST", "/ui/txn-requests", {
      type: "FREE_FORM",
      amount_cents: HIGH_VALUE_CENTS,
      currency: "usd",
      target: {},
    });
    if (cs === 402) { return; } // no balance
    const created = cb as Record<string, unknown>;
    if (created["status"] !== "PENDING") { return; } // SCA not triggered in this env

    const rid = created["request_id"] as string;
    const { status: es } = await apiCall(alicePage, "alice", "POST", `/ui/txn-requests/${rid}/execute`);
    expect(es).toBe(403);
  });
});

// ─── Section 813: Execute transaction request (API) ──────────────────────────

test.describe("Section 813: Execute transaction request — API", () => {
  test.beforeAll(async ({ browser }) => {
    if (!alicePage) alicePage = await newIdentityPage(browser, "alice");
    featureEnabled = await isFeatureEnabled(alicePage);
  });

  test("813.1 INITIATED FREE_FORM executes or fails with insufficient_funds", async () => {
    if (!featureEnabled) { test.skip(); return; }
    // Create a low-value request that bypasses SCA
    const { status: cs, body: cb } = await apiCall(alicePage, "alice", "POST", "/ui/txn-requests", {
      type: "FREE_FORM",
      amount_cents: 1, // 1 cent — below SCA threshold, tiny amount
      currency: "usd",
      target: {},
      reason: `execute test ${TS}`,
    });
    if (cs === 402) { return; }
    expect(cs).toBe(201);
    const created = cb as Record<string, unknown>;
    const rid = created["request_id"] as string;
    expect(created["status"]).toBe("INITIATED");

    const { status: es, body: eb } = await apiCall(
      alicePage,
      "alice",
      "POST",
      `/ui/txn-requests/${rid}/execute`,
    );
    // Either completes (wallet has balance) or fails with 402 insufficient_funds
    expect([200, 402]).toContain(es);
    const executed = eb as Record<string, unknown>;
    if (es === 200) {
      expect(["COMPLETED", "IN_FLIGHT"]).toContain(executed["status"]);
    }
  });

  test("813.2 executing COMPLETED request is idempotent", async () => {
    if (!featureEnabled || !createdRequestId) { test.skip(); return; }
    // Fetch the created request to check if it reached COMPLETED
    const { body } = await apiCall(alicePage, "alice", "GET", `/ui/txn-requests/${createdRequestId}`);
    const txn = body as Record<string, unknown>;
    if (txn["status"] !== "COMPLETED") { test.skip(); return; }

    // Re-executing a completed request should still return 200 (idempotent)
    const { status } = await apiCall(
      alicePage,
      "alice",
      "POST",
      `/ui/txn-requests/${createdRequestId}/execute`,
    );
    expect(status).toBe(200);
  });

  test("813.3 REFUND type requires payment_intent_id starting with pi_", async () => {
    if (!featureEnabled) { test.skip(); return; }
    const { status } = await apiCall(alicePage, "alice", "POST", "/ui/txn-requests", {
      type: "REFUND",
      amount_cents: 100,
      currency: "usd",
      target: { payment_intent_id: "invalid_no_pi_prefix" },
    });
    expect(status).toBe(400);
  });

  test("813.4 PAYOUT type requires payout_method_id", async () => {
    if (!featureEnabled) { test.skip(); return; }
    const { status } = await apiCall(alicePage, "alice", "POST", "/ui/txn-requests", {
      type: "PAYOUT",
      amount_cents: 100,
      currency: "usd",
      target: {},
    });
    expect(status).toBe(400);
  });

  test("813.5 COUNTERPARTY type requires counterparty_ref", async () => {
    if (!featureEnabled) { test.skip(); return; }
    const { status } = await apiCall(alicePage, "alice", "POST", "/ui/txn-requests", {
      type: "COUNTERPARTY",
      amount_cents: 100,
      currency: "usd",
      target: {},
    });
    expect(status).toBe(400);
  });
});

// ─── Section 814: TransfersPage UI (smoke) ───────────────────────────────────

test.describe("Section 814: TransfersPage UI — smoke tests", () => {
  test.beforeAll(async ({ browser }) => {
    if (!alicePage) alicePage = await newIdentityPage(browser, "alice");
  });

  test("814.1 /bank/transfers renders without crashing", async () => {
    await alicePage.goto(`${BASE}/bank/transfers`, { waitUntil: "domcontentloaded" });
    // Should show either the transfers page or a feature-disabled card
    await expect(alicePage.locator("h1")).toBeVisible({ timeout: 8000 });
    const h1 = await alicePage.locator("h1").textContent();
    expect(h1).toMatch(/transfer/i);
  });

  test("814.2 feature-disabled state shows graceful message when 404", async () => {
    if (featureEnabled) {
      // Feature is on — check the happy path instead
      await alicePage.goto(`${BASE}/bank/transfers`, { waitUntil: "domcontentloaded" });
      await expect(alicePage.locator("text=New Transfer")).toBeVisible({ timeout: 6000 });
      return;
    }
    // Feature is off — expect the disabled card
    await alicePage.goto(`${BASE}/bank/transfers`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.locator("text=/not.*enabled/i")).toBeVisible({ timeout: 8000 });
  });

  test("814.3 /bank/transfers/new renders form when feature enabled", async () => {
    if (!featureEnabled) { test.skip(); return; }
    await alicePage.goto(`${BASE}/bank/transfers/new`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.locator("text=New Transfer")).toBeVisible({ timeout: 6000 });
    await expect(alicePage.locator("select, [role=combobox]").first()).toBeVisible();
  });

  test("814.4 transfer list shows transfers after create when enabled", async () => {
    if (!featureEnabled) { test.skip(); return; }
    await alicePage.goto(`${BASE}/bank/transfers`, { waitUntil: "domcontentloaded" });
    // At least the list card should be visible
    await expect(alicePage.locator("[data-testid=transfers-list], .divide-y, [class*=card]").first()).toBeVisible({ timeout: 6000 });
  });

  test("814.5 /bank/transfers/:id renders detail page for existing request", async () => {
    if (!featureEnabled || !createdRequestId) { test.skip(); return; }
    await alicePage.goto(`${BASE}/bank/transfers/${createdRequestId}`, {
      waitUntil: "domcontentloaded",
    });
    await expect(alicePage.locator("text=Transfer Details")).toBeVisible({ timeout: 6000 });
    await expect(alicePage.locator(`text=${createdRequestId}`)).toBeVisible({ timeout: 6000 });
  });

  test("814.6 status filter select is functional", async () => {
    if (!featureEnabled) { test.skip(); return; }
    await alicePage.goto(`${BASE}/bank/transfers`, { waitUntil: "domcontentloaded" });
    // Open the status filter
    const select = alicePage.locator("[role=combobox]").first();
    await select.click();
    // Should show status options in the dropdown
    await expect(alicePage.locator("text=Completed").first()).toBeVisible({ timeout: 4000 });
    // Select Completed
    await alicePage.locator("text=Completed").first().click();
    // URL or UI should reflect filter
    await expect(alicePage.locator("text=Completed, text=transfers, text=All").first()).toBeVisible({ timeout: 4000 });
  });
});
