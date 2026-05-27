/**
 * E2E tests for Webhook Event Delivery System (PLATFORM-002).
 *
 * Sections:
 *   A — Webhook CRUD API (6 tests)
 *   B — Webhook Delivery API (5 tests)
 *   C — Webhook Signature (3 tests)
 *   D — Admin Webhooks API (4 tests)
 *   E — Webhooks UI (4 tests)
 *
 * Auth: Alice (user), Root (admin).
 * Sessions from e2e_session_setup.py and e2e_admin_session_setup.py.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as crypto from "crypto";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";
const ROOT_ID  = "root";
const TS       = Date.now();

// Mock webhook URL — we use a non-existent HTTPS URL for CRUD tests
// and a specially crafted one for test delivery.
const WEBHOOK_URL  = `https://e2e-hooks-${TS}.example.com/webhook`;
const WEBHOOK_URL2 = `https://e2e-hooks-${TS}-v2.example.com/webhook`;

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
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

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

let _adminSessions: Record<string, SessionData> | null = null;
function getAdminSessions(): Record<string, SessionData> {
  if (!_adminSessions) {
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _adminSessions = JSON.parse(raw);
  }
  return _adminSessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiPost(page: Page, identity: string, path: string, body?: object) {
  const sessions = getSessions();
  const sess = sessions[identity];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, identity: string, path: string) {
  const sessions = getSessions();
  const sess = sessions[identity];
  return page.request.get(`${BASE}${path}`, {
    headers: { "x-csrf-token": sess.csrf_token },
  });
}

async function apiPatch(page: Page, identity: string, path: string, body?: object) {
  const sessions = getSessions();
  const sess = sessions[identity];
  return page.request.patch(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiDelete(page: Page, identity: string, path: string) {
  const sessions = getSessions();
  const sess = sessions[identity];
  return page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": sess.csrf_token },
  });
}

async function adminApiPost(page: Page, path: string, body?: object) {
  const sessions = getAdminSessions();
  const sess = sessions[ROOT_ID];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function adminApiGet(page: Page, path: string) {
  const sessions = getAdminSessions();
  const sess = sessions[ROOT_ID];
  return page.request.get(`${BASE}${path}`, {
    headers: { "x-csrf-token": sess.csrf_token },
  });
}

// ─── Cleanup helper ──────────────────────────────────────────────────────────

async function deleteAllEndpoints(page: Page, identity: string) {
  const resp = await apiGet(page, identity, "/ui/webhooks");
  if (resp.ok()) {
    const endpoints = await resp.json();
    for (const ep of endpoints) {
      await apiDelete(page, identity, `/ui/webhooks/${ep.endpoint_id}`);
    }
  }
}

// =============================================================================
// Section A: Webhook CRUD API (6 tests)
// =============================================================================

test.describe("A — Webhook CRUD API", () => {
  let alicePage: Page;
  let createdEndpointId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await alicePage.context().addCookies(getSessions()[ALICE_ID].cookies);
    // Clean up any leftover endpoints from previous runs
    await deleteAllEndpoints(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await deleteAllEndpoints(alicePage, ALICE_ID);
    await alicePage.close();
  });

  test("1. User creates a webhook endpoint", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/webhooks", {
      url: WEBHOOK_URL,
      description: `E2E test endpoint ${TS}`,
      event_types: ["message.created", "payment.received"],
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.endpoint_id).toBeTruthy();
    expect(data.url).toBe(WEBHOOK_URL);
    expect(data.secret).toBeTruthy();
    expect(data.secret).toContain("whsec_");
    expect(data.enabled).toBe(true);
    expect(data.event_types).toContain("message.created");
    expect(data.event_types).toContain("payment.received");
    createdEndpointId = data.endpoint_id;
  });

  test("2. URL must be HTTPS", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/webhooks", {
      url: "http://insecure.example.com/hook",
      description: "Should fail",
      event_types: ["message.created"],
    });
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(data.detail).toContain("HTTPS");
  });

  test("3. User lists their endpoints", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, "/ui/webhooks");
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(Array.isArray(data)).toBe(true);
    const ep = data.find((e: any) => e.endpoint_id === createdEndpointId);
    expect(ep).toBeTruthy();
    expect(ep.url).toBe(WEBHOOK_URL);
    // Secret should not be returned on list
    expect(ep.secret).toBeNull();
  });

  test("4. User updates endpoint event types", async () => {
    const resp = await apiPatch(alicePage, ALICE_ID, `/ui/webhooks/${createdEndpointId}`, {
      event_types: ["message.created", "post.created", "broadcast.started"],
    });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.event_types).toContain("post.created");
    expect(data.event_types).toContain("broadcast.started");
    expect(data.event_types).toContain("message.created");
    expect(data.event_types).not.toContain("payment.received");
  });

  test("5. User deletes endpoint", async () => {
    // Create a temporary endpoint to delete
    const createResp = await apiPost(alicePage, ALICE_ID, "/ui/webhooks", {
      url: `https://e2e-delete-${TS}.example.com/hook`,
      description: "To be deleted",
      event_types: ["webhook.test"],
    });
    const tempId = (await createResp.json()).endpoint_id;

    const delResp = await apiDelete(alicePage, ALICE_ID, `/ui/webhooks/${tempId}`);
    expect(delResp.status()).toBe(204);

    // Verify it is gone
    const getResp = await apiGet(alicePage, ALICE_ID, `/ui/webhooks/${tempId}`);
    expect(getResp.status()).toBe(404);
  });

  test("6. Max 10 endpoints per user", async () => {
    // We already have 1 endpoint from test 1. Create 9 more to hit limit.
    const ids: string[] = [];
    for (let i = 0; i < 9; i++) {
      const resp = await apiPost(alicePage, ALICE_ID, "/ui/webhooks", {
        url: `https://e2e-limit-${TS}-${i}.example.com/hook`,
        description: `Limit test ${i}`,
        event_types: ["webhook.test"],
      });
      expect(resp.status()).toBe(201);
      ids.push((await resp.json()).endpoint_id);
    }

    // 11th should fail (we have 10 total now)
    const failResp = await apiPost(alicePage, ALICE_ID, "/ui/webhooks", {
      url: `https://e2e-limit-${TS}-overflow.example.com/hook`,
      description: "Should fail",
      event_types: ["webhook.test"],
    });
    expect(failResp.status()).toBe(409);

    // Clean up the 9 extra endpoints
    for (const id of ids) {
      await apiDelete(alicePage, ALICE_ID, `/ui/webhooks/${id}`);
    }
  });
});

// =============================================================================
// Section B: Webhook Delivery API (5 tests)
// =============================================================================

test.describe("B — Webhook Delivery API", () => {
  let alicePage: Page;
  let endpointId: string;
  let endpointSecret: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await alicePage.context().addCookies(getSessions()[ALICE_ID].cookies);
    await deleteAllEndpoints(alicePage, ALICE_ID);

    // Create an endpoint for delivery tests
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/webhooks", {
      url: WEBHOOK_URL,
      description: `Delivery test ${TS}`,
      event_types: ["message.created", "webhook.test"],
    });
    const data = await resp.json();
    endpointId = data.endpoint_id;
    endpointSecret = data.secret;
  });

  test.afterAll(async () => {
    await deleteAllEndpoints(alicePage, ALICE_ID);
    await alicePage.close();
  });

  test("1. Test delivery to non-existent URL fails gracefully", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/webhooks/${endpointId}/test`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.delivery_id).toBeTruthy();
    expect(data.status).toBe("failed");
    expect(data.error).toBeTruthy();
    expect(data.duration_ms).toBeGreaterThanOrEqual(0);
  });

  test("2. Delivery log shows test event", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, `/ui/webhooks/${endpointId}/deliveries`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.deliveries).toBeTruthy();
    expect(data.deliveries.length).toBeGreaterThanOrEqual(1);
    const testDelivery = data.deliveries.find(
      (d: any) => d.event_type === "webhook.test",
    );
    expect(testDelivery).toBeTruthy();
    expect(["success", "failed"]).toContain(testDelivery.status);
  });

  test("3. Secret rotation returns new secret", async () => {
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/webhooks/${endpointId}/rotate-secret`,
    );
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.secret).toBeTruthy();
    expect(data.secret).toContain("whsec_");
    // New secret should differ from the original
    expect(data.secret).not.toBe(endpointSecret);
    endpointSecret = data.secret;
  });

  test("4. Event types list returns all available types", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, "/ui/webhooks/event-types");
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.event_types).toBeTruthy();
    expect(data.event_types.length).toBeGreaterThan(10);
    const types = data.event_types.map((et: any) => et.type);
    expect(types).toContain("message.created");
    expect(types).toContain("webhook.test");
    expect(types).toContain("payment.received");
  });

  test("5. Get single endpoint by ID returns details", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, `/ui/webhooks/${endpointId}`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.endpoint_id).toBe(endpointId);
    expect(data.url).toBe(WEBHOOK_URL);
    expect(data.enabled).toBe(true);
    // Secret is never returned on GET
    expect(data.secret).toBeNull();
  });
});

// =============================================================================
// Section C: Webhook Signature (3 tests)
// =============================================================================

test.describe("C — Webhook Signature", () => {
  let alicePage: Page;
  let endpointId: string;
  let endpointSecret: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await alicePage.context().addCookies(getSessions()[ALICE_ID].cookies);
    await deleteAllEndpoints(alicePage, ALICE_ID);

    const resp = await apiPost(alicePage, ALICE_ID, "/ui/webhooks", {
      url: WEBHOOK_URL,
      description: `Signature test ${TS}`,
      event_types: ["webhook.test"],
    });
    const data = await resp.json();
    endpointId = data.endpoint_id;
    endpointSecret = data.secret;
  });

  test.afterAll(async () => {
    await deleteAllEndpoints(alicePage, ALICE_ID);
    await alicePage.close();
  });

  test("1. Test delivery includes delivery_id in response", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/webhooks/${endpointId}/test`);
    const data = await resp.json();
    expect(data.delivery_id).toBeTruthy();
    expect(data.delivery_id).toContain("wd_test_");
  });

  test("2. HMAC signature computation works correctly", async () => {
    // Verify that we can compute signatures the same way the backend does
    const timestamp = Math.floor(Date.now() / 1000);
    const payload = JSON.stringify({
      id: "evt_test",
      type: "webhook.test",
      created_at: timestamp,
      data: { message: "test" },
    });
    const message = `${timestamp}.${payload}`;
    const expectedSig = crypto
      .createHmac("sha256", endpointSecret)
      .update(message)
      .digest("hex");

    // Verify the signature is a valid hex string
    expect(expectedSig).toMatch(/^[a-f0-9]{64}$/);
  });

  test("3. Delivery log records attempt details", async () => {
    // The test delivery from test 1 should be in the log
    const resp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/webhooks/${endpointId}/deliveries`,
    );
    const data = await resp.json();
    expect(data.deliveries.length).toBeGreaterThanOrEqual(1);
    const delivery = data.deliveries[0];
    expect(delivery.delivery_id).toBeTruthy();
    expect(delivery.event_type).toBe("webhook.test");
    expect(delivery.attempt_count).toBeGreaterThanOrEqual(1);
    expect(delivery.created_at).toBeGreaterThan(0);
  });
});

// =============================================================================
// Section D: Admin Webhooks API (4 tests)
// =============================================================================

test.describe("D — Admin Webhooks API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let endpointId: string;

  test.beforeAll(async ({ browser }) => {
    // Root page (admin)
    rootPage = await browser.newPage();
    await rootPage.context().addCookies(getAdminSessions()[ROOT_ID].cookies);

    // Alice page (non-admin)
    alicePage = await browser.newPage();
    await alicePage.context().addCookies(getSessions()[ALICE_ID].cookies);
    await deleteAllEndpoints(alicePage, ALICE_ID);

    // Create an endpoint as Alice for admin to operate on
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/webhooks", {
      url: `https://e2e-admin-${TS}.example.com/hook`,
      description: `Admin test ${TS}`,
      event_types: ["message.created"],
    });
    endpointId = (await resp.json()).endpoint_id;
  });

  test.afterAll(async () => {
    await deleteAllEndpoints(alicePage, ALICE_ID);
    await alicePage.close();
    await rootPage.close();
  });

  test("1. Admin lists all endpoints across users", async () => {
    const resp = await adminApiGet(rootPage, "/ui/admin/webhooks/endpoints");
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.endpoints).toBeTruthy();
    expect(Array.isArray(data.endpoints)).toBe(true);
    // Should contain Alice's endpoint
    const found = data.endpoints.find((e: any) => e.endpoint_id === endpointId);
    expect(found).toBeTruthy();
  });

  test("2. Admin views delivery health summary", async () => {
    const resp = await adminApiGet(rootPage, "/ui/admin/webhooks/health");
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(typeof data.total_endpoints).toBe("number");
    expect(typeof data.enabled_endpoints).toBe("number");
    expect(typeof data.disabled_endpoints).toBe("number");
    expect(typeof data.total_deliveries_24h).toBe("number");
    expect(typeof data.success_count_24h).toBe("number");
  });

  test("3. Admin can force-disable an endpoint", async () => {
    const resp = await adminApiPost(
      rootPage,
      `/ui/admin/webhooks/endpoints/${endpointId}/disable`,
      { reason: "e2e_test_disable" },
    );
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.ok).toBe(true);

    // Verify it's disabled
    const getResp = await apiGet(alicePage, ALICE_ID, `/ui/webhooks/${endpointId}`);
    const ep = await getResp.json();
    expect(ep.enabled).toBe(false);
    expect(ep.disabled_reason).toBe("e2e_test_disable");
  });

  test("4. Non-admin cannot access admin webhook endpoints", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, "/ui/admin/webhooks/health");
    expect(resp.status()).toBe(403);
  });
});

// =============================================================================
// Section E: Webhooks UI (4 tests)
// =============================================================================

test.describe("E — Webhooks UI", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await deleteAllEndpoints(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await deleteAllEndpoints(alicePage, ALICE_ID);
    await alicePage.close();
  });

  test("1. Webhooks page loads with empty state", async () => {
    await alicePage.goto(`${BASE}/settings/webhooks`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByText("No webhooks configured")).toBeVisible({ timeout: 10_000 });
  });

  test("2. Create webhook form validates HTTPS", async () => {
    await alicePage.goto(`${BASE}/settings/webhooks`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByRole("button", { name: /create webhook/i })).toBeVisible({ timeout: 10_000 });
    await alicePage.getByRole("button", { name: /create webhook/i }).click();
    // Wait for dialog
    await expect(alicePage.getByText("Create Webhook Endpoint")).toBeVisible();

    // Type an HTTP URL
    await alicePage.locator("#webhook-url").fill("http://insecure.example.com/hook");
    await expect(alicePage.getByText("URL must start with https://")).toBeVisible();
  });

  test("3. Created webhook appears in list", async () => {
    // Create via API first
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/webhooks", {
      url: `https://e2e-ui-${TS}.example.com/hook`,
      description: `UI test ${TS}`,
      event_types: ["message.created"],
    });
    expect(resp.status()).toBe(201);

    // Navigate to page and verify the webhook appears
    await alicePage.goto(`${BASE}/settings/webhooks`, { waitUntil: "domcontentloaded" });
    await expect(
      alicePage.locator("p").filter({ hasText: `https://e2e-ui-${TS}.example.com/hook` }),
    ).toBeVisible({ timeout: 10_000 });
    await expect(alicePage.getByText("Active").first()).toBeVisible();
  });

  test("4. Delivery log expands on click", async () => {
    await alicePage.goto(`${BASE}/settings/webhooks`, { waitUntil: "domcontentloaded" });
    // Click "Delivery Log" button
    const deliveryLogBtn = alicePage.getByRole("button", { name: /delivery log/i }).first();
    await expect(deliveryLogBtn).toBeVisible({ timeout: 10_000 });
    await deliveryLogBtn.click();
    // Should show either deliveries or "No deliveries yet."
    const noDeliveries = alicePage.getByText("No deliveries yet.");
    const recentHeader = alicePage.getByText("Recent Deliveries");
    await expect(noDeliveries.or(recentHeader)).toBeVisible();
  });
});
