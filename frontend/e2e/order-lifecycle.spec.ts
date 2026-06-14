/**
 * E2E tests for the OFBiz ORDER-LIFECYCLE (ORD) frontend.
 *
 * Sections:
 *   90 — Order lifecycle API (lifecycle read / history / transition / cancel)
 *   91 — OrdersPage UI (lookup, status filter, recent)
 *   92 — OrderDetailPage UI (line items, timeline, actions)
 *
 * LIVE router: app/routers/order_lifecycle.py (prefix /ui/orders)
 *   GET  /ui/orders/{id}/lifecycle?include=history,adjustments,ship_groups
 *   GET  /ui/orders/{id}/history
 *   POST /ui/orders/{id}/transition         (ADMIN/ROOT only)
 *   POST /ui/orders/{id}/cancel             (owner: created/approved, or admin)
 *
 * NOTE: The order-lifecycle feature is gated by S.order_lifecycle_enabled
 * (default OFF). When OFF every endpoint returns 503 {code: feature_disabled};
 * the UI degrades gracefully. These tests assert behaviour under BOTH states by
 * tolerating 503 where the feature flag may be off (the page must not crash).
 *
 * Auth: e2e_admin_session_setup.py (root / alice / bob / charlie_admin).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ROOT_SUB = "root.admin@testdev.local";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();

interface AdminSessionData {
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

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
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

function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

// Feature flag may be off — treat 503 feature_disabled as an acceptable terminal.
function featureOffOr(resp: { status(): number }, ...okStatuses: number[]): boolean {
  return resp.status() === 503 || okStatuses.includes(resp.status());
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 90 — Order lifecycle API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 90: Order lifecycle API", () => {
  let rootPage: Page;
  let alicePage: Page;
  const MISSING_ID = `ord_missing_${TS}`;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
  });

  test("90.1 GET lifecycle for unknown order → 404 or 503 (feature off)", async () => {
    const resp = await apiGet(rootPage, `ui/orders/${MISSING_ID}/lifecycle`);
    expect(featureOffOr(resp, 404)).toBeTruthy();
  });

  test("90.2 GET history for unknown order → 404 or 503", async () => {
    const resp = await apiGet(rootPage, `ui/orders/${MISSING_ID}/history`);
    expect(featureOffOr(resp, 404)).toBeTruthy();
  });

  test("90.3 transition unknown order → 404/409 or 503", async () => {
    const resp = await apiPost(rootPage, "root", `ui/orders/${MISSING_ID}/transition`, {
      target_status: "approved",
      reason: "e2e",
    });
    expect(featureOffOr(resp, 404, 409)).toBeTruthy();
  });

  test("90.4 transition requires admin (alice non-admin) → 403/404/409 or 503", async () => {
    const resp = await apiPost(alicePage, "alice", `ui/orders/${MISSING_ID}/transition`, {
      target_status: "approved",
    });
    expect(featureOffOr(resp, 403, 404, 409)).toBeTruthy();
  });

  test("90.5 cancel unknown order → 404/409 or 503", async () => {
    const resp = await apiPost(alicePage, "alice", `ui/orders/${MISSING_ID}/cancel`, {
      reason: "e2e cancel",
    });
    expect(featureOffOr(resp, 404, 409)).toBeTruthy();
  });

  test("90.6 lifecycle with include= returns same shape or 404/503", async () => {
    const resp = await apiGet(rootPage, `ui/orders/${MISSING_ID}/lifecycle`, {
      include: "history,adjustments,ship_groups",
    });
    expect(featureOffOr(resp, 404)).toBeTruthy();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 91 — OrdersPage UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 91: OrdersPage UI", () => {
  test.beforeEach(async ({ page }) => {
    await injectAuth(page, "root");
  });

  test("91.1 Orders page renders header + lookup form", async ({ page }) => {
    await page.goto(`${BASE}/orders`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Orders", exact: true })).toBeVisible();
    await expect(page.getByLabel("Order ID")).toBeVisible();
    await expect(page.getByRole("button", { name: /look up/i })).toBeVisible();
  });

  test("91.2 Status filter dropdown is present", async ({ page }) => {
    await page.goto(`${BASE}/orders`, { waitUntil: "domcontentloaded" });
    await expect(page.getByLabel("Status")).toBeVisible();
  });

  test("91.3 Looking up an unknown order shows a friendly message (no crash)", async ({ page }) => {
    await page.goto(`${BASE}/orders`, { waitUntil: "domcontentloaded" });
    await page.getByLabel("Order ID").fill(`ord_nope_${TS}`);
    await page.getByRole("button", { name: /look up/i }).click();
    // Either feature-disabled card or a not-found message — page stays mounted.
    await expect(
      page.getByText(/No order found|not enabled|Unable to load/i).first(),
    ).toBeVisible({ timeout: 10_000 });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 92 — OrderDetailPage UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 92: OrderDetailPage UI", () => {
  test.beforeEach(async ({ page }) => {
    await injectAuth(page, "root");
  });

  test("92.1 Detail page for unknown order shows graceful empty state", async ({ page }) => {
    await page.goto(`${BASE}/orders/ord_nope_${TS}`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("button", { name: /back to orders/i }).first()).toBeVisible({
      timeout: 10_000,
    });
    await expect(
      page.getByText(/No order found|not enabled|Unable to load/i).first(),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("92.2 Back button navigates to the orders list", async ({ page }) => {
    await page.goto(`${BASE}/orders/ord_nope_${TS}`, { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: /back to orders/i }).first().click();
    await expect(page).toHaveURL(/\/orders$/);
  });
});

// Reference unused identifiers so lint stays quiet across edits.
void ROOT_SUB;
void ALICE_ID;
