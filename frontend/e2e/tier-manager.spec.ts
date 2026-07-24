/**
 * E2E tests for BILLING-003: Subscription Tier Editor (Creator-facing).
 *
 * Sections:
 *   1 — Plan CRUD (API + UI)
 *   2 — Discount Code Management (API + UI)
 *   3 — Navigation
 *
 * Auth: Subscription server uses X-User-Id header (require_user).
 * Test user: Alice (e2e_alice@test.local) — acts as creator.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ───────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();

// ─── Session bootstrap ──────────────────────────────────────────

interface SessionData {
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
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

// ─── Auth helpers ────────────────────────────────────────────────

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

async function newIdentityPage(browser: Browser, userId: string): Promise<Page> {
  const page = await browser.newPage();
  await injectAuth(page, userId);
  return page;
}

// ─── Subscription API helpers (X-User-Id header auth) ────────────

async function subPost(page: Page, userId: string, path: string, body?: object) {
  return page.request.post(`${API}${path}`, {
    data: body ?? {},
    headers: { "X-User-Id": userId },
  });
}

async function subGet(page: Page, userId: string, path: string) {
  return page.request.get(`${API}${path}`, {
    headers: { "X-User-Id": userId },
  });
}

async function subPatch(page: Page, userId: string, path: string, body: object) {
  return page.request.patch(`${API}${path}`, {
    data: body,
    headers: { "X-User-Id": userId },
  });
}

// ─────────────────────────────────────────────────────────────────
// Section 1: Plan CRUD (API + UI)
// ─────────────────────────────────────────────────────────────────

test.describe("Section 1: Plan CRUD", () => {
  let alicePage: Page;
  let planId: string;
  const PLAN_NAME = `Tier ${TS}`;
  const PLAN_NAME_EDITED = `Tier ${TS} v2`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("1.1 API: Create plan returns 200 with plan_id", async () => {
    const resp = await subPost(alicePage, ALICE_ID, `/api/creators/${ALICE_ID}/plans`, {
      name: PLAN_NAME,
      description: "E2E test plan",
      price_cents: 999,
      interval: "month",
    });
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.plan_id).toBeTruthy();
    expect(body.name).toBe(PLAN_NAME);
    expect(body.price_cents).toBe(999);
    expect(body.status).toBe("active");
    planId = body.plan_id;
  });

  test("1.2 API: List plans contains created plan", async () => {
    const resp = await alicePage.request.get(`${API}/api/creators/${ALICE_ID}/plans`);
    expect(resp.ok()).toBeTruthy();
    const plans = await resp.json();
    const found = plans.find((p: { plan_id: string }) => p.plan_id === planId);
    expect(found).toBeTruthy();
    expect(found.name).toBe(PLAN_NAME);
  });

  test("1.3 API: Update plan returns 200", async () => {
    const resp = await subPatch(alicePage, ALICE_ID, `/api/plans/${planId}`, {
      name: PLAN_NAME_EDITED,
      price_cents: 1499,
    });
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.name).toBe(PLAN_NAME_EDITED);
    expect(body.price_cents).toBe(1499);
  });

  test("1.4 API: Archive plan returns 200", async () => {
    const resp = await subPost(alicePage, ALICE_ID, `/api/plans/${planId}/archive`);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.status).toBe("archived");
  });

  test("1.5 API: Reactivate archived plan returns 200", async () => {
    const resp = await subPatch(alicePage, ALICE_ID, `/api/plans/${planId}`, {
      status: "active",
    });
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.status).toBe("active");
  });

  test("1.6 UI: Tier Manager page loads with plan list", async () => {
    await alicePage.goto(`${BASE}/subscriptions/manage`);
    await expect(alicePage.getByRole("heading", { name: "Subscription Tiers" })).toBeVisible();
    // The plan we created should be visible
    await expect(alicePage.getByText(PLAN_NAME_EDITED)).toBeVisible();
  });

  test("1.7 UI: Create plan dialog works", async () => {
    const uiPlanName = `UI Plan ${TS}`;
    await alicePage.goto(`${BASE}/subscriptions/manage`);
    await expect(alicePage.getByRole("heading", { name: "Subscription Tiers" })).toBeVisible();

    // Click Create Plan
    await alicePage.getByRole("button", { name: /Create Plan/i }).click();

    // Fill form
    await alicePage.getByLabel("Name").fill(uiPlanName);
    await alicePage.getByLabel("Description").fill("Created via UI test");
    await alicePage.getByLabel("Price (dollars)").fill("19.99");

    // Submit
    await alicePage.getByRole("button", { name: "Create" }).click();

    // Wait for dialog to close and plan to appear
    await expect(alicePage.getByText(uiPlanName)).toBeVisible({ timeout: 10_000 });
  });

  test("1.8 UI: Edit plan dialog opens with pre-filled data", async () => {
    await alicePage.goto(`${BASE}/subscriptions/manage`);
    await expect(alicePage.getByRole("heading", { name: "Subscription Tiers" })).toBeVisible();

    // Find the plan card and click Edit
    const planCard = alicePage.locator(".grid > div").filter({ hasText: PLAN_NAME_EDITED }).first();
    await planCard.getByRole("button", { name: /Edit/i }).click();

    // Verify pre-filled values
    await expect(alicePage.getByLabel("Name")).toHaveValue(PLAN_NAME_EDITED);
    // Close dialog
    await alicePage.getByRole("button", { name: "Cancel" }).click();
  });

  test("1.9 UI: Archive plan via UI shows archived badge", async () => {
    await alicePage.goto(`${BASE}/subscriptions/manage`);
    await expect(alicePage.getByRole("heading", { name: "Subscription Tiers" })).toBeVisible();

    // Find a plan with an Archive button and click it
    const planCard = alicePage.locator(".grid > div").filter({ hasText: PLAN_NAME_EDITED }).first();
    await planCard.getByRole("button", { name: /Archive/i }).click();

    // Confirm the dialog
    await alicePage.getByRole("button", { name: "Archive" }).last().click();

    // Verify archived badge appears
    await expect(planCard.getByText("Archived")).toBeVisible({ timeout: 10_000 });
  });

  test("1.10 UI: Reactivate archived plan via UI", async () => {
    await alicePage.goto(`${BASE}/subscriptions/manage`);
    await expect(alicePage.getByRole("heading", { name: "Subscription Tiers" })).toBeVisible();

    // Find the archived plan and reactivate
    const planCard = alicePage.locator(".grid > div").filter({ hasText: PLAN_NAME_EDITED }).first();
    await planCard.getByRole("button", { name: /Reactivate/i }).click();

    // Verify active badge appears
    await expect(planCard.getByText("Active")).toBeVisible({ timeout: 10_000 });
  });
});

// ─────────────────────────────────────────────────────────────────
// Section 2: Discount Code Management (API + UI)
// ─────────────────────────────────────────────────────────────────

test.describe("Section 2: Discount Code Management", () => {
  let alicePage: Page;
  const CODE_NAME = `E2ECODE${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("2.1 API: Create discount code returns 200", async () => {
    const resp = await subPost(
      alicePage,
      ALICE_ID,
      `/api/creators/${ALICE_ID}/discounts`,
      {
        code: CODE_NAME,
        percent_off: 25,
        duration: "once",
        active: true,
      },
    );
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.code).toBe(CODE_NAME.toUpperCase());
    expect(body.percent_off).toBe(25);
    expect(body.active).toBe(true);
  });

  test("2.2 API: List discount codes contains created code", async () => {
    const resp = await subGet(
      alicePage,
      ALICE_ID,
      `/api/creators/${ALICE_ID}/discounts`,
    );
    expect(resp.ok()).toBeTruthy();
    const codes = await resp.json();
    const found = codes.find((c: { code: string }) => c.code === CODE_NAME.toUpperCase());
    expect(found).toBeTruthy();
    expect(found.percent_off).toBe(25);
  });

  test("2.3 API: Disable discount code returns 200", async () => {
    const resp = await subPost(
      alicePage,
      ALICE_ID,
      `/api/creators/${ALICE_ID}/discounts/${CODE_NAME.toUpperCase()}/disable`,
    );
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.active).toBe(false);
  });

  test("2.4 API: Repeating discount requires duration_months", async () => {
    const resp = await subPost(
      alicePage,
      ALICE_ID,
      `/api/creators/${ALICE_ID}/discounts`,
      {
        code: `REPEAT${TS}`,
        percent_off: 10,
        duration: "repeating",
        // intentionally missing duration_months
      },
    );
    expect(resp.ok()).toBeFalsy();
    expect(resp.status()).toBe(400);
  });

  test("2.5 API: Repeating discount with duration_months succeeds", async () => {
    const resp = await subPost(
      alicePage,
      ALICE_ID,
      `/api/creators/${ALICE_ID}/discounts`,
      {
        code: `RPT${TS}`,
        percent_off: 15,
        duration: "repeating",
        duration_months: 3,
      },
    );
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.duration).toBe("repeating");
    expect(body.duration_months).toBe(3);
  });

  test("2.6 UI: Discount Codes tab shows codes table", async () => {
    await alicePage.goto(`${BASE}/subscriptions/manage`);
    await expect(alicePage.getByRole("heading", { name: "Subscription Tiers" })).toBeVisible();

    // Click Discount Codes tab
    await alicePage.getByRole("tab", { name: "Discount Codes" }).click();

    // Table should be visible with the disabled code
    await expect(alicePage.getByText(CODE_NAME.toUpperCase())).toBeVisible({ timeout: 10_000 });
    // There may be multiple "Disabled" badges from prior runs — use .first()
    await expect(alicePage.getByText("Disabled").first()).toBeVisible();
  });

  test("2.7 UI: Create discount code via form", async () => {
    const uiCode = `UITEST${TS}`;
    await alicePage.goto(`${BASE}/subscriptions/manage`);
    await alicePage.getByRole("tab", { name: "Discount Codes" }).click();

    // Click Create Code
    await alicePage.getByRole("button", { name: /Create Code/i }).click();

    // Fill form — use id-based locator to avoid strict mode violation
    await alicePage.locator("#dc-code").fill(uiCode);
    await alicePage.locator("#dc-pct").fill("30");

    // Submit
    await alicePage.getByRole("button", { name: "Create", exact: true }).click();

    // Verify code appears in table
    await expect(alicePage.getByText(uiCode.toUpperCase())).toBeVisible({ timeout: 10_000 });
  });
});

// ─────────────────────────────────────────────────────────────────
// Section 3: Preview + Navigation
// ─────────────────────────────────────────────────────────────────

test.describe("Section 3: Preview + Navigation", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("3.1 UI: Preview tab shows PlanBrowser", async () => {
    // First ensure there's at least one active plan
    await subPost(alicePage, ALICE_ID, `/api/creators/${ALICE_ID}/plans`, {
      name: `Preview Plan ${TS}`,
      price_cents: 599,
      interval: "month",
    });

    await alicePage.goto(`${BASE}/subscriptions/manage`);
    await alicePage.getByRole("tab", { name: "Preview" }).click();

    // PlanBrowser should show active plans with Subscribe buttons
    await expect(
      alicePage.getByRole("button", { name: /Subscribe/i }).first(),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("3.2 UI: Tier Manager link visible in sidebar", async () => {
    await alicePage.goto(`${BASE}/subscriptions/manage`);
    // Sidebar should contain Tier Manager link (may show i18n key "nav.tierManager" as fallback)
    const sidebarLink = alicePage.locator("a[href='/subscriptions/manage']").first();
    await expect(sidebarLink).toBeVisible();
  });

  test("3.3 UI: Sidebar link navigates to correct page", async () => {
    await alicePage.goto(BASE);
    const sidebarLink = alicePage.locator("a[href='/subscriptions/manage']").first();
    await sidebarLink.click();
    await expect(alicePage).toHaveURL(/\/subscriptions\/manage/);
    await expect(alicePage.getByRole("heading", { name: "Subscription Tiers" })).toBeVisible();
  });
});
