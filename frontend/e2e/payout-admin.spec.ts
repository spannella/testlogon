/**
 * E2E tests for GAP-0196 / GAP-0195: Payout Methods management + Admin Queue tab
 * in PayoutDashboard.
 *
 * Section 220: Payout Methods UI (add / list / set-default / delete + request picker)
 * Section 221: Admin Queue tab (role gate, stats, approve, reject-with-reason)
 *
 * Auth: cookie-based sessions via e2e_admin_session_setup.py. The Zustand auth
 * store is seeded with the REAL access_token so getRoleFromAccessToken() can
 * decode the role claim and render the Admin Queue tab for admins/root only.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const API = "http://localhost:8000";
const BASE = "http://localhost:3000";
const ALICE_KEY = "alice";
const CHARLIE_KEY = "charlie_admin";
const TS = Date.now();

// ─── Session bootstrap ──────────────────────────────────────────────────────────

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
  const sess = sessions[identity];
  const page = await browser.newPage();
  await page.context().addCookies(sess.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  // Seed the auth store WITH the real access token so role-aware UI works.
  await page.evaluate(
    ({ uid, token }: { uid: string; token: string }) => {
      const state = {
        userId: uid,
        accessToken: token,
        isAuthenticated: true,
      };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    { uid: sess.user_sub, token: sess.access_token },
  );
  return page;
}

async function apiPost(page: Page, sessionKey: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[sessionKey];
  return page.request.post(`${API}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

// ─── Section 220: Payout Methods UI ──────────────────────────────────────────────

test.describe("Section 220: Payout Methods UI", () => {
  test("220.1 user can add a bank payout method", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE_KEY);
    await page.goto(`${BASE}/payouts`, { waitUntil: "domcontentloaded" });

    await page.getByRole("tab", { name: "Payout Methods" }).click();
    await page.getByTestId("add-method-btn").click();

    // Default type is bank_ach -> account last4 visible
    await page.locator("#pm-acct").fill("4321");
    await page.locator("#pm-routing").fill("8765");
    await page.locator("#pm-nickname").fill(`Main ${TS}`);
    await page.getByTestId("save-method-btn").click();

    await expect(
      page.locator('[data-testid="method-row"]').filter({ hasText: "4321" }),
    ).toBeVisible();
  });

  test("220.2 user can set default and the badge moves", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE_KEY);
    // Ensure at least two methods exist
    await apiPost(page, ALICE_KEY, "/ui/payouts/methods", {
      method_type: "paypal",
      paypal_email: `pp${TS}@test.local`,
      nickname: `PayPal ${TS}`,
    });

    await page.goto(`${BASE}/payouts`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: "Payout Methods" }).click();

    const paypalRow = page
      .locator('[data-testid="method-row"]')
      .filter({ hasText: `pp${TS}@test.local` });
    await expect(paypalRow).toBeVisible();
    await paypalRow.getByRole("button", { name: "Set Default" }).click();

    await expect(paypalRow.getByText("Default")).toBeVisible();
  });

  test("220.3 saved methods appear in the request Destination picker", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE_KEY);
    await apiPost(page, ALICE_KEY, "/ui/payouts/methods", {
      method_type: "bank_ach",
      account_last4: "1111",
      routing_last4: "2222",
      nickname: `Picker ${TS}`,
    });

    await page.goto(`${BASE}/payouts`, { waitUntil: "domcontentloaded" });
    // My Payouts is default tab; open the destination select
    await page.getByTestId("payout-destination-trigger").click();
    await expect(
      page.getByRole("option", { name: /Picker/ }).first(),
    ).toBeVisible();
  });

  test("220.4 user can delete a non-default payout method", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE_KEY);
    const resp = await apiPost(page, ALICE_KEY, "/ui/payouts/methods", {
      method_type: "bank_ach",
      account_last4: "9999",
      routing_last4: "8888",
      nickname: `Delete ${TS}`,
    });
    expect(resp.ok()).toBeTruthy();

    await page.goto(`${BASE}/payouts`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: "Payout Methods" }).click();

    const row = page
      .locator('[data-testid="method-row"]')
      .filter({ hasText: "9999" });
    await expect(row).toBeVisible();
    await row.getByRole("button", { name: "Delete" }).click();
    await page.getByRole("button", { name: "Remove" }).click();

    await expect(row).toHaveCount(0);
  });
});

// ─── Section 221: Admin Queue tab ─────────────────────────────────────────────────

test.describe("Section 221: Admin Queue tab", () => {
  test("221.1 admin queue tab hidden for regular user", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE_KEY);
    await page.goto(`${BASE}/payouts`, { waitUntil: "domcontentloaded" });
    await expect(
      page.getByRole("tab", { name: "Admin Queue" }),
    ).toHaveCount(0);
  });

  test("221.2 admin sees Admin Queue tab with stats and table", async ({ browser }) => {
    const page = await newIdentityPage(browser, CHARLIE_KEY);
    await page.goto(`${BASE}/payouts`, { waitUntil: "domcontentloaded" });

    const tab = page.getByRole("tab", { name: "Admin Queue" });
    await expect(tab).toBeVisible();
    await tab.click();

    await expect(page.getByTestId("stat-requested")).toBeVisible();
    await expect(page.getByTestId("admin-status-filter")).toBeVisible();
  });

  test("221.3 admin reject dialog enforces a min-length reason", async ({ browser }) => {
    const page = await newIdentityPage(browser, CHARLIE_KEY);

    // Seed a requested payout for Alice so the queue is non-empty.
    await apiPost(page, ALICE_KEY, "/ui/payouts/request", {
      amount_cents: 100,
      method: "bank_transfer",
      notes: `admin-test ${TS}`,
    });

    await page.goto(`${BASE}/payouts`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: "Admin Queue" }).click();

    const row = page.locator('[data-testid="admin-payout-row"]').first();
    await expect(row).toBeVisible();
    await row.getByTestId("reject-btn").click();

    const confirm = page.getByTestId("confirm-reject-btn");
    await expect(confirm).toBeDisabled();
    await page.getByTestId("reject-reason-input").fill("Too short");
    await expect(confirm).toBeDisabled();
    await page.getByTestId("reject-reason-input").fill("Address could not be verified");
    await expect(confirm).toBeEnabled();
  });
});
