/**
 * E2E tests for Admin Ad Platform Management (ADS-018).
 *
 * An admin oversight layer over the existing advertiser ad system. Covers:
 *   Section 420 — Cross-user listing API (4 tests)
 *   Section 421 — Account moderation API (4 tests)
 *   Section 422 — Creative moderation API (4 tests)
 *   Section 423 — Platform metrics API (3 tests)
 *   Section 424 — Admin Ad Platform dashboard UI (3 tests)
 *
 * Auth:
 *   Alice (USER)         — advertiser who creates accounts/campaigns/creatives
 *   Charlie (ADMIN)      — platform admin (read + moderation)
 *   Root (ROOT)          — platform admin (also dashboard UI)
 *
 * Sessions created by e2e_admin_session_setup.py (role-bearing JWT cookies).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE       = "http://localhost:3000";
const ALICE_ID   = "alice";
const ROOT_ID    = "root";
const CHARLIE_ID = "charlie_admin";
const TS         = Date.now();

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
function getAdminSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, identity: string) {
  const sessions = getAdminSessions();
  const session = sessions[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, identity: string, path: string) {
  const sess = getAdminSessions()[identity];
  return page.request.get(`${BASE}${path}`, {
    headers: { "x-csrf-token": sess.csrf_token },
  });
}

// ─── Shared state ─────────────────────────────────────────────────────────────

let alicePage: Page;
let charliePage: Page;
let rootPage: Page;
let accountId: string;       // pending_review account (for moderation)
let approvedAccountId: string;
let campaignId: string;
let creativeId: string;      // pending_review creative (for moderation)

// ─── Setup: seed advertiser account / campaign / creative as Alice ──────────────

test.beforeAll(async ({ browser }) => {
  alicePage = await newIdentityPage(browser, ALICE_ID);
  charliePage = await newIdentityPage(browser, CHARLIE_ID);
  rootPage = await newIdentityPage(browser, ROOT_ID);

  // 1. Pending-review account (moderation target).
  const acct = await apiPost(alicePage, ALICE_ID, "/ui/ads/accounts", {
    company_name: `AdPlatformCo_${TS}`,
    billing_email: `adplat_${TS}@test.local`,
  });
  expect(acct.status()).toBe(201);
  accountId = (await acct.json()).account_id;

  // 2. Approved account so we can create a campaign + creative under it.
  const acct2 = await apiPost(alicePage, ALICE_ID, "/ui/ads/accounts", {
    company_name: `AdPlatformApproved_${TS}`,
    billing_email: `adplat2_${TS}@test.local`,
  });
  expect(acct2.status()).toBe(201);
  approvedAccountId = (await acct2.json()).account_id;

  await apiPost(rootPage, ROOT_ID, `/ui/admin/ads/accounts/${approvedAccountId}/review`, {
    decision: "approve",
    notes: "seed",
  });

  // 3. Campaign under approved account.
  const camp = await apiPost(
    alicePage, ALICE_ID, `/ui/ads/accounts/${approvedAccountId}/campaigns`,
    { name: `AdPlatformCamp_${TS}`, objective: "awareness", budget_cents: 5000, budget_type: "daily" },
  );
  expect(camp.status()).toBe(201);
  campaignId = (await camp.json()).campaign_id;

  // 4. Creative, submitted for review (→ pending_review).
  const cr = await apiPost(
    alicePage, ALICE_ID, `/ui/ads/campaigns/${campaignId}/creatives`,
    { format: "image", title: `AdPlatformCreative_${TS}`, alt_text: "test" },
  );
  expect(cr.status()).toBe(201);
  creativeId = (await cr.json()).creative_id;
  await apiPost(
    alicePage, ALICE_ID,
    `/ui/ads/campaigns/${campaignId}/creatives/${creativeId}/submit`,
  );
});

test.afterAll(async () => {
  await alicePage?.close();
  await charliePage?.close();
  await rootPage?.close();
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 420: Cross-user listing API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("420 — Cross-user listing API", () => {
  test("420.1 Admin lists all advertiser accounts across users", async () => {
    const r = await apiGet(charliePage, CHARLIE_ID, "/ui/admin/ad-platform/accounts");
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(Array.isArray(data)).toBe(true);
    expect(data.some((a: { account_id: string }) => a.account_id === accountId)).toBe(true);
  });

  test("420.2 Admin lists all campaigns across users", async () => {
    const r = await apiGet(charliePage, CHARLIE_ID, "/ui/admin/ad-platform/campaigns");
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.some((c: { campaign_id: string }) => c.campaign_id === campaignId)).toBe(true);
  });

  test("420.3 Admin lists all creatives across users", async () => {
    const r = await apiGet(charliePage, CHARLIE_ID, "/ui/admin/ad-platform/creatives");
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.some((c: { creative_id: string }) => c.creative_id === creativeId)).toBe(true);
  });

  test("420.4 Non-admin (USER) cannot list accounts", async () => {
    const r = await apiGet(alicePage, ALICE_ID, "/ui/admin/ad-platform/accounts");
    expect(r.status()).toBe(403);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 421: Account moderation API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("421 — Account moderation API", () => {
  test("421.1 Moderation queue lists pending account", async () => {
    const r = await apiGet(charliePage, CHARLIE_ID, "/ui/admin/ad-platform/moderation/queue");
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.accounts.some((a: { account_id: string }) => a.account_id === accountId)).toBe(true);
  });

  test("421.2 Admin approves account", async () => {
    const r = await apiPost(
      charliePage, CHARLIE_ID, `/ui/admin/ad-platform/accounts/${accountId}/moderate`,
      { action: "approve" },
    );
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.status).toBe("active");
  });

  test("421.3 Moderation history records the approval", async () => {
    const r = await apiGet(
      charliePage, CHARLIE_ID,
      `/ui/admin/ad-platform/moderation/account/${accountId}/history`,
    );
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(Array.isArray(data)).toBe(true);
    expect(data.length).toBeGreaterThanOrEqual(1);
    expect(data[0]).toHaveProperty("action");
  });

  test("421.4 Suspend without reason returns 422", async () => {
    const r = await apiPost(
      charliePage, CHARLIE_ID, `/ui/admin/ad-platform/accounts/${accountId}/moderate`,
      { action: "suspend", reason: "" },
    );
    expect(r.status()).toBe(422);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 422: Creative moderation API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("422 — Creative moderation API", () => {
  test("422.1 Moderation queue lists pending creative", async () => {
    const r = await apiGet(charliePage, CHARLIE_ID, "/ui/admin/ad-platform/moderation/queue");
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.creatives.some((c: { creative_id: string }) => c.creative_id === creativeId)).toBe(true);
  });

  test("422.2 Admin rejects creative with reason", async () => {
    const r = await apiPost(
      charliePage, CHARLIE_ID, `/ui/admin/ad-platform/creatives/${creativeId}/moderate`,
      { action: "reject", reason: "Violates content policy" },
    );
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.status).toBe("rejected");
  });

  test("422.3 Creative moderation history records the rejection", async () => {
    const r = await apiGet(
      charliePage, CHARLIE_ID,
      `/ui/admin/ad-platform/moderation/creative/${creativeId}/history`,
    );
    expect(r.status()).toBe(200);
    const data = await r.json();
    const evt = data.find((e: { action: string }) => e.action === "reject");
    expect(evt).toBeTruthy();
    expect(evt.reason).toBe("Violates content policy");
  });

  test("422.4 Moderate non-existent creative returns 404", async () => {
    const r = await apiPost(
      charliePage, CHARLIE_ID, "/ui/admin/ad-platform/creatives/cr_doesnotexist/moderate",
      { action: "approve" },
    );
    expect(r.status()).toBe(404);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 423: Platform metrics API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("423 — Platform metrics API", () => {
  test("423.1 Admin views platform metrics", async () => {
    const r = await apiGet(charliePage, CHARLIE_ID, "/ui/admin/ad-platform/metrics");
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data).toHaveProperty("total_spend_cents");
    expect(data).toHaveProperty("platform_revenue_cents");
    expect(data.account_count).toBeGreaterThanOrEqual(1);
    expect(data.total_spend_cents).toBeGreaterThanOrEqual(0);
  });

  test("423.2 Revenue series returns an array", async () => {
    const r = await apiGet(charliePage, CHARLIE_ID, "/ui/admin/ad-platform/metrics/revenue-series");
    expect(r.status()).toBe(200);
    expect(Array.isArray(await r.json())).toBe(true);
  });

  test("423.3 Non-admin cannot view metrics", async () => {
    const r = await apiGet(alicePage, ALICE_ID, "/ui/admin/ad-platform/metrics");
    expect(r.status()).toBe(403);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 424: Admin Ad Platform dashboard UI
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("424 — Admin Ad Platform dashboard UI", () => {
  test("424.1 Dashboard loads with revenue tab", async () => {
    await injectAuth(rootPage, ROOT_ID);
    await rootPage.goto(`${BASE}/admin/ad-platform`, { waitUntil: "domcontentloaded" });
    await expect(rootPage.getByRole("heading", { name: "Ad Platform Management" })).toBeVisible();
    await expect(rootPage.getByRole("tab", { name: "Revenue" })).toBeVisible();
  });

  test("424.2 Moderation tab shows queue", async () => {
    await rootPage.getByRole("tab", { name: "Moderation" }).click();
    await expect(rootPage.getByText("Pending Accounts")).toBeVisible();
  });

  test("424.3 Accounts tab shows advertiser accounts", async () => {
    await rootPage.getByRole("tab", { name: "Accounts" }).click();
    await expect(rootPage.getByText("Advertiser Accounts")).toBeVisible();
  });
});
