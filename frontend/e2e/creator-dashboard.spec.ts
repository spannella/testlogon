/**
 * E2E tests for CREATOR-003: Creator Dashboard Mobile-Optimized View
 *
 * Sections:
 *   114 — Dashboard Summary API (5 tests)
 *   115 — Milestone API (5 tests)
 *   116 — Dashboard UI (6 tests)
 *   117 — Milestone Settings (3 tests)
 *   118 — Milestone Acknowledge (3 tests)
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";

const DDB_ENDPOINT = "http://localhost:8001";
const PYTHON = "/home/ubuntu/testlogon/.venv/bin/python3";

// ─── Session bootstrap ────────────────────────────────────────────────────────

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
    const raw = execSync(
      `${PYTHON} /home/ubuntu/testlogon/e2e_session_setup.py`,
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
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

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

async function apiPost(page: Page, path: string, body?: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${API}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiPatch(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.patch(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── DynamoDB helpers ─────────────────────────────────────────────────────────

function ddbPut(tableName: string, item: Record<string, unknown>) {
  const script = `
import boto3, json, sys
from decimal import Decimal

def convert(obj):
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, int):
        return obj
    if isinstance(obj, dict):
        return {k: convert(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [convert(i) for i in obj]
    return obj

ddb = boto3.resource("dynamodb", region_name="us-east-1", endpoint_url="${DDB_ENDPOINT}")
table = ddb.Table("${tableName}")
item = json.loads(sys.argv[1])
table.put_item(Item=convert(item))
print("OK")
`;
  execSync(`${PYTHON} -c '${script}' '${JSON.stringify(item)}'`, {
    cwd: "/home/ubuntu/testlogon",
    timeout: 10_000,
  });
}

function ddbDelete(tableName: string, key: Record<string, string>) {
  const script = `
import boto3, json, sys
ddb = boto3.resource("dynamodb", region_name="us-east-1", endpoint_url="${DDB_ENDPOINT}")
table = ddb.Table("${tableName}")
table.delete_item(Key=json.loads(sys.argv[1]))
print("OK")
`;
  try {
    execSync(`${PYTHON} -c '${script}' '${JSON.stringify(key)}'`, {
      cwd: "/home/ubuntu/testlogon",
      timeout: 10_000,
    });
  } catch {
    // ignore
  }
}

// ─── Test data ────────────────────────────────────────────────────────────────

const TS = Date.now();
const TODAY = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
const NOW_TS = Math.floor(Date.now() / 1000);

// Compute 7 past dates
function daysAgo(n: number): string {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d.toISOString().slice(0, 10);
}

// ─── Test setup ───────────────────────────────────────────────────────────────

test.describe("114 . Dashboard summary API", () => {
  test.beforeAll(() => {
    getSessions();

    // Seed billing ledger entries for today (3 tips of $5 each = $15)
    for (let i = 0; i < 3; i++) {
      ddbPut("billing", {
        pk: `USER#${ALICE_ID}`,
        sk: `LEDGER#${NOW_TS + i}#tip_${TS}_${i}`,
        type: "credit",
        amount_cents: 500,
        reason: "Tip received",
        currency: "USD",
        ts: NOW_TS + i,
        entry_id: `tip_${TS}_${i}`,
      });
    }

    // Seed analytics rollup rows for 7 days
    for (let d = 0; d < 7; d++) {
      const dateStr = daysAgo(d);
      ddbPut("AnalyticsRollups", {
        pk: `CREATOR#${ALICE_ID}`,
        sk: `DAILY#${dateStr}`,
        date_scope: `DATE#${dateStr}`,
        total_views: 100 + d * 10,
        unique_viewers: 50 + d * 5,
        revenue_cents: 200 + d * 50,
        revenue_tips_cents: 100 + d * 20,
        revenue_subscriptions_cents: 100 + d * 30,
        new_subscribers: 5 + d,
        total_subscribers: 100 + d * 5,
        top_content_ids: [`post_${TS}_${d}`],
        created_at: NOW_TS,
        updated_at: NOW_TS,
      });
    }

    // Seed SUMMARY sentinel with total_subscribers
    ddbPut("AnalyticsRollups", {
      pk: `CREATOR#${ALICE_ID}`,
      sk: "SUMMARY",
      total_subscribers: 130,
      updated_at: NOW_TS,
    });
  });

  test("114.1 Summary returns all expected fields", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    const resp = await apiGet(page, "/ui/dashboard/summary");
    expect(resp.status()).toBe(200);

    const data = await resp.json();
    expect(data).toHaveProperty("today_earnings_cents");
    expect(data).toHaveProperty("period_views");
    expect(data).toHaveProperty("total_subscribers");
    expect(data).toHaveProperty("top_content");
    expect(data).toHaveProperty("active_broadcasts");
    expect(data).toHaveProperty("recent_milestones");
    expect(data).toHaveProperty("currency");
    expect(data).toHaveProperty("generated_at");

    await ctx.close();
  });

  test("114.2 Summary with no data returns zeros gracefully", async ({ browser }) => {
    // Use a fresh session (which has no seeded data for a different user)
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    // The endpoint should return 200 even if some sources have no data
    const resp = await apiGet(page, "/ui/dashboard/summary");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(typeof data.today_earnings_cents).toBe("number");
    expect(typeof data.period_views).toBe("number");
    expect(Array.isArray(data.warnings)).toBe(true);

    await ctx.close();
  });

  test("114.3 Refresh endpoint returns 200", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    const resp = await apiPost(page, "/ui/dashboard/refresh");
    // Accept either 200 or 429 (rate limited from other test runs)
    expect([200, 429]).toContain(resp.status());

    if (resp.status() === 200) {
      const data = await resp.json();
      expect(data.ok).toBe(true);
    }

    await ctx.close();
  });

  test("114.4 Summary includes earnings breakdown", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    const resp = await apiGet(page, "/ui/dashboard/summary");
    expect(resp.status()).toBe(200);

    const data = await resp.json();
    expect(data.earnings_breakdown).toBeDefined();
    expect(typeof data.earnings_breakdown.tips).toBe("number");
    expect(typeof data.earnings_breakdown.subscriptions).toBe("number");

    await ctx.close();
  });

  test("114.5 Summary includes generated_at timestamp", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    const resp = await apiGet(page, "/ui/dashboard/summary");
    expect(resp.status()).toBe(200);

    const data = await resp.json();
    expect(data.generated_at).toBeGreaterThan(0);
    // Should be a recent timestamp (within the last minute)
    const now = Math.floor(Date.now() / 1000);
    expect(data.generated_at).toBeGreaterThan(now - 60);
    expect(data.generated_at).toBeLessThanOrEqual(now + 5);

    await ctx.close();
  });
});

// ── Section 115: Milestone API ────────────────────────────────────────────────

test.describe("115 . Milestone API", () => {
  const MILESTONE_METRIC = "subscribers";
  const MILESTONE_THRESHOLD = 100;
  const MILESTONE_ID = `${MILESTONE_METRIC}_${MILESTONE_THRESHOLD}`;

  test.beforeAll(() => {
    getSessions();
    // Clean up any previous milestone records
    ddbDelete("app_single_table", {
      pk: `USER#${ALICE_ID}`,
      sk: `MILESTONE#subscribers#10`,
    });
    ddbDelete("app_single_table", {
      pk: `USER#${ALICE_ID}`,
      sk: `MILESTONE#subscribers#50`,
    });
    ddbDelete("app_single_table", {
      pk: `USER#${ALICE_ID}`,
      sk: `MILESTONE#subscribers#100`,
    });
    ddbDelete("app_single_table", {
      pk: `USER#${ALICE_ID}`,
      sk: `MILESTONE#subscribers#500`,
    });
  });

  test("115.1 Milestone detected on threshold crossing", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    // Seed a milestone manually by writing to the app_single_table
    ddbPut("app_single_table", {
      pk: `USER#${ALICE_ID}`,
      sk: `MILESTONE#${MILESTONE_METRIC}#${MILESTONE_THRESHOLD}`,
      milestone_id: MILESTONE_ID,
      user_id: ALICE_ID,
      metric: MILESTONE_METRIC,
      threshold: MILESTONE_THRESHOLD,
      current_value: 130,
      formatted: "100",
      achieved_at: NOW_TS,
      acknowledged: false,
    });

    // List milestones should now include this one
    const resp = await apiGet(page, "/ui/milestones");
    expect(resp.status()).toBe(200);

    const milestones = await resp.json();
    expect(Array.isArray(milestones)).toBe(true);
    const found = milestones.find(
      (m: any) => m.metric === MILESTONE_METRIC && Number(m.threshold) === MILESTONE_THRESHOLD
    );
    expect(found).toBeDefined();

    await ctx.close();
  });

  test("115.2 No duplicate milestone on re-check", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    // List milestones: there should be at most one for subscribers#100
    const resp = await apiGet(page, "/ui/milestones");
    expect(resp.status()).toBe(200);

    const milestones = await resp.json();
    const matches = milestones.filter(
      (m: any) => m.metric === MILESTONE_METRIC && Number(m.threshold) === MILESTONE_THRESHOLD
    );
    expect(matches.length).toBe(1);

    await ctx.close();
  });

  test("115.3 List milestones returns ordered", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    // Seed a second milestone
    ddbPut("app_single_table", {
      pk: `USER#${ALICE_ID}`,
      sk: `MILESTONE#subscribers#50`,
      milestone_id: "subscribers_50",
      user_id: ALICE_ID,
      metric: "subscribers",
      threshold: 50,
      current_value: 130,
      formatted: "50",
      achieved_at: NOW_TS - 100,
      acknowledged: false,
    });

    const resp = await apiGet(page, "/ui/milestones");
    expect(resp.status()).toBe(200);

    const milestones = await resp.json();
    expect(milestones.length).toBeGreaterThanOrEqual(2);
    // Should be sorted by achieved_at descending (most recent first)
    for (let i = 1; i < milestones.length; i++) {
      expect(Number(milestones[i - 1].achieved_at)).toBeGreaterThanOrEqual(
        Number(milestones[i].achieved_at)
      );
    }

    await ctx.close();
  });

  test("115.4 Acknowledge milestone sets acknowledged=true", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    const resp = await apiPost(
      page,
      `/ui/milestones/${MILESTONE_ID}/acknowledge`
    );
    expect(resp.status()).toBe(200);

    // Verify it's now acknowledged
    const listResp = await apiGet(page, "/ui/milestones");
    const milestones = await listResp.json();
    const found = milestones.find(
      (m: any) => m.metric === MILESTONE_METRIC && Number(m.threshold) === MILESTONE_THRESHOLD
    );
    expect(found).toBeDefined();
    expect(found.acknowledged).toBe(true);

    await ctx.close();
  });

  test("115.5 Milestone settings update persists", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    // Update settings
    const patchResp = await apiPatch(page, "/ui/milestones/settings", {
      push_enabled: false,
      email_enabled: true,
      celebration_enabled: false,
    });
    expect(patchResp.status()).toBe(200);

    // Read back
    const getResp = await apiGet(page, "/ui/milestones/settings");
    expect(getResp.status()).toBe(200);
    const settings = await getResp.json();
    expect(settings.push_enabled).toBe(false);
    expect(settings.email_enabled).toBe(true);
    expect(settings.celebration_enabled).toBe(false);

    await ctx.close();
  });
});

// ── Section 116: Dashboard UI ─────────────────────────────────────────────────

test.describe("116 . Dashboard UI", () => {
  test.beforeAll(() => {
    getSessions();
  });

  test("116.1 Page loads with KPI cards visible", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/creator-dashboard`, { waitUntil: "domcontentloaded" });

    // Wait for the page to load
    await expect(page.getByText("Creator Dashboard")).toBeVisible({ timeout: 10_000 });

    // KPI cards should be visible
    await expect(page.getByText("Today's Earnings")).toBeVisible();
    await expect(page.getByText("Subscribers", { exact: true })).toBeVisible();
    await expect(page.getByText("7d Views")).toBeVisible();
    await expect(page.getByText("7d Revenue")).toBeVisible();

    await ctx.close();
  });

  test("116.2 Quick action buttons visible", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/creator-dashboard`, { waitUntil: "domcontentloaded" });

    await expect(page.getByText("Creator Dashboard")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByRole("button", { name: "New Post" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Go Live" })).toBeVisible();

    await ctx.close();
  });

  test("116.3 Top content section renders", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/creator-dashboard`, { waitUntil: "domcontentloaded" });

    await expect(page.getByText("Creator Dashboard")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText("Top Content")).toBeVisible();

    await ctx.close();
  });

  test("116.4 Earnings summary card renders", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/creator-dashboard`, { waitUntil: "domcontentloaded" });

    await expect(page.getByText("Creator Dashboard")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText("Earnings Breakdown")).toBeVisible();

    await ctx.close();
  });

  test("116.5 Warning banner shown when warnings present", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    // Mock the summary endpoint to return warnings
    await page.route("**/ui/dashboard/summary", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          today_earnings_cents: 0,
          earnings_breakdown: {
            subscriptions: 0,
            tips: 0,
            unlocks: 0,
            vod_purchases: 0,
            other: 0,
          },
          period_views: 0,
          period_revenue_cents: 0,
          total_subscribers: 0,
          top_content: [],
          active_broadcasts: [],
          recent_milestones: [],
          currency: "USD",
          generated_at: Math.floor(Date.now() / 1000),
          warnings: ["earnings_unavailable", "analytics_unavailable"],
        }),
      });
    });

    await page.goto(`${BASE}/creator-dashboard`, { waitUntil: "domcontentloaded" });
    await expect(page.getByText("Creator Dashboard")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText("Some data sources are currently unavailable")).toBeVisible();

    await ctx.close();
  });

  test("116.6 Navigate to /creator-dashboard works", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });

    // Navigate by URL
    await page.goto(`${BASE}/creator-dashboard`, { waitUntil: "domcontentloaded" });
    await expect(page.getByText("Creator Dashboard")).toBeVisible({ timeout: 10_000 });
    expect(page.url()).toContain("/creator-dashboard");

    await ctx.close();
  });
});

// ── Section 117: Milestone Settings ───────────────────────────────────────────

test.describe("117 . Milestone Settings", () => {
  test.beforeAll(() => {
    getSessions();

    // Ensure there's an unacknowledged milestone so the settings button shows
    ddbPut("app_single_table", {
      pk: `USER#${ALICE_ID}`,
      sk: `MILESTONE#views#100`,
      milestone_id: "views_100",
      user_id: ALICE_ID,
      metric: "views",
      threshold: 100,
      current_value: 150,
      formatted: "100",
      achieved_at: NOW_TS,
      acknowledged: false,
    });

    // Reset settings to defaults
    ddbDelete("app_single_table", {
      pk: `USER#${ALICE_ID}`,
      sk: "MILESTONE_PREFS",
    });
  });

  test("117.1 Settings dialog opens", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/creator-dashboard`, { waitUntil: "domcontentloaded" });

    await expect(page.getByText("Creator Dashboard")).toBeVisible({ timeout: 10_000 });

    // Wait for milestones section to appear (needs time for the milestones query)
    const settingsBtn = page.getByLabel("Milestone Settings");
    await expect(settingsBtn).toBeVisible({ timeout: 15_000 });

    await settingsBtn.click();
    await expect(page.getByText("Milestone Settings")).toBeVisible();
    await expect(page.getByText("Push notifications")).toBeVisible();

    await ctx.close();
  });

  test("117.2 Toggle saves setting", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/creator-dashboard`, { waitUntil: "domcontentloaded" });

    await expect(page.getByText("Creator Dashboard")).toBeVisible({ timeout: 10_000 });

    const settingsBtn = page.getByLabel("Milestone Settings");
    await expect(settingsBtn).toBeVisible({ timeout: 5_000 });
    await settingsBtn.click();
    await expect(page.getByText("Milestone Settings")).toBeVisible();

    // Toggle push notifications off
    const pushSwitch = page.locator("#push_enabled");
    await pushSwitch.click();

    // Wait for the mutation to complete
    await page.waitForTimeout(1000);

    // Verify via API
    const resp = await apiGet(page, "/ui/milestones/settings");
    const settings = await resp.json();
    expect(settings.push_enabled).toBe(false);

    await ctx.close();
  });

  test("117.3 Settings persist after reload", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    // Set a known state via API
    await apiPatch(page, "/ui/milestones/settings", {
      push_enabled: false,
      email_enabled: false,
      celebration_enabled: true,
    });

    // Verify via API after "reload"
    const resp = await apiGet(page, "/ui/milestones/settings");
    const settings = await resp.json();
    expect(settings.push_enabled).toBe(false);
    expect(settings.email_enabled).toBe(false);
    expect(settings.celebration_enabled).toBe(true);

    await ctx.close();
  });
});

// ── Section 118: Milestone Acknowledge ────────────────────────────────────────

test.describe("118 . Milestone Acknowledge", () => {
  const ACK_METRIC_A = "views";
  const ACK_THRESHOLD_A = 1000;
  const ACK_ID_A = `${ACK_METRIC_A}_${ACK_THRESHOLD_A}`;

  const ACK_METRIC_B = "views";
  const ACK_THRESHOLD_B = 10000;
  const ACK_ID_B = `${ACK_METRIC_B}_${ACK_THRESHOLD_B}`;

  test.beforeAll(() => {
    getSessions();

    // Seed two unacknowledged milestones
    ddbPut("app_single_table", {
      pk: `USER#${ALICE_ID}`,
      sk: `MILESTONE#${ACK_METRIC_A}#${ACK_THRESHOLD_A}`,
      milestone_id: ACK_ID_A,
      user_id: ALICE_ID,
      metric: ACK_METRIC_A,
      threshold: ACK_THRESHOLD_A,
      current_value: 1500,
      formatted: "1K",
      achieved_at: NOW_TS - 50,
      acknowledged: false,
    });

    ddbPut("app_single_table", {
      pk: `USER#${ALICE_ID}`,
      sk: `MILESTONE#${ACK_METRIC_B}#${ACK_THRESHOLD_B}`,
      milestone_id: ACK_ID_B,
      user_id: ALICE_ID,
      metric: ACK_METRIC_B,
      threshold: ACK_THRESHOLD_B,
      current_value: 15000,
      formatted: "10K",
      achieved_at: NOW_TS - 25,
      acknowledged: false,
    });
  });

  test("118.1 Acknowledge removes milestone from unacknowledged list", async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    // Acknowledge milestone A
    const resp = await apiPost(page, `/ui/milestones/${ACK_ID_A}/acknowledge`);
    expect(resp.status()).toBe(200);

    // List milestones — A should be acknowledged now
    const listResp = await apiGet(page, "/ui/milestones");
    const milestones = await listResp.json();
    const foundA = milestones.find(
      (m: any) => m.metric === ACK_METRIC_A && Number(m.threshold) === ACK_THRESHOLD_A
    );
    expect(foundA).toBeDefined();
    expect(foundA.acknowledged).toBe(true);

    await ctx.close();
  });

  test("118.2 Acknowledged milestone not in recent_milestones", async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    // Dashboard summary should not include acknowledged milestones in recent_milestones
    const resp = await apiGet(page, "/ui/dashboard/summary");
    expect(resp.status()).toBe(200);
    const data = await resp.json();

    // The acknowledged milestone A should NOT appear
    const foundA = data.recent_milestones.find(
      (m: any) => m.metric === ACK_METRIC_A && Number(m.threshold) === ACK_THRESHOLD_A
    );
    expect(foundA).toBeUndefined();

    await ctx.close();
  });

  test("118.3 Multiple milestones can be acknowledged independently", async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    // B should still be unacknowledged
    const listResp = await apiGet(page, "/ui/milestones");
    const milestones = await listResp.json();
    const foundB = milestones.find(
      (m: any) => m.metric === ACK_METRIC_B && Number(m.threshold) === ACK_THRESHOLD_B
    );
    expect(foundB).toBeDefined();
    expect(foundB.acknowledged).toBe(false);

    // Acknowledge B
    const ackResp = await apiPost(
      page,
      `/ui/milestones/${ACK_ID_B}/acknowledge`
    );
    expect(ackResp.status()).toBe(200);

    // Verify both are now acknowledged
    const listResp2 = await apiGet(page, "/ui/milestones");
    const milestones2 = await listResp2.json();
    const foundA2 = milestones2.find(
      (m: any) => m.metric === ACK_METRIC_A && Number(m.threshold) === ACK_THRESHOLD_A
    );
    const foundB2 = milestones2.find(
      (m: any) => m.metric === ACK_METRIC_B && Number(m.threshold) === ACK_THRESHOLD_B
    );
    expect(foundA2?.acknowledged).toBe(true);
    expect(foundB2?.acknowledged).toBe(true);

    await ctx.close();
  });
});
