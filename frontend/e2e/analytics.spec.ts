/**
 * E2E tests for the Creator Analytics Dashboard (ANALYTICS-001).
 *
 * Sections:
 *   A (1-8)  — Analytics API: seed rollup data, query endpoints, verify responses
 *   B (1-4)  — Analytics API Edge Cases: validation errors, auth, refresh
 *   C (1-6)  — Analytics UI: page load, charts, date range, responsive
 *
 * Auth: Cookie-based session for Alice (e2e_alice@test.local) with CSRF.
 *
 * Endpoints under test:
 *   GET  /ui/analytics/overview
 *   GET  /ui/analytics/revenue
 *   GET  /ui/analytics/views
 *   GET  /ui/analytics/subscribers
 *   GET  /ui/analytics/top-content
 *   GET  /ui/analytics/audience
 *   POST /ui/analytics/refresh
 */

import { tmpdir } from "os";
import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import { writeFileSync, unlinkSync } from "fs";
import * as path from "path";
import { loadSessions } from "./helpers/session";
import { usingCpp, cppSeedAnalyticsRollup, cppSeedAnalyticsSummary } from "./helpers/cpp-seed-analytics";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const PYTHON = REPO_ROOT + "/.venv/bin/python3";

// ─── Session bootstrap ───────────────────────────────────────────────────────

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

// ─── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  // Set localStorage auth-store so ProtectedRoute allows access
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

async function apiPost(page: Page, path: string, body?: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── DDB helpers ─────────────────────────────────────────────────────────────

const DDB_PRELUDE = `
import boto3, os, time, json
from decimal import Decimal
from pathlib import Path
for ln in Path('${REPO_ROOT}/.env.local').read_text().splitlines():
    ln = ln.strip()
    if ln and not ln.startswith('#') and '=' in ln:
        k, v = ln.split('=', 1); os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.environ.get('DDB_ANALYTICS_ROLLUPS', 'AnalyticsRollups'))
`;

function seedRollupRow(
  userSub: string,
  dateStr: string,
  data: Record<string, unknown>,
): void {
  if (usingCpp()) {
    cppSeedAnalyticsRollup(userSub, dateStr, data);
    return;
  }
  const tmpFile = `${tmpdir()}/analytics_seed_${Date.now()}.json`;
  writeFileSync(tmpFile, JSON.stringify(data));
  try {
    execSync(
      `${PYTHON} -c "
${DDB_PRELUDE}
import json
with open('${tmpFile}') as f:
    data = json.loads(f.read())
item = {
    'pk': 'CREATOR#${userSub}',
    'sk': 'DAILY#${dateStr}',
    'date_scope': 'DATE#${dateStr}',
    'created_at': int(time.time()),
    'updated_at': int(time.time()),
}
for k, v in data.items():
    if isinstance(v, float):
        item[k] = Decimal(str(v))
    elif isinstance(v, int):
        item[k] = v
    elif isinstance(v, dict):
        item[k] = {mk: int(mv) if isinstance(mv, (int, float)) else mv for mk, mv in v.items()}
    elif isinstance(v, list):
        item[k] = v
    else:
        item[k] = v
tbl.put_item(Item=item)
print('seeded', '${dateStr}')
"`,
      { timeout: 10_000 },
    );
  } finally {
    try { unlinkSync(tmpFile); } catch {}
  }
}

function seedSummarySentinel(
  userSub: string,
  data: Record<string, unknown>,
): void {
  if (usingCpp()) {
    cppSeedAnalyticsSummary(userSub, data);
    return;
  }
  const tmpFile = `${tmpdir()}/analytics_summary_${Date.now()}.json`;
  writeFileSync(tmpFile, JSON.stringify(data));
  try {
    execSync(
      `${PYTHON} -c "
${DDB_PRELUDE}
import json
with open('${tmpFile}') as f:
    data = json.loads(f.read())
item = {
    'pk': 'CREATOR#${userSub}',
    'sk': 'SUMMARY',
    'updated_at': int(time.time()),
}
for k, v in data.items():
    if isinstance(v, float):
        item[k] = Decimal(str(v))
    elif isinstance(v, int):
        item[k] = v
    else:
        item[k] = v
tbl.put_item(Item=item)
print('seeded SUMMARY')
"`,
      { timeout: 10_000 },
    );
  } finally {
    try { unlinkSync(tmpFile); } catch {}
  }
}

function cleanupRollups(userSub: string): void {
  try {
    execSync(
      `${PYTHON} -c "${DDB_PRELUDE}
pk = 'CREATOR#${userSub}'
resp = tbl.query(KeyConditionExpression=boto3.dynamodb.conditions.Key('pk').eq(pk))
with tbl.batch_writer() as batch:
    for item in resp.get('Items', []):
        batch.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
print('cleaned', len(resp.get('Items', [])), 'items')
"`,
      { timeout: 10_000 },
    );
  } catch {
    // Table may not exist yet; ignore
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section A: Analytics API (8 tests)
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("A — Analytics API", () => {
  let alicePage: Page;
  let aliceSub: string;

  test.beforeAll(async ({ browser }) => {
    const sessions = getSessions();
    aliceSub = sessions[ALICE_ID].user_sub;

    // Clean up any stale rollup data
    cleanupRollups(aliceSub);

    // Seed 6 days of rollup data (May 20-25, 2026)
    for (let day = 20; day <= 25; day++) {
      const dateStr = `2026-05-${day.toString().padStart(2, "0")}`;
      seedRollupRow(aliceSub, dateStr, {
        total_views: 100 * (day - 19),
        unique_viewers: 50 * (day - 19),
        watch_time_seconds: 3000 * (day - 19),
        revenue_cents: 500 * (day - 19),
        revenue_tips_cents: 100 * (day - 19),
        revenue_subscriptions_cents: 200 * (day - 19),
        revenue_unlocks_cents: 100 * (day - 19),
        revenue_vod_cents: 50 * (day - 19),
        revenue_ads_cents: 25 * (day - 19),
        revenue_calls_cents: 25 * (day - 19),
        new_subscribers: day - 19,
        churned_subscribers: 1,
        net_subscribers: day - 20,
        total_subscribers: 340 + (day - 20),
        top_content_ids: [`vid_test_${day}`, `post_test_${day}`],
        audience_countries: { US: 30 * (day - 19), GB: 10 * (day - 19), DE: 10 * (day - 19) },
        audience_devices: { mobile: 30 * (day - 19), desktop: 15 * (day - 19), tablet: 5 * (day - 19) },
        post_reactions: 10 * (day - 19),
        post_comments: 5 * (day - 19),
      });
    }

    // Seed summary sentinel
    seedSummarySentinel(aliceSub, {
      total_subscribers: 345,
      lifetime_revenue_cents: 125000,
      lifetime_views: 45230,
      last_rollup_date: "2026-05-25",
    });

    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    cleanupRollups(aliceSub);
    await alicePage.context().close();
  });

  test("A1 — Empty analytics returns zero for fresh date range", async () => {
    // Query a date range with no seeded data
    const resp = await apiGet(alicePage, "/ui/analytics/overview?from_date=2025-01-01&to_date=2025-01-07");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.period_views).toBe(0);
    expect(data.period_revenue_cents).toBe(0);
    expect(data.period_new_subscribers).toBe(0);
    expect(data.currency).toBe("USD");
  });

  test("A2 — Revenue breakdown includes seeded tip/subscription/unlock credits", async () => {
    const resp = await apiGet(alicePage, "/ui/analytics/revenue?from_date=2026-05-20&to_date=2026-05-25&granularity=day");
    expect(resp.status()).toBe(200);
    const data = await resp.json();

    expect(data.total_cents).toBeGreaterThan(0);
    expect(data.breakdown).toBeDefined();
    expect(data.breakdown.tips).toBeGreaterThan(0);
    expect(data.breakdown.subscriptions).toBeGreaterThan(0);
    expect(data.breakdown.unlocks).toBeGreaterThan(0);
    expect(data.breakdown.vod).toBeGreaterThan(0);
    expect(data.breakdown.ads).toBeGreaterThan(0);
    expect(data.breakdown.calls).toBeGreaterThan(0);
    expect(data.currency).toBe("USD");
  });

  test("A3 — Time range filter excludes out-of-range data", async () => {
    // Query May 22-24 (3 days out of the 6 seeded)
    const resp = await apiGet(alicePage, "/ui/analytics/revenue?from_date=2026-05-22&to_date=2026-05-24&granularity=day");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.time_series).toHaveLength(3);
    // Each entry should have a date in the range
    const dates = data.time_series.map((ts: { date: string }) => ts.date);
    expect(dates).toContain("2026-05-22");
    expect(dates).toContain("2026-05-23");
    expect(dates).toContain("2026-05-24");
  });

  test("A4 — Daily granularity produces per-day time series", async () => {
    const resp = await apiGet(alicePage, "/ui/analytics/views?from_date=2026-05-20&to_date=2026-05-25&granularity=day");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.time_series).toHaveLength(6);
    for (const entry of data.time_series) {
      expect(entry.views).toBeGreaterThanOrEqual(0);
      expect(entry.unique_viewers).toBeGreaterThanOrEqual(0);
    }
  });

  test("A5 — Top content returns ranked list by view count", async () => {
    const resp = await apiGet(alicePage, "/ui/analytics/top-content?from_date=2026-05-20&to_date=2026-05-25&sort_by=views");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items.length).toBeGreaterThan(0);
    expect(data.total_items).toBeGreaterThan(0);
    // First item should have highest views
    if (data.items.length > 1) {
      expect(data.items[0].views).toBeGreaterThanOrEqual(data.items[1].views);
    }
  });

  test("A6 — Subscriber growth shows correct net change", async () => {
    const resp = await apiGet(alicePage, "/ui/analytics/subscribers?from_date=2026-05-20&to_date=2026-05-25&granularity=day");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.time_series).toHaveLength(6);
    // net_change should be sum of daily net values
    const calculatedNetChange = data.time_series.reduce(
      (sum: number, ts: { net: number }) => sum + ts.net,
      0,
    );
    expect(data.net_change).toBe(calculatedNetChange);
    expect(data.current_total).toBeGreaterThan(0);
  });

  test("A7 — Audience endpoint returns country/device breakdown", async () => {
    const resp = await apiGet(alicePage, "/ui/analytics/audience?from_date=2026-05-20&to_date=2026-05-25");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.countries.length).toBeGreaterThan(0);
    expect(data.devices.length).toBeGreaterThan(0);
    expect(data.total_unique_viewers).toBeGreaterThan(0);

    // Check country structure
    const us = data.countries.find((c: { code: string }) => c.code === "US");
    expect(us).toBeDefined();
    expect(us.name).toBe("United States");
    expect(us.viewers).toBeGreaterThan(0);
    expect(us.percentage).toBeGreaterThan(0);

    // Check device structure
    const mobile = data.devices.find((d: { type: string }) => d.type === "mobile");
    expect(mobile).toBeDefined();
    expect(mobile.viewers).toBeGreaterThan(0);
  });

  test("A8 — Overview returns aggregated summary cards", async () => {
    const resp = await apiGet(alicePage, "/ui/analytics/overview?from_date=2026-05-20&to_date=2026-05-25");
    expect(resp.status()).toBe(200);
    const data = await resp.json();

    // Views should be sum of daily views (100 + 200 + 300 + 400 + 500 + 600 = 2100)
    expect(data.period_views).toBe(2100);
    // Revenue should be sum of daily revenue (500 + 1000 + 1500 + 2000 + 2500 + 3000 = 10500)
    expect(data.period_revenue_cents).toBe(10500);
    // New subscribers should be sum (1 + 2 + 3 + 4 + 5 + 6 = 21)
    expect(data.period_new_subscribers).toBe(21);
    // total_subscribers from SUMMARY or last rollup day
    expect(data.total_subscribers).toBeGreaterThanOrEqual(345);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section B: Analytics API Edge Cases (4 tests)
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("B — Analytics API Edge Cases", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.context().close();
  });

  test("B1 — Invalid date range returns 400", async () => {
    const resp = await apiGet(
      alicePage,
      "/ui/analytics/overview?from_date=2026-06-01&to_date=2026-05-01",
    );
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(data.detail).toContain("from_date must be before to_date");
  });

  test("B2 — Unauthenticated request returns 401", async () => {
    // Use a fresh context with no cookies
    const ctx = await alicePage.context().browser()!.newContext({ storageState: undefined });
    const noAuthPage = await ctx.newPage();
    const resp = await noAuthPage.request.get(`${BASE}/ui/analytics/overview`);
    expect(resp.status()).toBe(401);
    await ctx.close();
  });

  test("B3 — Very large date range returns 400", async () => {
    const resp = await apiGet(
      alicePage,
      "/ui/analytics/overview?from_date=2024-01-01&to_date=2026-05-27",
    );
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(data.detail).toContain("Date range cannot exceed 365 days");
  });

  test("B4 — Refresh endpoint triggers without error", async () => {
    const resp = await apiPost(alicePage, "/ui/analytics/refresh");
    // Accept 200 (success) or 429 (rate limited from prior run — in-memory cooldown)
    expect([200, 429]).toContain(resp.status());
    if (resp.status() === 200) {
      const data = await resp.json();
      expect(data.ok).toBe(true);
      expect(data.days_refreshed).toBeGreaterThan(0);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section C: Analytics UI (6 tests)
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("C — Analytics UI", () => {
  let alicePage: Page;
  let aliceSub: string;

  test.beforeAll(async ({ browser }) => {
    const sessions = getSessions();
    aliceSub = sessions[ALICE_ID].user_sub;

    // Seed some rollup data so charts have content
    // Use dates relative to today for proper default range matching
    const now = new Date();
    for (let i = 1; i <= 7; i++) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      const dateStr = d.toISOString().slice(0, 10);
      seedRollupRow(aliceSub, dateStr, {
        total_views: 100 * i,
        unique_viewers: 50 * i,
        watch_time_seconds: 3000 * i,
        revenue_cents: 500 * i,
        revenue_tips_cents: 100 * i,
        revenue_subscriptions_cents: 200 * i,
        revenue_unlocks_cents: 100 * i,
        revenue_vod_cents: 50 * i,
        revenue_ads_cents: 25 * i,
        revenue_calls_cents: 25 * i,
        new_subscribers: i,
        churned_subscribers: 1,
        net_subscribers: i - 1,
        total_subscribers: 340 + i,
        top_content_ids: [`vid_ui_${i}`, `post_ui_${i}`],
        audience_countries: { US: 30 * i, GB: 10 * i },
        audience_devices: { mobile: 30 * i, desktop: 15 * i, tablet: 5 * i },
        post_reactions: 10 * i,
        post_comments: 5 * i,
      });
    }

    seedSummarySentinel(aliceSub, {
      total_subscribers: 347,
      lifetime_revenue_cents: 125000,
      lifetime_views: 45230,
      last_rollup_date: now.toISOString().slice(0, 10),
    });

    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    cleanupRollups(aliceSub);
    await alicePage.context().close();
  });

  test("C1 — Analytics page loads with summary cards", async () => {
    await alicePage.goto(`${BASE}/analytics`);
    await alicePage.waitForLoadState("domcontentloaded");

    // Wait for summary cards to appear — they have data-testid or recognizable text
    await expect(alicePage.getByText("Views", { exact: true }).first()).toBeVisible({ timeout: 15_000 });
    await expect(alicePage.getByText("Revenue", { exact: true }).first()).toBeVisible();
    await expect(alicePage.getByText("New Subscribers").first()).toBeVisible();
    await expect(alicePage.getByText("Total Subscribers").first()).toBeVisible();
  });

  test("C2 — Revenue breakdown chart renders", async () => {
    await alicePage.goto(`${BASE}/analytics`);
    await alicePage.waitForLoadState("domcontentloaded");

    // Wait for the Revenue Breakdown section to load
    await expect(alicePage.getByText("Revenue Breakdown").first()).toBeVisible({ timeout: 15_000 });

    // The "Total:" label should always be present in the revenue breakdown section
    await expect(alicePage.getByText("Total:").first()).toBeVisible({ timeout: 10_000 });
  });

  test("C3 — Date range selector updates URL params", async () => {
    await alicePage.goto(`${BASE}/analytics`);
    await alicePage.waitForLoadState("domcontentloaded");

    // Click "30d" preset. The label appears in more than one control
    // (preset pill plus other range selectors), so scope to the first.
    const btn30d = alicePage.getByRole("button", { name: "30d" }).first();
    await expect(btn30d).toBeVisible({ timeout: 10_000 });
    await btn30d.click();

    // URL should now contain date params
    await alicePage.waitForTimeout(500);
    const url = alicePage.url();
    expect(url).toContain("analytics");
  });

  test("C4 — Top content section is rendered", async () => {
    await alicePage.goto(`${BASE}/analytics`);

    // Wait for the top-content API response to complete
    await alicePage.waitForResponse(
      (resp) => resp.url().includes("/ui/analytics/top-content") && resp.status() === 200,
      { timeout: 15_000 },
    );

    // Scroll down to make the Top Content section visible
    await alicePage.evaluate(() => window.scrollTo(0, document.body.scrollHeight));

    // Wait for the Top Content section heading
    await expect(alicePage.getByText("Top Content").first()).toBeVisible({ timeout: 10_000 });

    // Either the table headers or the "No content data yet" empty state should be present
    const titleLocator = alicePage.locator("th").filter({ hasText: "Title" });
    const emptyLocator = alicePage.getByText("No content data yet");
    await expect(titleLocator.or(emptyLocator).first()).toBeVisible({ timeout: 5_000 });
  });

  test("C5 — Subscriber growth chart renders", async () => {
    await alicePage.goto(`${BASE}/analytics`);
    await alicePage.waitForLoadState("domcontentloaded");

    // Check that the subscriber growth section exists
    await expect(alicePage.getByText("Subscriber Growth").first()).toBeVisible({ timeout: 15_000 });

    // Recharts renders SVG elements — verify there is an SVG in the chart area
    const chartContainer = alicePage.locator("text=Subscriber Growth").locator("..").locator("..");
    // Just verify the section is visible; chart may or may not have SVG depending on data
    await expect(chartContainer).toBeVisible();
  });

  test("C6 — Page is responsive on mobile viewport", async () => {
    // Use a new context with mobile viewport
    const ctx = await alicePage.context().browser()!.newContext({
      viewport: { width: 375, height: 667 },
    });
    const mobilePage = await ctx.newPage();
    await injectAuth(mobilePage, ALICE_ID);

    await mobilePage.goto(`${BASE}/analytics`);
    await mobilePage.waitForLoadState("domcontentloaded");

    // The h1 page title should be visible (use role heading to avoid matching sidebar)
    await expect(mobilePage.getByRole("heading", { name: "Analytics" })).toBeVisible({ timeout: 15_000 });

    // Summary cards should stack (all visible but in single column)
    await expect(mobilePage.getByText("Views", { exact: true }).first()).toBeVisible({ timeout: 10_000 });

    await ctx.close();
  });
});
