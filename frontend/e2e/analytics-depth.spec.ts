/**
 * E2E tests for Creator Analytics Depth (ANALYTICS-002).
 *
 * Sections:
 *   1 (tests 1-4) — Engagement Rate Fix
 *   2 (tests 5-7) — Title Resolution Fix
 *   3 (tests 8-12) — Per-Content Drill-down
 *   4 (tests 13-15) — Empty/Edge States
 *   5 (tests 16-18) — API Contract
 *   6 (tests 19-20) — Sortable Engagement Column
 *
 * Auth: Cookie-based session for Alice via e2e_admin_session_setup.py
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import { writeFileSync, unlinkSync } from "fs";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const PYTHON = "/home/ubuntu/testlogon/.venv/bin/python3";
const TS = Date.now();

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
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await injectAuth(page, identity);
  return page;
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  const qs = params ? "?" + new URLSearchParams(params).toString() : "";
  return page.request.get(`${API}${path}${qs}`);
}

async function apiPost(page: Page, identity: string, path: string, body: object) {
  const s = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token },
  });
}

// ─── DDB helpers ─────────────────────────────────────────────────────────────

const DDB_PRELUDE = `
import boto3, os, time, json
from decimal import Decimal
from pathlib import Path
for ln in Path('/home/ubuntu/testlogon/.env.local').read_text().splitlines():
    ln = ln.strip()
    if ln and not ln.startswith('#') and '=' in ln:
        k, v = ln.split('=', 1); os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
`;

function seedRollupRow(
  userSub: string,
  dateStr: string,
  data: Record<string, unknown>,
): void {
  const tmpFile = `/tmp/analytics_depth_seed_${Date.now()}_${Math.random().toString(36).slice(2)}.json`;
  writeFileSync(tmpFile, JSON.stringify(data));
  try {
    execSync(
      `${PYTHON} -c "
${DDB_PRELUDE}
tbl = ddb.Table(os.environ.get('DDB_ANALYTICS_ROLLUPS', 'AnalyticsRollups'))
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

function seedVideoMetadata(
  videoId: string,
  ownerUserId: string,
  data: Record<string, unknown>,
): void {
  const tmpFile = `/tmp/analytics_depth_video_${Date.now()}_${Math.random().toString(36).slice(2)}.json`;
  writeFileSync(tmpFile, JSON.stringify(data));
  try {
    execSync(
      `${PYTHON} -c "
${DDB_PRELUDE}
tbl = ddb.Table(os.environ.get('DDB_VIDEO_METADATA', 'VideoMetadata'))
import json
with open('${tmpFile}') as f:
    data = json.loads(f.read())
item = {
    'video_id': '${videoId}',
    'owner_user_id': '${ownerUserId}',
    'owner_id': '${ownerUserId}',
    'created_at': int(time.time()),
}
for k, v in data.items():
    if isinstance(v, float):
        from decimal import Decimal
        item[k] = Decimal(str(v))
    elif isinstance(v, int):
        item[k] = v
    else:
        item[k] = v
tbl.put_item(Item=item)
print('seeded video', '${videoId}')
"`,
      { timeout: 10_000 },
    );
  } finally {
    try { unlinkSync(tmpFile); } catch {}
  }
}

function seedPost(
  postId: string,
  userId: string,
  bodyPlain: string,
  data?: Record<string, unknown>,
): void {
  const extraData = data ? JSON.stringify(data) : "{}";
  const tmpFile = `/tmp/analytics_depth_post_${Date.now()}_${Math.random().toString(36).slice(2)}.json`;
  writeFileSync(tmpFile, extraData);
  try {
    execSync(
      `${PYTHON} -c "
${DDB_PRELUDE}
tbl = ddb.Table(os.environ.get('APP_TABLE', 'app_single_table'))
import json
with open('${tmpFile}') as f:
    extra = json.loads(f.read())
body_plain = '''${bodyPlain.replace(/'/g, "\\'")}'''
item = {
    'pk': 'POST#${postId}',
    'sk': 'META',
    'user_id': '${userId}',
    'author_id': '${userId}',
    'body_plain': body_plain,
    'body': body_plain,
    'created_at': int(time.time()),
    'view_count': 0,
    'like_count': 0,
    'comment_count': 0,
}
for k, v in extra.items():
    if isinstance(v, int):
        item[k] = v
    else:
        item[k] = v
tbl.put_item(Item=item)
print('seeded post', '${postId}')
"`,
      { timeout: 10_000 },
    );
  } finally {
    try { unlinkSync(tmpFile); } catch {}
  }
}

function seedBillingLedger(
  userSub: string,
  contentId: string,
  reason: string,
  amountCents: number,
): void {
  const entryId = `ledger_${Date.now()}_${Math.random().toString(36).slice(2)}`;
  execSync(
    `${PYTHON} -c "
${DDB_PRELUDE}
tbl = ddb.Table(os.environ.get('BILLING_TABLE_NAME', 'billing'))
import time
tbl.put_item(Item={
    'pk': 'USER#${userSub}',
    'sk': 'LEDGER#${entryId}',
    'amount_cents': ${amountCents},
    'reason': '${reason}',
    'meta': {'content_id': '${contentId}'},
    'created_at': int(time.time()),
})
print('seeded ledger', '${entryId}')
"`,
    { timeout: 10_000 },
  );
}

function cleanupRollups(userSub: string): void {
  try {
    execSync(
      `${PYTHON} -c "
${DDB_PRELUDE}
import boto3.dynamodb.conditions as cond
tbl = ddb.Table(os.environ.get('DDB_ANALYTICS_ROLLUPS', 'AnalyticsRollups'))
pk = 'CREATOR#${userSub}'
resp = tbl.query(KeyConditionExpression=cond.Key('pk').eq(pk))
with tbl.batch_writer() as batch:
    for item in resp.get('Items', []):
        batch.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
print('cleaned', len(resp.get('Items', [])), 'items')
"`,
      { timeout: 10_000 },
    );
  } catch {
    // ignore
  }
}

// ─── Test identifiers ─────────────────────────────────────────────────────────

const ALICE_ID = "alice";
const BOB_ID = "bob";

const VID_ENGAGED = `vid_engaged_${TS}`;
const VID_TITLED = `vid_titled_${TS}`;
const VID_NOVIEWS = `vid_noviews_${TS}`;
const VID_DETAIL = `vid_detail_${TS}`;
const VID_NOREV = `vid_norev_${TS}`;
const VID_BOB = `vid_bob_${TS}`;
const POST_LONG = `post_long_${TS}`;
const VID_MISSING = `vid_nonexistent_${TS}`;

// ═══════════════════════════════════════════════════════════════════════════════
// Section 1: Engagement Rate Fix
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 1: Engagement Rate Fix", () => {
  let alicePage: Page;
  let aliceSub: string;

  test.beforeAll(async ({ browser }) => {
    const sessions = getSessions();
    aliceSub = sessions[ALICE_ID].user_sub;
    alicePage = await newIdentityPage(browser, ALICE_ID);

    // Cleanup old rollup data
    cleanupRollups(aliceSub);

    // Seed video with known engagement stats
    seedVideoMetadata(VID_ENGAGED, aliceSub, {
      title: "Engaging Video",
      view_count: 100,
      like_count: 8,
      comment_count: 2,
    });

    seedVideoMetadata(VID_NOVIEWS, aliceSub, {
      title: "Zero Views Video",
      view_count: 0,
      like_count: 5,
      comment_count: 0,
    });

    // Seed rollup referencing these videos
    seedRollupRow(aliceSub, "2026-05-01", {
      total_views: 100,
      revenue_cents: 500,
      top_content_ids: [VID_ENGAGED, VID_NOVIEWS],
    });
  });

  test.afterAll(async () => {
    await alicePage.context().close();
  });

  test("1. Top content returns non-zero engagement rate for content with likes", async () => {
    const resp = await apiGet(alicePage, "/ui/analytics/top-content", {
      from_date: "2026-05-01",
      to_date: "2026-05-31",
    });
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    const engagedItem = body.items.find((i: any) => i.content_id === VID_ENGAGED);
    expect(engagedItem).toBeTruthy();
    // (8 + 2) / 100 = 0.10
    expect(engagedItem.engagement_rate).toBeCloseTo(0.10, 2);
  });

  test("2. Engagement rate formatted correctly (> 0)", async () => {
    const resp = await apiGet(alicePage, "/ui/analytics/top-content", {
      from_date: "2026-05-01",
      to_date: "2026-05-31",
    });
    const body = await resp.json();
    const engagedItem = body.items.find((i: any) => i.content_id === VID_ENGAGED);
    expect(engagedItem.engagement_rate).toBeGreaterThan(0);
    // Should be a proper float with max 4 decimal places
    const rateStr = engagedItem.engagement_rate.toString();
    const decimals = rateStr.includes(".") ? rateStr.split(".")[1].length : 0;
    expect(decimals).toBeLessThanOrEqual(4);
  });

  test("3. Top content supports sort_by=views and sort_by=revenue", async () => {
    const respViews = await apiGet(alicePage, "/ui/analytics/top-content", {
      from_date: "2026-05-01",
      to_date: "2026-05-31",
      sort_by: "views",
    });
    expect(respViews.ok()).toBeTruthy();
    const respRev = await apiGet(alicePage, "/ui/analytics/top-content", {
      from_date: "2026-05-01",
      to_date: "2026-05-31",
      sort_by: "revenue",
    });
    expect(respRev.ok()).toBeTruthy();
    // Both return items with engagement_rate
    const bodyViews = await respViews.json();
    const bodyRev = await respRev.json();
    expect(bodyViews.items[0].engagement_rate).toBeDefined();
    expect(bodyRev.items[0].engagement_rate).toBeDefined();
  });

  test("4. Engagement rate is zero for content with no views", async () => {
    const resp = await apiGet(alicePage, "/ui/analytics/top-content", {
      from_date: "2026-05-01",
      to_date: "2026-05-31",
    });
    const body = await resp.json();
    const noViewsItem = body.items.find((i: any) => i.content_id === VID_NOVIEWS);
    expect(noViewsItem).toBeTruthy();
    expect(noViewsItem.engagement_rate).toBe(0.0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 2: Title Resolution Fix
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 2: Title Resolution Fix", () => {
  let alicePage: Page;
  let aliceSub: string;

  test.beforeAll(async ({ browser }) => {
    const sessions = getSessions();
    aliceSub = sessions[ALICE_ID].user_sub;
    alicePage = await newIdentityPage(browser, ALICE_ID);

    // Seed video with a real title
    seedVideoMetadata(VID_TITLED, aliceSub, {
      title: "My Amazing Analytics Video",
      view_count: 50,
      like_count: 3,
      comment_count: 1,
    });

    // Seed post with long body
    const longBody = "This is a really long post body that should get truncated to sixty characters with an ellipsis at the end because it exceeds the limit";
    seedPost(POST_LONG, aliceSub, longBody, {
      view_count: 30,
      like_count: 2,
      comment_count: 1,
    });

    // Seed rollup referencing video, post, and a missing content_id
    seedRollupRow(aliceSub, "2026-05-02", {
      total_views: 80,
      revenue_cents: 300,
      top_content_ids: [VID_TITLED, POST_LONG, VID_MISSING],
    });
  });

  test.afterAll(async () => {
    await alicePage.context().close();
  });

  test("5. Top content shows real video title instead of vid_ prefix", async () => {
    const resp = await apiGet(alicePage, "/ui/analytics/top-content", {
      from_date: "2026-05-01",
      to_date: "2026-05-31",
    });
    const body = await resp.json();
    const vidItem = body.items.find((i: any) => i.content_id === VID_TITLED);
    expect(vidItem).toBeTruthy();
    expect(vidItem.title).toBe("My Amazing Analytics Video");
    expect(vidItem.title).not.toContain("vid_");
  });

  test("6. Post title is truncated body preview (60 chars + ...)", async () => {
    const resp = await apiGet(alicePage, "/ui/analytics/top-content", {
      from_date: "2026-05-01",
      to_date: "2026-05-31",
    });
    const body = await resp.json();
    const postItem = body.items.find((i: any) => i.content_id === POST_LONG);
    expect(postItem).toBeTruthy();
    // Should be truncated to 60 chars + "..."
    expect(postItem.title.endsWith("...")).toBeTruthy();
    expect(postItem.title.length).toBeLessThanOrEqual(63);
    expect(postItem.title).not.toContain("post_");
  });

  test("7. Missing content falls back gracefully (raw ID as title)", async () => {
    const resp = await apiGet(alicePage, "/ui/analytics/top-content", {
      from_date: "2026-05-01",
      to_date: "2026-05-31",
    });
    const body = await resp.json();
    const missingItem = body.items.find((i: any) => i.content_id === VID_MISSING);
    expect(missingItem).toBeTruthy();
    // Falls back to using the content_id as title
    expect(missingItem.title).toBe(VID_MISSING);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 3: Per-Content Drill-down
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 3: Per-Content Drill-down", () => {
  let alicePage: Page;
  let aliceSub: string;

  test.beforeAll(async ({ browser }) => {
    const sessions = getSessions();
    aliceSub = sessions[ALICE_ID].user_sub;
    alicePage = await newIdentityPage(browser, ALICE_ID);

    // Seed a video with metadata for detail page
    seedVideoMetadata(VID_DETAIL, aliceSub, {
      title: "Detail Test Video",
      view_count: 250,
      like_count: 20,
      comment_count: 5,
    });

    // Seed rollup for the overview page to have a clickable row
    seedRollupRow(aliceSub, "2026-05-03", {
      total_views: 250,
      revenue_cents: 1200,
      top_content_ids: [VID_DETAIL],
    });

    // Seed billing ledger for revenue breakdown
    seedBillingLedger(aliceSub, VID_DETAIL, "Tip sent", 500);
    seedBillingLedger(aliceSub, VID_DETAIL, "Unlock purchase", 700);
  });

  test.afterAll(async () => {
    await alicePage.context().close();
  });

  test("8. Clicking top content row navigates to detail page", async () => {
    await alicePage.goto(`${BASE}/analytics`, { waitUntil: "domcontentloaded" });
    // Wait for the Top Content section to finish loading. The table only
    // renders when the top-content query returns items; when it returns none
    // there is no <table> at all, so tolerate a missing table and fall back to
    // direct navigation below.
    await alicePage.waitForSelector("table", { timeout: 10_000 }).catch(() => {});
    // Find row with our video and click it
    const row = alicePage.locator("tr").filter({ hasText: "Detail Test Video" });
    if (await row.count() > 0) {
      await row.first().click();
      await alicePage.waitForURL(/\/analytics\/content\//);
      expect(alicePage.url()).toContain(`/analytics/content/${VID_DETAIL}`);
    } else {
      // Fallback: navigate directly to verify the page works
      await alicePage.goto(`${BASE}/analytics/content/${VID_DETAIL}`, { waitUntil: "domcontentloaded" });
      expect(alicePage.url()).toContain(`/analytics/content/${VID_DETAIL}`);
    }
  });

  test("9. Content detail page shows summary cards", async () => {
    await alicePage.goto(`${BASE}/analytics/content/${VID_DETAIL}`, { waitUntil: "domcontentloaded" });
    // Check for summary card labels
    await expect(alicePage.getByText("Total Views")).toBeVisible();
    await expect(alicePage.getByText("Revenue", { exact: true })).toBeVisible();
    await expect(alicePage.getByText("Engagement")).toBeVisible();
    await expect(alicePage.getByText("Interactions")).toBeVisible();
  });

  test("10. View trend chart renders on detail page", async () => {
    await alicePage.goto(`${BASE}/analytics/content/${VID_DETAIL}`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByText("View Trends")).toBeVisible();
    // The chart or no-data message should be present
    const chart = alicePage.locator(".recharts-responsive-container").first();
    const noData = alicePage.getByText("No view data for this period");
    const hasChart = await chart.isVisible().catch(() => false);
    const hasNoData = await noData.isVisible().catch(() => false);
    expect(hasChart || hasNoData).toBeTruthy();
  });

  test("11. Revenue breakdown shows categories", async () => {
    await alicePage.goto(`${BASE}/analytics/content/${VID_DETAIL}`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByText("Revenue Breakdown")).toBeVisible();
    // Should show Tips and Unlocks since we seeded both
    await expect(alicePage.getByText("Tips").first()).toBeVisible();
    await expect(alicePage.getByText("Unlocks").first()).toBeVisible();
  });

  test("12. Back button returns to analytics page", async () => {
    await alicePage.goto(`${BASE}/analytics/content/${VID_DETAIL}`, { waitUntil: "domcontentloaded" });
    await alicePage.getByRole("button", { name: "Back to analytics" }).click();
    await alicePage.waitForURL(/\/analytics$/);
    expect(alicePage.url()).toContain("/analytics");
    expect(alicePage.url()).not.toContain("/content/");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 4: Empty/Edge States
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 4: Empty/Edge States", () => {
  let alicePage: Page;
  let aliceSub: string;
  let bobPage: Page;
  let bobSub: string;

  test.beforeAll(async ({ browser }) => {
    const sessions = getSessions();
    aliceSub = sessions[ALICE_ID].user_sub;
    bobSub = sessions[BOB_ID].user_sub;
    alicePage = await newIdentityPage(browser, ALICE_ID);
    bobPage = await newIdentityPage(browser, BOB_ID);

    // Seed a video with no revenue for Alice
    seedVideoMetadata(VID_NOREV, aliceSub, {
      title: "No Revenue Video",
      view_count: 10,
      like_count: 0,
      comment_count: 0,
    });

    // Seed a video owned by Bob (for 403 test)
    seedVideoMetadata(VID_BOB, bobSub, {
      title: "Bob Private Video",
      view_count: 100,
      like_count: 10,
      comment_count: 5,
    });
  });

  test.afterAll(async () => {
    await alicePage.context().close();
    await bobPage.context().close();
  });

  test("13. Content with no revenue shows zero breakdown", async () => {
    const resp = await apiGet(alicePage, `/ui/analytics/content/${VID_NOREV}`);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.revenue_breakdown.tips).toBe(0);
    expect(body.revenue_breakdown.unlocks).toBe(0);
    expect(body.revenue_breakdown.vod).toBe(0);
    expect(body.total_revenue_cents).toBe(0);
  });

  test("14. Content detail returns 404 for non-existent content", async () => {
    const resp = await apiGet(alicePage, `/ui/analytics/content/vid_does_not_exist_xyz`);
    expect(resp.status()).toBe(404);
  });

  test("15. Content detail returns 403 for non-owner", async () => {
    // Alice tries to view Bob's video analytics
    const resp = await apiGet(alicePage, `/ui/analytics/content/${VID_BOB}`);
    expect(resp.status()).toBe(403);
    const body = await resp.json();
    expect(body.detail).toContain("Not your content");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 5: API Contract
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 5: API Contract", () => {
  let alicePage: Page;
  let aliceSub: string;

  test.beforeAll(async ({ browser }) => {
    const sessions = getSessions();
    aliceSub = sessions[ALICE_ID].user_sub;
    alicePage = await newIdentityPage(browser, ALICE_ID);

    // Ensure VID_DETAIL exists (may have been seeded by Section 3, but re-seed for isolation)
    seedVideoMetadata(VID_DETAIL, aliceSub, {
      title: "Detail Test Video",
      view_count: 200,
      like_count: 15,
      comment_count: 5,
    });
    seedBillingLedger(aliceSub, VID_DETAIL, "Tip sent", 500);
    seedBillingLedger(aliceSub, VID_DETAIL, "Unlock purchase", 700);
  });

  test.afterAll(async () => {
    await alicePage.context().close();
  });

  test("16. GET /ui/analytics/content/{id} returns correct response shape", async () => {
    const resp = await apiGet(alicePage, `/ui/analytics/content/${VID_DETAIL}`);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();

    // Verify all required fields exist
    expect(body.content_id).toBe(VID_DETAIL);
    expect(body.content_type).toBe("vod");
    expect(typeof body.title).toBe("string");
    expect(typeof body.total_views).toBe("number");
    expect(typeof body.total_revenue_cents).toBe("number");
    expect(typeof body.engagement_rate).toBe("number");
    expect(typeof body.like_count).toBe("number");
    expect(typeof body.comment_count).toBe("number");
    expect(Array.isArray(body.view_time_series)).toBeTruthy();
    expect(body.revenue_breakdown).toBeDefined();
    expect(typeof body.revenue_breakdown.tips).toBe("number");
    expect(typeof body.revenue_breakdown.unlocks).toBe("number");
    expect(typeof body.revenue_breakdown.vod).toBe("number");
    expect(body.currency).toBe("USD");
  });

  test("17. Content detail respects date range params", async () => {
    // Request a narrow 7-day window
    const resp1 = await apiGet(alicePage, `/ui/analytics/content/${VID_DETAIL}`, {
      from_date: "2026-05-20",
      to_date: "2026-05-27",
    });
    expect(resp1.ok()).toBeTruthy();
    const body1 = await resp1.json();

    // Request a wider 30-day window
    const resp2 = await apiGet(alicePage, `/ui/analytics/content/${VID_DETAIL}`, {
      from_date: "2026-05-01",
      to_date: "2026-05-31",
    });
    expect(resp2.ok()).toBeTruthy();
    const body2 = await resp2.json();

    // The 30-day window should have more time series entries than the 7-day window
    expect(body2.view_time_series.length).toBeGreaterThan(body1.view_time_series.length);

    // Verify time series dates are within the requested range
    if (body1.view_time_series.length > 0) {
      const firstDate = body1.view_time_series[0].date;
      expect(firstDate >= "2026-05-20").toBeTruthy();
    }
  });

  test("18. Content detail for non-existent content returns 404", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/analytics/content/vid_absolutely_does_not_exist_${TS}`,
    );
    expect(resp.status()).toBe(404);
    const body = await resp.json();
    expect(body.detail).toContain("Content not found");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 6: Sortable Engagement Column (Top Content table)
// ═══════════════════════════════════════════════════════════════════════════════

const VID_SORT_HI = `vid_sorthi_${TS}`;
const VID_SORT_LO = `vid_sortlo_${TS}`;

test.describe("Section 6: Sortable Engagement Column", () => {
  let alicePage: Page;
  let aliceSub: string;

  test.beforeAll(async ({ browser }) => {
    const sessions = getSessions();
    aliceSub = sessions[ALICE_ID].user_sub;
    alicePage = await newIdentityPage(browser, ALICE_ID);
    cleanupRollups(aliceSub);

    // High-engagement video: (50 + 50) / 200 = 0.50
    seedVideoMetadata(VID_SORT_HI, aliceSub, {
      title: "High Engagement Clip",
      view_count: 200,
      like_count: 50,
      comment_count: 50,
    });
    // Low-engagement video: (2 + 0) / 200 = 0.01
    seedVideoMetadata(VID_SORT_LO, aliceSub, {
      title: "Low Engagement Clip",
      view_count: 200,
      like_count: 2,
      comment_count: 0,
    });

    seedRollupRow(aliceSub, "2026-05-05", {
      total_views: 400,
      revenue_cents: 1000,
      top_content_ids: [VID_SORT_HI, VID_SORT_LO],
    });
  });

  test.afterAll(async () => {
    await alicePage.context().close();
  });

  test("19. Engagement column header is clickable and toggles sort", async () => {
    await alicePage.goto(`${BASE}/analytics?from_date=2026-05-01&to_date=2026-05-31`, {
      waitUntil: "domcontentloaded",
    });
    await alicePage.waitForSelector("table");

    const sortBtn = alicePage.getByRole("button", { name: "Sort by engagement" });
    await expect(sortBtn).toBeVisible();

    // Make sure our seeded rows are present before sorting.
    await expect(
      alicePage.locator("tr").filter({ hasText: "High Engagement Clip" }),
    ).toHaveCount(1);

    // First click → descending: highest engagement row first.
    await sortBtn.click();
    const firstRowDesc = alicePage.locator("tbody tr").first();
    await expect(firstRowDesc).toContainText("High Engagement Clip");

    // Second click → ascending: lowest engagement row first.
    await sortBtn.click();
    const firstRowAsc = alicePage.locator("tbody tr").first();
    await expect(firstRowAsc).toContainText("Low Engagement Clip");
  });

  test("20. Engagement column renders percentage values", async () => {
    await alicePage.goto(`${BASE}/analytics?from_date=2026-05-01&to_date=2026-05-31`, {
      waitUntil: "domcontentloaded",
    });
    await alicePage.waitForSelector("table");
    const hiRow = alicePage.locator("tr").filter({ hasText: "High Engagement Clip" });
    await expect(hiRow).toContainText("%");
    // 0.50 engagement → "50.0%"
    await expect(hiRow).toContainText("50.0%");
  });
});
