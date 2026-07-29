/**
 * E2E tests for Engagement Rate Calculation (FIN-012).
 *
 * Sections:
 *   583 — Engagement Rate Calculation API (5 tests)
 *   584 — Engagement Time Series API (3 tests)
 *   585 — Benchmarks / Public Profile API (4 tests)
 *   586 — Engagement UI (4 tests)
 *   587 — Engagement Edge Cases (5 tests)
 *
 * Engagement rate is computed deterministically from REAL data:
 *   rate = total_interactions / (followers * posts_in_period) * 100
 * where total_interactions = likes + comments + shares + tips.
 *
 * Stored/returned in basis points (bps) too; capped at 100%; zero-safe.
 *
 * Auth: cookie-based session for Alice (creator) with CSRF.
 */

import { tmpdir } from "os";
import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import { writeFileSync, unlinkSync } from "fs";
import * as path from "path";
import { loadSessions, unauthContext } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
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
  return page.request.get(`${BASE}${path}`);
}

async function apiPut(page: Page, userId: string, path: string, body?: object) {
  const session = getSessions()[userId];
  return page.request.put(`${BASE}${path}`, {
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
profiles = ddb.Table(os.environ.get('PROFILE_TABLE_NAME', 'profiles'))
`;

function seedEngagementRow(
  userSub: string,
  dateStr: string,
  data: Record<string, number>,
): void {
  const tmpFile = `${tmpdir()}/eng_seed_${Date.now()}_${Math.random().toString(36).slice(2)}.json`;
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
    item[k] = int(v)
tbl.put_item(Item=item)
print('seeded', '${dateStr}')
"`,
      { timeout: 10_000 },
    );
  } finally {
    try { unlinkSync(tmpFile); } catch {}
  }
}

function setFollowerCount(userSub: string, count: number): void {
  execSync(
    `${PYTHON} -c "
${DDB_PRELUDE}
profiles.update_item(
    Key={'user_sub': '${userSub}'},
    UpdateExpression='SET follower_count = :c',
    ExpressionAttributeValues={':c': ${count}},
)
print('followers', ${count})
"`,
    { timeout: 10_000 },
  );
}

function setSummaryPublic(userSub: string, visible: boolean): void {
  execSync(
    `${PYTHON} -c "
${DDB_PRELUDE}
tbl.update_item(
    Key={'pk': 'CREATOR#${userSub}', 'sk': 'SUMMARY'},
    UpdateExpression='SET show_engagement_public = :v, updated_at = :now',
    ExpressionAttributeValues={':v': ${visible ? "True" : "False"}, ':now': int(time.time())},
)
print('public', '${visible}')
"`,
    { timeout: 10_000 },
  );
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
print('cleaned', len(resp.get('Items', [])))
"`,
      { timeout: 10_000 },
    );
  } catch {
    // ignore
  }
}

// ─── Date helpers (UTC, matching backend) ────────────────────────────────────

function utcDaysAgo(n: number): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - n);
  return d.toISOString().slice(0, 10);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 583: Engagement Rate Calculation API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("583 — Engagement Rate Calculation API", () => {
  let page: Page;
  let aliceSub: string;

  test.beforeAll(async ({ browser }) => {
    aliceSub = getSessions()[ALICE_ID].user_sub;
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);

    cleanupRollups(aliceSub);
    setFollowerCount(aliceSub, 1000);
    // Seed 5 recent days with likes/comments/shares/tips and post_count.
    for (let i = 1; i <= 5; i++) {
      seedEngagementRow(aliceSub, utcDaysAgo(i), {
        engagement_likes: 100,
        engagement_comments: 40,
        engagement_shares: 0,
        engagement_tips: 10,
        post_count: 2,
        total_interactions: 150,
        follower_snapshot: 1000,
      });
    }
  });

  test.afterAll(async () => {
    cleanupRollups(aliceSub);
    await page.close();
  });

  test("583.1 — engagement rate for creator with posts is > 0", async () => {
    const resp = await apiGet(page, "/ui/analytics/engagement?period_days=30");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    // interactions = 5*150 = 750; posts = 10; followers = 1000
    // rate = 750 / (1000*10) * 100 = 7.5%
    expect(body.engagement_rate).toBeGreaterThan(0);
    expect(body.engagement_rate_bps).toBeGreaterThan(0);
    expect(body.total_interactions).toBe(750);
    expect(body.posts_in_period).toBe(10);
    expect(body.follower_count).toBe(1000);
    expect(body.engagement_rate).toBeCloseTo(7.5, 1);
  });

  test("583.2 — engagement includes tip interactions", async () => {
    const resp = await apiGet(page, "/ui/analytics/engagement?period_days=30");
    const body = await resp.json();
    expect(body.tips).toBe(50); // 5 days * 10
    expect(body.likes).toBe(500);
    expect(body.comments).toBe(200);
  });

  test("583.3 — rate is zero with no followers (no div-by-zero)", async () => {
    const bobSub = getSessions()[BOB_ID].user_sub;
    cleanupRollups(bobSub);
    setFollowerCount(bobSub, 0);
    seedEngagementRow(bobSub, utcDaysAgo(1), {
      engagement_likes: 100,
      engagement_comments: 50,
      post_count: 3,
      total_interactions: 150,
      follower_snapshot: 0,
    });
    const bobPage = await page.context().browser()!.newPage();
    await injectAuth(bobPage, BOB_ID);
    const resp = await apiGet(bobPage, "/ui/analytics/engagement?period_days=30");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.engagement_rate).toBe(0.0);
    expect(body.engagement_rate_bps).toBe(0);
    await bobPage.close();
    cleanupRollups(bobSub);
  });

  test("583.4 — period selector changes calculation window", async () => {
    // Seed an older day (20 days ago) so 7d excludes it but 30d includes it.
    seedEngagementRow(aliceSub, utcDaysAgo(20), {
      engagement_likes: 500,
      engagement_comments: 0,
      post_count: 1,
      total_interactions: 500,
      follower_snapshot: 1000,
    });
    const r7 = await apiGet(page, "/ui/analytics/engagement?period_days=7");
    const r30 = await apiGet(page, "/ui/analytics/engagement?period_days=30");
    const b7 = await r7.json();
    const b30 = await r30.json();
    expect(b7.total_interactions).not.toBe(b30.total_interactions);
    expect(b30.total_interactions).toBeGreaterThan(b7.total_interactions);
  });

  test("583.5 — invalid period_days returns 422", async () => {
    const resp = await apiGet(page, "/ui/analytics/engagement?period_days=13");
    expect(resp.status()).toBe(422);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 584: Engagement Time Series API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("584 — Engagement Time Series API", () => {
  let page: Page;
  let aliceSub: string;

  test.beforeAll(async ({ browser }) => {
    aliceSub = getSessions()[ALICE_ID].user_sub;
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);

    cleanupRollups(aliceSub);
    setFollowerCount(aliceSub, 1000);
    for (let i = 1; i <= 4; i++) {
      seedEngagementRow(aliceSub, utcDaysAgo(i), {
        engagement_likes: 50 * i,
        engagement_comments: 10,
        post_count: 1,
        total_interactions: 50 * i + 10,
        follower_snapshot: 1000,
      });
    }
  });

  test.afterAll(async () => {
    cleanupRollups(aliceSub);
    await page.close();
  });

  test("584.1 — time series returns engagement data points", async () => {
    const from = utcDaysAgo(7);
    const to = utcDaysAgo(0);
    const resp = await apiGet(
      page,
      `/ui/analytics/engagement/history?from_date=${from}&to_date=${to}`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.items)).toBe(true);
    expect(body.items.length).toBeGreaterThanOrEqual(4);
    for (const it of body.items) {
      expect(it).toHaveProperty("date");
      expect(it).toHaveProperty("engagement_rate");
      expect(it).toHaveProperty("interactions");
    }
  });

  test("584.2 — time series filters by date range", async () => {
    // Narrow range to only the 2 most recent days.
    const from = utcDaysAgo(2);
    const to = utcDaysAgo(1);
    const resp = await apiGet(
      page,
      `/ui/analytics/engagement/history?from_date=${from}&to_date=${to}`,
    );
    const body = await resp.json();
    expect(body.items.length).toBeLessThanOrEqual(2);
    for (const it of body.items) {
      expect(it.date >= from && it.date <= to).toBe(true);
    }
  });

  test("584.3 — items are sorted ascending by date", async () => {
    const from = utcDaysAgo(7);
    const to = utcDaysAgo(0);
    const resp = await apiGet(
      page,
      `/ui/analytics/engagement/history?from_date=${from}&to_date=${to}`,
    );
    const body = await resp.json();
    const dates = body.items.map((i: { date: string }) => i.date);
    const sorted = [...dates].sort();
    expect(dates).toEqual(sorted);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 585: Public Profile API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("585 — Public Profile API", () => {
  let page: Page;
  let aliceSub: string;

  test.beforeAll(async ({ browser }) => {
    aliceSub = getSessions()[ALICE_ID].user_sub;
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);

    cleanupRollups(aliceSub);
    setFollowerCount(aliceSub, 1000);
    for (let i = 1; i <= 5; i++) {
      seedEngagementRow(aliceSub, utcDaysAgo(i), {
        engagement_likes: 100,
        engagement_comments: 40,
        engagement_tips: 10,
        post_count: 2,
        total_interactions: 150,
        follower_snapshot: 1000,
      });
    }
  });

  test.afterAll(async () => {
    cleanupRollups(aliceSub);
    await page.close();
  });

  test("585.1 — toggle public engagement on returns 200", async () => {
    const resp = await apiPut(page, ALICE_ID, "/ui/analytics/engagement/public", {
      visible: true,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.visible).toBe(true);
    expect(body.engagement_rate_30d).toBeGreaterThan(0);
  });

  test("585.2 — public endpoint returns rate when enabled", async () => {
    setSummaryPublic(aliceSub, true);
    const resp = await apiGet(
      page,
      `/api/creators/${encodeURIComponent(aliceSub)}/engagement`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.engagement_rate_30d).toBeGreaterThan(0);
    expect(body.visible).toBe(true);
  });

  test("585.3 — public endpoint 404 when disabled", async () => {
    setSummaryPublic(aliceSub, false);
    const resp = await apiGet(
      page,
      `/api/creators/${encodeURIComponent(aliceSub)}/engagement`,
    );
    expect(resp.status()).toBe(404);
  });

  test("585.4 — toggle off returns visible=false", async () => {
    const resp = await apiPut(page, ALICE_ID, "/ui/analytics/engagement/public", {
      visible: false,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.visible).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 586: Engagement UI
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("586 — Engagement UI", () => {
  let page: Page;
  let aliceSub: string;

  test.beforeAll(async ({ browser }) => {
    aliceSub = getSessions()[ALICE_ID].user_sub;
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);

    cleanupRollups(aliceSub);
    setFollowerCount(aliceSub, 1000);
    for (let i = 1; i <= 5; i++) {
      seedEngagementRow(aliceSub, utcDaysAgo(i), {
        engagement_likes: 100,
        engagement_comments: 40,
        engagement_tips: 10,
        post_count: 2,
        total_interactions: 150,
        follower_snapshot: 1000,
      });
    }
  });

  test.afterAll(async () => {
    cleanupRollups(aliceSub);
    await page.close();
  });

  test("586.1 — engagement section visible on analytics dashboard", async () => {
    await page.goto(`${BASE}/analytics`, { waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("engagement-section")).toBeVisible({ timeout: 15000 });
    await expect(page.getByText("Engagement Rate", { exact: true })).toBeVisible();
  });

  test("586.2 — engagement rate displays as percentage", async () => {
    await page.goto(`${BASE}/analytics`, { waitUntil: "domcontentloaded" });
    const value = page.getByTestId("engagement-rate-value");
    await expect(value).toBeVisible({ timeout: 15000 });
    await expect(value).toContainText("%");
  });

  test("586.3 — trend indicator is visible", async () => {
    await page.goto(`${BASE}/analytics`, { waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("engagement-rate-value")).toBeVisible({ timeout: 15000 });
    await expect(page.getByTestId("engagement-trend")).toBeVisible();
  });

  test("586.4 — public profile toggle is present", async () => {
    await page.goto(`${BASE}/analytics`, { waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("engagement-public-toggle")).toBeVisible({ timeout: 15000 });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 587: Engagement Edge Cases
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("587 — Engagement Edge Cases", () => {
  let page: Page;
  let aliceSub: string;

  test.beforeAll(async ({ browser }) => {
    aliceSub = getSessions()[ALICE_ID].user_sub;
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
  });

  test.afterAll(async () => {
    cleanupRollups(aliceSub);
    await page.close();
  });

  test("587.1 — creator with 0 posts gets rate 0", async () => {
    cleanupRollups(aliceSub);
    setFollowerCount(aliceSub, 1000);
    // Seed a day with interactions but post_count 0.
    seedEngagementRow(aliceSub, utcDaysAgo(1), {
      engagement_likes: 50,
      engagement_comments: 20,
      post_count: 0,
      total_interactions: 70,
      follower_snapshot: 1000,
    });
    const resp = await apiGet(page, "/ui/analytics/engagement?period_days=30");
    const body = await resp.json();
    expect(body.posts_in_period).toBe(0);
    expect(body.engagement_rate).toBe(0.0);
  });

  test("587.2 — empty data returns 200 with zero rate", async () => {
    cleanupRollups(aliceSub);
    setFollowerCount(aliceSub, 1000);
    const resp = await apiGet(page, "/ui/analytics/engagement?period_days=30");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.engagement_rate).toBe(0.0);
    expect(body.total_interactions).toBe(0);
  });

  test("587.3 — engagement rate capped at 100%", async () => {
    cleanupRollups(aliceSub);
    setFollowerCount(aliceSub, 10);
    // Far more interactions than followers*posts -> would exceed 100%.
    seedEngagementRow(aliceSub, utcDaysAgo(1), {
      engagement_likes: 10000,
      engagement_comments: 5000,
      post_count: 1,
      total_interactions: 15000,
      follower_snapshot: 10,
    });
    const resp = await apiGet(page, "/ui/analytics/engagement?period_days=30");
    const body = await resp.json();
    expect(body.engagement_rate).toBeLessThanOrEqual(100.0);
    expect(body.engagement_rate_bps).toBeLessThanOrEqual(10000);
    expect(body.engagement_rate).toBe(100.0);
  });

  test("587.4 — another creator cannot read alice's engagement (self-scoped)", async () => {
    cleanupRollups(aliceSub);
    setFollowerCount(aliceSub, 1000);
    seedEngagementRow(aliceSub, utcDaysAgo(1), {
      engagement_likes: 200,
      engagement_comments: 50,
      post_count: 2,
      total_interactions: 250,
      follower_snapshot: 1000,
    });
    const bobSub = getSessions()[BOB_ID].user_sub;
    cleanupRollups(bobSub);
    setFollowerCount(bobSub, 1000);
    const bobPage = await page.context().browser()!.newPage();
    await injectAuth(bobPage, BOB_ID);
    // Bob's own engagement endpoint returns Bob's data (no rollups) -> 0,
    // confirming the endpoint is scoped to the caller, not Alice.
    const resp = await apiGet(bobPage, "/ui/analytics/engagement?period_days=30");
    const body = await resp.json();
    expect(body.total_interactions).toBe(0);
    expect(body.engagement_rate).toBe(0.0);
    await bobPage.close();
    cleanupRollups(bobSub);
  });

  test("587.5 — unauthenticated request returns 401", async () => {
    const anon = await unauthContext(BASE);
    const resp = await anon.get(
      `/ui/analytics/engagement?period_days=30`,
    );
    expect(resp.status()).toBe(401);
    await anon.dispose();
  });
});
