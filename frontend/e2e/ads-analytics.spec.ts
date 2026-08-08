/**
 * E2E tests for Ad Analytics Dashboard (ADS-008).
 *
 * Sections:
 *   374 — Summary API (4 tests)
 *   375 — Time Series API (4 tests)
 *   376 — Breakdown API (3 tests)
 *   377 — CSV Export (2 tests)
 *   378 — Dashboard UI (3 tests)
 *
 * Auth: Alice session cookies (from e2e_session_setup.py).
 *
 * Test data: Rollup rows are seeded directly into DynamoDB in beforeAll
 * with deterministic values so assertions are stable.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions, isCpp } from "./helpers/session";
import { cppSeedAdAnalytics } from "./helpers/cpp-seed";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const TS = Date.now();

const ACCOUNT_ID = `adv_analytics_${TS}`;
const CAMPAIGN_ID = `camp_analytics_${TS}`;

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
    _sessions = loadSessions();
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

// ─── API helpers ──────────────────────────────────────────────────────────────

function csrfHeaders(identity = ALICE_ID) {
  return { "x-csrf-token": getSessions()[identity].csrf_token };
}

async function apiGet(page: Page, path: string, identity = ALICE_ID) {
  return page.request.get(`${BASE}${path}`, {
    headers: csrfHeaders(identity),
  });
}

// ─── DDB seed helper ─────────────────────────────────────────────────────────

function seedRollupData() {
  // TRACK harness-seed: under cpp the inline :8001 python seeder below never
  // reaches the C++ backend (it reads tlc_ad_* in its own moto). Seed the
  // equivalent account+rollups+ledger into cpp keyed by ALICE REAL SUB.
  if (isCpp()) {
    const aliceSub = loadSessions()[ALICE_ID]?.user_sub;
    if (!aliceSub) throw new Error("cpp ads-analytics seed: alice sub unresolved");
    cppSeedAdAnalytics({
      accountId: ACCOUNT_ID,
      campaignId: CAMPAIGN_ID,
      ownerSub: aliceSub,
    });
    return;
  }
  // Seed an ad account, then daily rollup items for the last 7 days
  const script = `
import sys, os, json
from datetime import datetime, timedelta, timezone
sys.path.insert(0, os.getcwd())
os.environ.setdefault("DEV_MODE", "1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("DDB_ENDPOINT_URL", "http://localhost:8001")

import boto3
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1")

# Seed ad account
acct_table = ddb.Table("AdAccounts")
acct_table.put_item(Item={
    "pk": "ACCT#${ACCOUNT_ID}",
    "sk": "META",
    "account_id": "${ACCOUNT_ID}",
    "owner_sub": "${ALICE_ID}",
    "company_name": "E2E Analytics Co",
    "billing_email": "ads@test.local",
    "status": "active",
    "balance_cents": 100000,
    "lifetime_spend_cents": 0,
    "created_at": ${Math.floor(TS / 1000)},
    "updated_at": ${Math.floor(TS / 1000)},
})

# Seed daily rollup items
rollup_table = ddb.Table("AdAnalyticsRollups")
now = datetime.now(timezone.utc)

for i in range(7):
    d = now - timedelta(days=6 - i)
    date_str = d.strftime("%Y-%m-%d")
    rollup_table.put_item(Item={
        "pk": f"CAMP#${CAMPAIGN_ID}",
        "sk": f"ROLLUP#daily#{date_str}",
        "campaign_id": "${CAMPAIGN_ID}",
        "account_id": "${ACCOUNT_ID}",
        "period": "daily",
        "date": date_str,
        "impressions": 100,
        "clicks": 5,
        "skips": 2,
        "completes": 80,
        "spend_cents": 50,
        "revenue_cents": 35,
        "unique_users": 50,
        "by_creative": {
            "creative_a": {"impressions": 60, "clicks": 3, "spend_cents": 30},
            "creative_b": {"impressions": 40, "clicks": 2, "spend_cents": 20},
        },
        "by_surface": {
            "newsfeed": {"impressions": 52, "clicks": 3, "spend_cents": 26},
            "broadcast": {"impressions": 28, "clicks": 1, "spend_cents": 14},
            "vod": {"impressions": 20, "clicks": 1, "spend_cents": 10},
        },
        "by_targeting": {
            "interest_tech": {"impressions": 70, "clicks": 4, "spend_cents": 35},
            "geo_us": {"impressions": 30, "clicks": 1, "spend_cents": 15},
        },
        "computed_at": ${Math.floor(TS / 1000)},
    })

# Seed hourly rollup items for today
for h in range(3):
    hour_str = now.strftime("%Y-%m-%dT") + f"{h:02d}"
    rollup_table.put_item(Item={
        "pk": f"CAMP#${CAMPAIGN_ID}",
        "sk": f"ROLLUP#hourly#{hour_str}",
        "campaign_id": "${CAMPAIGN_ID}",
        "account_id": "${ACCOUNT_ID}",
        "period": "hourly",
        "date": hour_str,
        "impressions": 15,
        "clicks": 1,
        "skips": 0,
        "completes": 12,
        "spend_cents": 8,
        "revenue_cents": 5,
        "unique_users": 10,
        "by_creative": {},
        "by_surface": {},
        "by_targeting": {},
        "computed_at": ${Math.floor(TS / 1000)},
    })

# Seed previous period data (7 days before the current 7-day range)
for i in range(7):
    d = now - timedelta(days=13 - i)
    date_str = d.strftime("%Y-%m-%d")
    rollup_table.put_item(Item={
        "pk": f"CAMP#${CAMPAIGN_ID}",
        "sk": f"ROLLUP#daily#{date_str}",
        "campaign_id": "${CAMPAIGN_ID}",
        "account_id": "${ACCOUNT_ID}",
        "period": "daily",
        "date": date_str,
        "impressions": 80,
        "clicks": 4,
        "skips": 3,
        "completes": 60,
        "spend_cents": 40,
        "revenue_cents": 28,
        "unique_users": 40,
        "by_creative": {},
        "by_surface": {},
        "by_targeting": {},
        "computed_at": ${Math.floor(TS / 1000)},
    })

# ─── ADV3-8: the analytics summary + ROAS are now sourced from the ad_billing
# LEDGER (ad_roas.ledger_metrics), NOT AdAnalyticsRollups. Seed matching ledger
# rows so get_summary returns the same impressions/clicks the rollups above hold.
# ledger_metrics reads AdBilling rows keyed pk=ACCT#{id}, sk begins_with LEDGER#,
# counting one impression/click/conversion per entry_type row, filtered by
# campaign_id + created_at window. Current 7d: 700 impressions / 35 clicks;
# previous 7d (days 8..14): 560 impressions / 28 clicks. Spend rides on the click
# rows (10c each) so spend_change_pct is a real, non-degenerate number.
import uuid, time as _time
ad_billing = ddb.Table("AdBilling")
_now_ts = int(_time.time())

def _seed_ledger(day_offset_start, day_offset_end, impr_per_day, click_per_day):
    with ad_billing.batch_writer() as bw:
        for day in range(day_offset_start, day_offset_end):
            # Offset in SECONDS from now (not calendar noon) so every row sits
            # strictly inside its window regardless of wall-clock time of day:
            # get_summary current = [now-7d, now); previous = [now-14d, now-7d).
            # day 0 -> ~12h ago (safely < now and >= now-7d); day 13 -> ~13.5d ago.
            row_ts = _now_ts - day * 86400 - 43200
            for _ in range(impr_per_day):
                eid = uuid.uuid4().hex
                bw.put_item(Item={
                    "pk": "ACCT#${ACCOUNT_ID}",
                    "sk": f"LEDGER#{row_ts}#{eid}",
                    "entry_id": eid,
                    "account_id": "${ACCOUNT_ID}",
                    "campaign_id": "${CAMPAIGN_ID}",
                    "entry_type": "impression_charge",
                    "amount_cents": 0,
                    "created_at": row_ts,
                })
            for _ in range(click_per_day):
                eid = uuid.uuid4().hex
                bw.put_item(Item={
                    "pk": "ACCT#${ACCOUNT_ID}",
                    "sk": f"LEDGER#{row_ts}#{eid}",
                    "entry_id": eid,
                    "account_id": "${ACCOUNT_ID}",
                    "campaign_id": "${CAMPAIGN_ID}",
                    "entry_type": "click_charge",
                    "amount_cents": 10,
                    "created_at": row_ts,
                })

# Current window: days 0..6 (last 7 days) -> 700 impressions, 35 clicks.
_seed_ledger(0, 7, 100, 5)
# Previous window: days 7..13 -> 560 impressions, 28 clicks.
_seed_ledger(7, 14, 80, 4)

print("SEED_OK")
`;
  const result = execSync(`python3 -`, {
    cwd: REPO_ROOT,
    timeout: 30_000,
    input: script,
  }).toString();
  if (!result.includes("SEED_OK")) {
    throw new Error(`Seed failed: ${result}`);
  }
}

// ─── Test setup ───────────────────────────────────────────────────────────────

test.describe("Ad Analytics (ADS-008)", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    // Seed rollup data
    seedRollupData();

    // Create Alice page
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  // ── Section 374: Summary API ────────────────────────────────────────────

  test("374.1 — Get analytics summary", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/ads/analytics/summary?account_id=${ACCOUNT_ID}&days=7`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data).toHaveProperty("impressions");
    expect(data).toHaveProperty("clicks");
    expect(data).toHaveProperty("ctr_pct");
    expect(data.impressions).toBe(700); // 7 days * 100
    expect(data.clicks).toBe(35);       // 7 days * 5
  });

  test("374.2 — Summary includes previous period", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/ads/analytics/summary?account_id=${ACCOUNT_ID}&days=7`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data).toHaveProperty("previous_period");
    expect(data.previous_period).toHaveProperty("impressions");
    expect(data.previous_period).toHaveProperty("clicks");
    expect(data.previous_period).toHaveProperty("spend_cents");
    expect(data.previous_period.impressions).toBe(560); // 7 * 80
  });

  test("374.3 — Summary includes change percentages", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/ads/analytics/summary?account_id=${ACCOUNT_ID}&days=7`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(typeof data.impressions_change_pct).toBe("number");
    expect(typeof data.clicks_change_pct).toBe("number");
    expect(typeof data.spend_change_pct).toBe("number");
    // 700 vs 560 = +25%
    expect(data.impressions_change_pct).toBe(25);
  });

  test("374.4 — Campaign-specific summary", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/ads/analytics/summary?account_id=${ACCOUNT_ID}&campaign_id=${CAMPAIGN_ID}&days=7`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.impressions).toBe(700);
    expect(data.days).toBe(7);
  });

  // ── Section 375: Time Series API ────────────────────────────────────────

  test("375.1 — Get daily time series", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/ads/analytics/timeseries?account_id=${ACCOUNT_ID}&campaign_id=${CAMPAIGN_ID}&days=7&granularity=daily`,
    );
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as Array<Record<string, unknown>>;
    expect(Array.isArray(data)).toBe(true);
    expect(data.length).toBe(7);
  });

  test("375.2 — Each point has required fields", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/ads/analytics/timeseries?account_id=${ACCOUNT_ID}&campaign_id=${CAMPAIGN_ID}&days=7&granularity=daily`,
    );
    const data = (await resp.json()) as Array<Record<string, unknown>>;
    const first = data[0];
    expect(first).toHaveProperty("date");
    expect(first).toHaveProperty("impressions");
    expect(first).toHaveProperty("clicks");
    expect(first).toHaveProperty("spend_cents");
    expect(first).toHaveProperty("ctr_pct");
  });

  test("375.3 — Hourly granularity", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/ads/analytics/timeseries?account_id=${ACCOUNT_ID}&campaign_id=${CAMPAIGN_ID}&days=7&granularity=hourly`,
    );
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as Array<Record<string, unknown>>;
    expect(Array.isArray(data)).toBe(true);
    // We seeded 3 hourly rollups for today
    expect(data.length).toBeGreaterThanOrEqual(3);
    // Hourly dates contain "T" (e.g. "2026-05-29T14")
    expect(String(data[0].date)).toContain("T");
  });

  test("375.4 — Time series sorted by date ascending", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/ads/analytics/timeseries?account_id=${ACCOUNT_ID}&campaign_id=${CAMPAIGN_ID}&days=7&granularity=daily`,
    );
    const data = (await resp.json()) as Array<{ date: string }>;
    for (let i = 1; i < data.length; i++) {
      expect(data[i].date >= data[i - 1].date).toBe(true);
    }
  });

  // ── Section 376: Breakdown API ──────────────────────────────────────────

  test("376.1 — Breakdown by creative", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/ads/analytics/breakdown?account_id=${ACCOUNT_ID}&campaign_id=${CAMPAIGN_ID}&dimension=creative&days=7`,
    );
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as Array<Record<string, unknown>>;
    expect(Array.isArray(data)).toBe(true);
    expect(data.length).toBe(2); // creative_a and creative_b
    const keys = data.map((d) => d.dimension_key);
    expect(keys).toContain("creative_a");
    expect(keys).toContain("creative_b");
  });

  test("376.2 — Breakdown by surface", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/ads/analytics/breakdown?account_id=${ACCOUNT_ID}&campaign_id=${CAMPAIGN_ID}&dimension=surface&days=7`,
    );
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as Array<Record<string, unknown>>;
    const keys = data.map((d) => d.dimension_key);
    expect(keys).toContain("newsfeed");
    expect(keys).toContain("broadcast");
    expect(keys).toContain("vod");
  });

  test("376.3 — Breakdown sorted by impressions descending", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/ads/analytics/breakdown?account_id=${ACCOUNT_ID}&campaign_id=${CAMPAIGN_ID}&dimension=creative&days=7`,
    );
    const data = (await resp.json()) as Array<{ impressions: number }>;
    for (let i = 1; i < data.length; i++) {
      expect(data[i - 1].impressions).toBeGreaterThanOrEqual(data[i].impressions);
    }
    // creative_a should be first (60 * 7 = 420 > 40 * 7 = 280)
    expect((data[0] as Record<string, unknown>).dimension_key).toBe("creative_a");
  });

  // ── Section 377: CSV Export ─────────────────────────────────────────────

  test("377.1 — Export returns CSV", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/ads/analytics/export?account_id=${ACCOUNT_ID}&campaign_id=${CAMPAIGN_ID}&days=7`,
    );
    expect(resp.status()).toBe(200);
    const ct = resp.headers()["content-type"] || "";
    expect(ct).toContain("text/csv");
    const body = await resp.text();
    expect(body.length).toBeGreaterThan(0);
    // Should start with header row
    expect(body.startsWith("date,")).toBe(true);
  });

  test("377.2 — CSV contains expected columns", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/ads/analytics/export?account_id=${ACCOUNT_ID}&campaign_id=${CAMPAIGN_ID}&days=7`,
    );
    const body = await resp.text();
    const headerLine = body.split("\n")[0];
    expect(headerLine).toContain("date");
    expect(headerLine).toContain("impressions");
    expect(headerLine).toContain("clicks");
    expect(headerLine).toContain("ctr_pct");
    expect(headerLine).toContain("spend_cents");
    // Data rows should exist (7 days of data)
    const lines = body.trim().split("\n");
    expect(lines.length).toBe(8); // header + 7 data rows
  });

  // ── Section 378: Dashboard UI ───────────────────────────────────────────

  test("378.1 — Dashboard loads with KPI cards", async () => {
    await alicePage.goto(
      `${BASE}/ads/analytics?account_id=${ACCOUNT_ID}`,
      { waitUntil: "domcontentloaded" },
    );
    await expect(
      alicePage.getByRole("heading", { name: "Ad Analytics Dashboard" }),
    ).toBeVisible();
    // KPI cards should appear (scope to the card label paragraphs to avoid
    // matching the analytics table column headers of the same name)
    await expect(
      alicePage.getByRole("paragraph").filter({ hasText: /^Impressions$/ }),
    ).toBeVisible({ timeout: 10_000 });
    await expect(
      alicePage.getByRole("paragraph").filter({ hasText: /^Clicks$/ }),
    ).toBeVisible();
    await expect(
      alicePage.getByRole("paragraph").filter({ hasText: /^CTR$/ }),
    ).toBeVisible();
    await expect(
      // The ROAS panel also renders a "Spend" paragraph; the KPI card grid comes
      // first in the DOM, so .first() targets the KPI card (avoids strict-mode 2-match).
      alicePage.getByRole("paragraph").filter({ hasText: /^Spend$/ }).first(),
    ).toBeVisible();
  });

  test("378.2 — Date range selector is present", async () => {
    await alicePage.goto(
      `${BASE}/ads/analytics?account_id=${ACCOUNT_ID}`,
      { waitUntil: "domcontentloaded" },
    );
    const selector = alicePage.locator('[data-testid="date-range-select"]');
    await expect(selector).toBeVisible({ timeout: 10_000 });
  });

  test("378.3 — Time series chart container renders", async () => {
    await alicePage.goto(
      `${BASE}/ads/analytics?account_id=${ACCOUNT_ID}`,
      { waitUntil: "domcontentloaded" },
    );
    const chart = alicePage.locator('[data-testid="analytics-chart"]');
    await expect(chart).toBeVisible({ timeout: 10_000 });
  });
});
