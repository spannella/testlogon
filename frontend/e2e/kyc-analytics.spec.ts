/**
 * E2E tests for KYC-024 — KYC Analytics & Funnel Dashboard.
 *
 * Sections:
 *   237 — Analytics API (funnel, trends, processing-times, rejection-reasons, screening-hits, auth)
 *   238 — Comparison & Geographic API (compare, geographic, drop-off, snapshot, empty, invalid range)
 *   239 — Analytics Dashboard UI (page load, filters, comparison, granularity)
 *   240 — Pre-computation & edge cases (snapshot precompute, max periods, zero cases, concurrency)
 *
 * Auth: e2e_admin_session_setup.py (root, alice, bob, charlie_admin).
 * Cases are seeded directly into the kyc_cases DDB table for deterministic,
 * date-controlled scenarios under a unique per-run cohort tag.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ──────────────────────────────────────────────────────────────

const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();
const NOW = Math.floor(Date.now() / 1000);
// A tight window around "recent" cases for this run so we don't aggregate the
// whole table. All seeded cases fall within [WIN_FROM, WIN_TO].
const WIN_FROM = NOW - 5 * 86400;
const WIN_TO = NOW + 86400;

// ─── Session bootstrap ──────────────────────────────────────────────────────

interface SessionData {
  user_sub: string;
  csrf_token: string;
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

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const sub = sessions[identity].user_sub;
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  // ProtectedRoute gates on the zustand auth store (localStorage), not cookies,
  // so the UI tests need it seeded or they redirect to /login.
  await page.addInitScript((uid: string) => {
    localStorage.setItem(
      "auth-store",
      JSON.stringify({ state: { userId: uid, accessToken: null, isAuthenticated: true }, version: 0 }),
    );
  }, sub);
  return page;
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}${path}`, { params });
}

// ─── DDB prelude ────────────────────────────────────────────────────────────

const DDB_PRELUDE = `
import boto3, os, time, json
from pathlib import Path
env_file = Path('${REPO_ROOT}/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
`;

function runPy(body: string, extraEnv: Record<string, string> = {}): string {
  // Pass the program via stdin (not -c) so embedded JSON/quotes can't collide
  // with shell quoting; large payloads come in via env vars.
  return execSync(`python3 -`, {
    cwd: REPO_ROOT,
    timeout: 20_000,
    input: `${DDB_PRELUDE}${body}`,
    env: { ...process.env, ...extraEnv },
  }).toString();
}

interface SeedCase {
  status: string;
  intake?: string; // basic | standard | enhanced
  country?: string;
  reason?: string;
  createdAt: number;
  submittedAt?: number;
  decidedAt?: number;
}

/** Seed KYC cases directly into the kyc_cases table. */
function seedCases(cases: SeedCase[]): void {
  runPy(`
tbl = ddb.Table(os.environ.get('KYC_CASES_TABLE_NAME','kyc_cases'))
cohort = '${TS}'
cases = json.loads(os.environ['DDB_CASES'])
for i, c in enumerate(cases):
    cid = f'kyc_an{cohort}_{i}'
    ts = int(c['createdAt'])
    review = {'reason_codes': [c['reason']] if c.get('reason') else [], 'decided_at': c.get('decidedAt')}
    submission = {'submitted_at': c.get('submittedAt'), 'evidence_snapshot': {}, 'evidence_hash': None}
    item = {
        'pk': 'KYC#' + cid, 'sk': 'META', 'entity_type': 'kyc_case', 'kyc_case_id': cid,
        'user_sub': f'an_{cohort}_{i}@test.local', 'status': c['status'],
        'intake_profile': c.get('intake') or 'basic',
        'country': c.get('country'),
        'questionnaire': {}, 'files': [], 'signature': {},
        'submission': submission, 'review': review,
        'created_at': ts, 'updated_at': ts, 'version': 1,
        'gsi_owner_pk': 'OWNER#an_' + cohort + '_' + str(i),
        'gsi_owner_sk': f'UPDATED#{ts:013d}#KYC#' + cid,
        'gsi_status_pk': 'STATUS#' + c['status'],
        'gsi_status_sk': f'UPDATED#{ts:013d}#KYC#' + cid,
    }
    # DynamoDB rejects empty-string GSI/attr values; drop None country.
    if item['country'] is None:
        del item['country']
    tbl.put_item(Item=item)
print('seeded', len(cases))
`, { DDB_CASES: JSON.stringify(cases) });
}

// ─── Shared pages + seed ────────────────────────────────────────────────────

let rootPage: Page;
let alicePage: Page;

test.beforeAll(async ({ browser }) => {
  getSessions();
  rootPage = await newIdentityPage(browser, "root");
  alicePage = await newIdentityPage(browser, "alice");

  const day = (n: number) => NOW - n * 86400;
  seedCases([
    // approved cases (with processing times)
    { status: "approved", country: "SE", intake: "basic", createdAt: day(3), submittedAt: day(3), decidedAt: day(3) + 7200 },
    { status: "approved", country: "DE", intake: "standard", createdAt: day(2), submittedAt: day(2), decidedAt: day(2) + 3600 },
    { status: "approved", country: "SE", intake: "basic", createdAt: day(1), submittedAt: day(1), decidedAt: day(1) + 14400 },
    // rejected cases with reasons
    { status: "rejected", country: "SE", intake: "basic", createdAt: day(2), reason: "expired_id" },
    { status: "rejected", country: "DE", intake: "enhanced", createdAt: day(1), reason: "suspicious_identity" },
    // pending
    { status: "submitted", country: "DE", intake: "standard", createdAt: day(1) },
    { status: "under_review", country: "SE", intake: "enhanced", createdAt: day(1) },
    // draft (started but not submitted)
    { status: "draft", country: "US", intake: "basic", createdAt: day(2) },
  ]);
});

test.afterAll(async () => {
  await rootPage?.close();
  await alicePage?.close();
  try {
    runPy(`
tbl = ddb.Table(os.environ.get('KYC_CASES_TABLE_NAME','kyc_cases'))
for i in range(20):
    tbl.delete_item(Key={'pk': 'KYC#kyc_an${TS}_' + str(i), 'sk': 'META'})
print('cleaned')
`);
  } catch {
    /* best-effort */
  }
});

const RANGE = { from: String(WIN_FROM), to: String(WIN_TO) };

// ─── 237. Analytics API ─────────────────────────────────────────────────────

test.describe("237. KYC-024 Analytics API", () => {
  test("237.1 Get funnel returns steps with counts", async () => {
    const r = await apiGet(rootPage, "/v1/kyc/analytics/funnel", RANGE);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      funnel: Array<{ step: string; count: number; percentage: number }>;
      conversion_rate: number;
    };
    expect(Array.isArray(data.funnel)).toBe(true);
    const steps = data.funnel.map((s) => s.step);
    expect(steps).toContain("started");
    expect(steps).toContain("approved");
    const started = data.funnel.find((s) => s.step === "started")!;
    expect(started.count).toBeGreaterThanOrEqual(8);
    expect(started.percentage).toBe(100);
    const approved = data.funnel.find((s) => s.step === "approved")!;
    expect(approved.count).toBeGreaterThanOrEqual(3);
    expect(data.conversion_rate).toBeGreaterThan(0);
  });

  test("237.2 Funnel filtered by tier", async () => {
    const r = await apiGet(rootPage, "/v1/kyc/analytics/funnel", { ...RANGE, tier: "tier_3" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { funnel: Array<{ step: string; count: number }> };
    const started = data.funnel.find((s) => s.step === "started")!;
    // Only enhanced-profile cases map to tier_3 (2 seeded: rejected + under_review).
    expect(started.count).toBeGreaterThanOrEqual(2);
    expect(started.count).toBeLessThan(8);
  });

  test("237.3 Volume trends returns time series", async () => {
    const r = await apiGet(rootPage, "/v1/kyc/analytics/trends", {
      granularity: "daily",
      periods: "7",
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { trends: Array<{ period: string; started: number }> };
    expect(data.trends.length).toBe(7);
    expect(data.trends[0]).toHaveProperty("period");
    expect(data.trends[0]).toHaveProperty("started");
    expect(data.trends[0]).toHaveProperty("approved");
  });

  test("237.4 Processing time histogram returns buckets", async () => {
    const r = await apiGet(rootPage, "/v1/kyc/analytics/processing-times", RANGE);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      histogram: Array<{ bucket_label: string; count: number }>;
      percentiles: { p50: number; p75: number; p90: number; p99: number };
    };
    expect(data.histogram.length).toBeGreaterThan(0);
    expect(data.histogram[0]).toHaveProperty("bucket_label");
    expect(data.percentiles).toHaveProperty("p50");
    expect(data.percentiles).toHaveProperty("p99");
    // Three approved cases have processing times (1h, 2h, 4h).
    const totalBucketed = data.histogram.reduce((s, b) => s + b.count, 0);
    expect(totalBucketed).toBeGreaterThanOrEqual(3);
  });

  test("237.5 Rejection reasons returns reason code counts", async () => {
    const r = await apiGet(rootPage, "/v1/kyc/analytics/rejection-reasons", RANGE);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { reasons: Record<string, number> };
    expect(data.reasons.expired_id).toBeGreaterThanOrEqual(1);
    expect(data.reasons.suspicious_identity).toBeGreaterThanOrEqual(1);
  });

  test("237.6 Non-admin cannot access analytics", async () => {
    const r = await apiGet(alicePage, "/v1/kyc/analytics/funnel", RANGE);
    expect(r.status()).toBe(403);
  });

  test("237.7 Screening hits trend returns data", async () => {
    const r = await apiGet(rootPage, "/v1/kyc/analytics/screening-hits", {
      granularity: "daily",
      periods: "7",
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      trends: Array<{ period: string; total_screened: number; hits: number; hit_rate: number }>;
    };
    expect(data.trends.length).toBe(7);
    expect(data.trends[0]).toHaveProperty("total_screened");
    expect(data.trends[0]).toHaveProperty("hits");
    expect(data.trends[0]).toHaveProperty("hit_rate");
  });
});

// ─── 238. Comparison & Geographic API ───────────────────────────────────────

test.describe("238. KYC-024 Comparison & Geographic API", () => {
  test("238.1 Compare periods returns current, previous, and deltas", async () => {
    const r = await apiGet(rootPage, "/v1/kyc/analytics/compare", {
      current_from: String(WIN_FROM),
      current_to: String(WIN_TO),
      previous_from: String(WIN_FROM - 30 * 86400),
      previous_to: String(WIN_FROM),
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      current: { total_applications: number };
      previous: { total_applications: number };
      deltas: { volume_delta: number };
    };
    expect(data.current.total_applications).toBeGreaterThanOrEqual(8);
    expect(data.previous).toHaveProperty("total_applications");
    expect(data.deltas).toHaveProperty("volume_delta");
    expect(data.deltas).toHaveProperty("conversion_rate_delta");
  });

  test("238.2 Geographic distribution returns country breakdown", async () => {
    const r = await apiGet(rootPage, "/v1/kyc/analytics/geographic", RANGE);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      countries: Array<{ country: string; count: number; approval_rate: number }>;
    };
    const se = data.countries.find((c) => c.country === "SE");
    expect(se).toBeTruthy();
    expect(se!.count).toBeGreaterThanOrEqual(3);
    expect(se).toHaveProperty("approval_rate");
  });

  test("238.3 Drop-off analysis shows loss between steps", async () => {
    const r = await apiGet(rootPage, "/v1/kyc/analytics/drop-off", RANGE);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      steps: Array<{ from_step: string; to_step: string; continued: number; dropped: number; drop_rate: number }>;
    };
    expect(data.steps.length).toBeGreaterThan(0);
    expect(data.steps[0]).toHaveProperty("from_step");
    expect(data.steps[0]).toHaveProperty("to_step");
    expect(data.steps[0]).toHaveProperty("drop_rate");
  });

  test("238.4 Snapshot returns full analytics summary", async () => {
    const r = await apiGet(rootPage, "/v1/kyc/analytics/snapshot", RANGE);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      snapshot: {
        funnel: unknown[];
        conversion_rate: number;
        processing_time_distribution: { p50: number };
        geographic_distribution: unknown[];
        tier_breakdown: Record<string, unknown>;
        rejection_reasons: Record<string, number>;
      };
    };
    expect(data.snapshot.funnel.length).toBeGreaterThan(0);
    expect(data.snapshot).toHaveProperty("conversion_rate");
    expect(data.snapshot.processing_time_distribution).toHaveProperty("p50");
    expect(data.snapshot.geographic_distribution.length).toBeGreaterThan(0);
    expect(Object.keys(data.snapshot.tier_breakdown).length).toBeGreaterThan(0);
  });

  test("238.5 Empty date range returns zero counts", async () => {
    const future = NOW + 365 * 86400;
    const r = await apiGet(rootPage, "/v1/kyc/analytics/funnel", {
      from: String(future),
      to: String(future + 86400),
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      funnel: Array<{ count: number }>;
      conversion_rate: number;
    };
    expect(data.funnel.every((s) => s.count === 0)).toBe(true);
    expect(data.conversion_rate).toBe(0);
  });

  test("238.6 Invalid date range (from > to) returns 400", async () => {
    const r = await apiGet(rootPage, "/v1/kyc/analytics/funnel", {
      from: "9999999999",
      to: "1000000",
    });
    expect(r.status()).toBe(400);
  });
});

// ─── 239. Analytics Dashboard UI ────────────────────────────────────────────

test.describe("239. KYC-024 Analytics Dashboard UI", () => {
  test("239.1 Dashboard page loads with funnel chart", async () => {
    await rootPage.goto("http://localhost:3000/admin/kyc/analytics");
    await expect(rootPage.getByTestId("kyc-analytics-heading")).toBeVisible({ timeout: 15_000 });
    await expect(rootPage.getByTestId("funnel-chart")).toBeVisible({ timeout: 15_000 });
    await expect(rootPage.getByTestId("funnel-label-started")).toBeVisible();
  });

  test("239.2 Date range filter updates chart data", async () => {
    await rootPage.goto("http://localhost:3000/admin/kyc/analytics");
    await expect(rootPage.getByTestId("kyc-analytics-heading")).toBeVisible({ timeout: 15_000 });
    const respPromise = rootPage.waitForResponse(
      (r) => r.url().includes("/v1/kyc/analytics/funnel") && r.request().method() === "GET",
    );
    await rootPage.getByTestId("range-7d").click();
    const resp = await respPromise;
    expect(resp.status()).toBe(200);
  });

  test("239.3 Country filter narrows results", async () => {
    await rootPage.goto("http://localhost:3000/admin/kyc/analytics");
    await expect(rootPage.getByTestId("kyc-analytics-heading")).toBeVisible({ timeout: 15_000 });
    const respPromise = rootPage.waitForResponse(
      (r) => r.url().includes("/v1/kyc/analytics/funnel") && r.url().includes("country=SE"),
    );
    await rootPage.getByTestId("filter-country").click();
    await rootPage.getByRole("option", { name: /SE/ }).click();
    const resp = await respPromise;
    expect(resp.status()).toBe(200);
  });

  test("239.4 Comparison mode shows previous period overlay", async () => {
    await rootPage.goto("http://localhost:3000/admin/kyc/analytics");
    await expect(rootPage.getByTestId("kyc-analytics-heading")).toBeVisible({ timeout: 15_000 });
    await rootPage.getByTestId("compare-toggle").check();
    await expect(rootPage.getByTestId("period-comparison-cards")).toBeVisible({ timeout: 15_000 });
    await expect(rootPage.getByTestId("compare-conversion")).toBeVisible();
  });

  test("239.5 Granularity toggle changes trend chart", async () => {
    await rootPage.goto("http://localhost:3000/admin/kyc/analytics");
    await expect(rootPage.getByTestId("kyc-analytics-heading")).toBeVisible({ timeout: 15_000 });
    const respPromise = rootPage.waitForResponse(
      (r) => r.url().includes("/v1/kyc/analytics/trends") && r.url().includes("granularity=weekly"),
    );
    await rootPage.getByTestId("granularity-weekly").click();
    const resp = await respPromise;
    expect(resp.status()).toBe(200);
  });
});

// ─── 240. Pre-computation & edge cases ──────────────────────────────────────

test.describe("240. KYC-024 Pre-computation & edge cases", () => {
  test("240.1 Precomputed snapshot can be stored and retrieved", async () => {
    // Trigger precomputation for a specific date via the service, then verify
    // the DDB item exists with a computed_at timestamp.
    const dateIso = new Date((NOW - 2 * 86400) * 1000).toISOString().slice(0, 10);
    const out = runPy(`
import sys
sys.path.insert(0, '${REPO_ROOT}')
from app.services.kyc_analytics import ANALYTICS_SERVICE
ANALYTICS_SERVICE.precompute_daily_snapshot(date_iso='${dateIso}')
snap = ANALYTICS_SERVICE.get_daily_snapshot(date_iso='${dateIso}')
print('OK' if snap and snap.get('computed_at') else 'MISSING')
`);
    expect(out.trim().endsWith("OK")).toBe(true);
  });

  test("240.2 Trends max periods enforced", async () => {
    const r = await apiGet(rootPage, "/v1/kyc/analytics/trends", {
      granularity: "daily",
      periods: "100",
    });
    expect(r.status()).toBe(400);
  });

  test("240.3 Analytics with zero cases returns valid empty structure", async () => {
    const future = NOW + 500 * 86400;
    const r = await apiGet(rootPage, "/v1/kyc/analytics/snapshot", {
      from: String(future),
      to: String(future + 86400),
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      snapshot: {
        total_applications: number;
        conversion_rate: number;
        geographic_distribution: unknown[];
        rejection_reasons: Record<string, number>;
      };
    };
    expect(data.snapshot.total_applications).toBe(0);
    expect(data.snapshot.conversion_rate).toBe(0);
    expect(data.snapshot.geographic_distribution).toEqual([]);
    expect(Object.keys(data.snapshot.rejection_reasons)).toEqual([]);
  });

  test("240.4 Multiple concurrent analytics queries return consistent data", async () => {
    const results = await Promise.all([
      apiGet(rootPage, "/v1/kyc/analytics/funnel", RANGE),
      apiGet(rootPage, "/v1/kyc/analytics/snapshot", RANGE),
      apiGet(rootPage, "/v1/kyc/analytics/trends", { granularity: "daily", periods: "7" }),
      apiGet(rootPage, "/v1/kyc/analytics/geographic", RANGE),
      apiGet(rootPage, "/v1/kyc/analytics/rejection-reasons", RANGE),
    ]);
    for (const r of results) {
      expect(r.status()).toBe(200);
    }
  });
});
