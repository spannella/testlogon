/**
 * E2E tests for KYC-016 — Ongoing Monitoring & Periodic Review.
 *
 * Section 750: Review Schedule API (user + admin schedule, frequency by tier)
 * Section 751: Trigger Events API (manual trigger flags case, list, validation)
 * Section 752: Review Checker & Re-screening API (grace period, downgrade, rescreen)
 * Section 753: Monitoring Dashboard API + auth (admin-only / 401)
 *
 * Auth strategy mirrors admin-roles.spec.ts: role-bearing JWT cookies created by
 * e2e_admin_session_setup.py. Review schedules are seeded directly into the
 * kyc_review_schedule DDB table for deterministic past-date scenarios.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
import { usingCpp } from "./helpers/cpp-seed";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ─────────────────────────────────────────────────────────────────

const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const TS = Date.now();

// Isolated synthetic users seeded only in DDB (never logged in) so downgrade /
// rescreening side effects don't affect the shared real test identities.
const SCHED_USER = `e2e_kyc016_sched_${TS}@test.local`;
const TRIG_USER = `e2e_kyc016_trig_${TS}@test.local`;
const GRACE_USER = `e2e_kyc016_grace_${TS}@test.local`;
const DOWNGRADE_USER = `e2e_kyc016_down_${TS}@test.local`;
const FLAGGED_USER = `e2e_kyc016_flagged_${TS}@test.local`;
const UPCOMING_USER = `e2e_kyc016_up_${TS}@test.local`;

// ─── Session bootstrap (same as admin-roles.spec.ts) ────────────────────────────

interface AdminSessionData {
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

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    _adminSessions = loadSessions();
  }
  return _adminSessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  await page.goto("http://localhost:3000/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, sessions[identity].user_sub);
  return page;
}

type ReqParams = Record<string, string>;

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string, params?: ReqParams) {
  return page.request.get(`${API}/${path}`, { params });
}

// ─── DDB helpers ───────────────────────────────────────────────────────────────

const CPP_DDB = "http://localhost:5005";                 // moto on .82 (loopback there)
const CPP_SCHEDULE_TABLE = "tlc_kyc_review_schedule";
// Under cpp, boto3 runs ON .82 (moto is 127.0.0.1-bound) against tlc_* tables;
// the Python path is byte-identical (defaults + .env.local untouched).
const PY_ENV = usingCpp()
  ? `
import boto3, os
os.environ.setdefault('DDB_ENDPOINT_URL', '${CPP_DDB}')
os.environ.setdefault('KYC_REVIEW_SCHEDULE_TABLE_NAME', '${CPP_SCHEDULE_TABLE}')
os.environ.setdefault('USERS_TABLE_NAME', 'tlc_users')
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','${CPP_DDB}'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
`
  : `
import boto3, os
from pathlib import Path
env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k,v = line.split('=',1)
        os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
`;

function runPy(body: string): string {
  // NOTE: do NOT replace real newlines with literal "\n" — python -c cannot parse
  // backslash-n as a statement separator (SyntaxError). Real newlines in the
  // double-quoted shell argument are preserved and execute correctly.
  if (usingCpp()) {
    // moto binds 127.0.0.1 on .82, so the boto3 writes must run THERE. Base64
    // the script so the remote login shell never has to parse quotes/newlines.
    const script = `${PY_ENV}${body}`;
    const b64 = Buffer.from(script, "utf8").toString("base64");
    const key = process.env.E2E_CPP_SSH_KEY ?? "/home/sean/.ssh/e2e_cpp_seed_ed25519";
    return execSync(
      `ssh -i ${key} -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=20 `
        + `sean@192.168.0.82 `
        + `'python3 -c "import base64,sys; exec(base64.b64decode(sys.argv[1]).decode())" ${b64}'`,
      { timeout: 20_000 },
    ).toString();
  }
  return execSync(`python3 -c "${PY_ENV}${body}"`, {
    cwd: REPO_ROOT,
    timeout: 15_000,
  }).toString();
}

/** Seed a review schedule row directly into the kyc_review_schedule table. */
function seedSchedule(opts: {
  userSub: string;
  riskTier: string;
  status: string;
  nextReviewDate: number;
  graceDeadline: number;
}): void {
  const now = Math.floor(Date.now() / 1000);
  runPy(`
tbl = ddb.Table(os.environ.get('KYC_REVIEW_SCHEDULE_TABLE_NAME','kyc_review_schedule'))
tbl.put_item(Item={
  'pk': 'USER#${opts.userSub}',
  'sk': 'SCHEDULE',
  'user_sub': '${opts.userSub}',
  'risk_tier': '${opts.riskTier}',
  'review_frequency_days': 365,
  'last_review_date': ${now},
  'next_review_date': ${opts.nextReviewDate},
  'grace_period_days': 30,
  'grace_deadline': ${opts.graceDeadline},
  'status': '${opts.status}',
  'gsi_status_pk': '${opts.status}',
  'case_id': 'seed_${TS}',
  'created_at': ${now},
  'updated_at': ${now},
})
print('seeded')
`);
}

/** Set a user's kyc_tier directly so the downgrade path has somewhere to fall. */
function setUserTier(userSub: string, tier: number): void {
  const now = Math.floor(Date.now() / 1000);
  runPy(`
tbl = ddb.Table(os.environ.get('USERS_TABLE_NAME','users'))
tbl.update_item(Key={'user_sub':'${userSub}'}, UpdateExpression='SET kyc_tier=:t, kyc_tier_updated_at=:ts', ExpressionAttributeValues={':t':${tier}, ':ts':${now}})
print('tier set')
`);
}

/** Read a schedule's status back from DDB. */
function readScheduleStatus(userSub: string): string {
  const out = runPy(`
tbl = ddb.Table(os.environ.get('KYC_REVIEW_SCHEDULE_TABLE_NAME','kyc_review_schedule'))
item = tbl.get_item(Key={'pk':'USER#${userSub}','sk':'SCHEDULE'}, ConsistentRead=True).get('Item') or {}
print(item.get('status',''))
`);
  return out.trim();
}

// ─── Shared pages ──────────────────────────────────────────────────────────────

let rootPage: Page;
let alicePage: Page;

test.beforeAll(async ({ browser }) => {
  getAdminSessions();
  rootPage = await newIdentityPage(browser, "root");
  alicePage = await newIdentityPage(browser, "alice");
});

test.afterAll(async () => {
  await rootPage?.close();
  await alicePage?.close();
});

// ─── 750. Review Schedule API ───────────────────────────────────────────────────

test.describe("750. KYC-016 Review Schedule API", () => {
  test("750.1 admin can read a seeded review schedule with correct tier", async () => {
    const now = Math.floor(Date.now() / 1000);
    seedSchedule({
      userSub: SCHED_USER,
      riskTier: "high",
      status: "active",
      nextReviewDate: now + 182 * 86400,
      graceDeadline: now + 212 * 86400,
    });
    const r = await apiGet(rootPage, `v1/kyc/monitoring/admin/${encodeURIComponent(SCHED_USER)}/schedule`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { schedule: Record<string, unknown> | null };
    expect(data.schedule).not.toBeNull();
    expect(data.schedule!.risk_tier).toBe("high");
    expect(data.schedule!.status).toBe("active");
    expect(Number(data.schedule!.next_review_date)).toBeGreaterThan(now);
  });

  test("750.2 schedule for a user with no KYC returns null", async () => {
    const r = await apiGet(rootPage, `v1/kyc/monitoring/admin/${encodeURIComponent(BOB_ID)}_nonexistent_${TS}/schedule`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { schedule: unknown };
    expect(data.schedule).toBeNull();
  });

  test("750.3 user can read their own schedule via /schedule", async () => {
    // alice has no seeded schedule -> null, but endpoint must return 200
    const r = await apiGet(alicePage, "v1/kyc/monitoring/schedule");
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { schedule: unknown };
    expect("schedule" in data).toBe(true);
  });

  test("750.4 admin complete-review resets schedule to active with new tier", async () => {
    const r = await apiPost(rootPage, "root", `v1/kyc/monitoring/admin/${encodeURIComponent(SCHED_USER)}/complete-review`, {
      new_risk_tier: "low",
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { schedule: Record<string, unknown> | null };
    expect(data.schedule!.status).toBe("active");
    expect(data.schedule!.risk_tier).toBe("low");
    // low tier => 1095-day frequency
    expect(Number(data.schedule!.review_frequency_days)).toBe(1095);
  });

  test("750.5 complete-review on missing schedule returns 404", async () => {
    const r = await apiPost(rootPage, "root", `v1/kyc/monitoring/admin/missing_${TS}@x.local/complete-review`, {});
    expect(r.status()).toBe(404);
  });
});

// ─── 751. Trigger Events API ────────────────────────────────────────────────────

test.describe("751. KYC-016 Trigger Events API", () => {
  test("751.1 manual trigger flags an active schedule as needs_review", async () => {
    const now = Math.floor(Date.now() / 1000);
    seedSchedule({
      userSub: TRIG_USER,
      riskTier: "medium",
      status: "active",
      nextReviewDate: now + 365 * 86400,
      graceDeadline: now + 395 * 86400,
    });
    const r = await apiPost(rootPage, "root", `v1/kyc/monitoring/admin/${encodeURIComponent(TRIG_USER)}/trigger`, {
      reason: `e2e manual trigger ${TS}`,
    });
    expect(r.status()).toBe(200);
    const ev = (await r.json()) as Record<string, unknown>;
    expect(ev.trigger_type).toBe("manual");
    expect(readScheduleStatus(TRIG_USER)).toBe("needs_review");
  });

  test("751.2 admin can list the user's trigger events via admin schedule + my triggers", async () => {
    // Second trigger
    await apiPost(rootPage, "root", `v1/kyc/monitoring/admin/${encodeURIComponent(TRIG_USER)}/trigger`, {
      reason: `e2e second trigger ${TS}`,
    });
    // Verify via DDB the trigger rows exist (TRIGGER# items)
    const out = runPy(`
tbl = ddb.Table(os.environ.get('KYC_REVIEW_SCHEDULE_TABLE_NAME','kyc_review_schedule'))
from boto3.dynamodb.conditions import Key
resp = tbl.query(KeyConditionExpression=Key('pk').eq('USER#${TRIG_USER}') & Key('sk').begins_with('TRIGGER#'))
print(len(resp.get('Items',[])))
`);
    expect(Number(out.trim())).toBeGreaterThanOrEqual(2);
  });

  test("751.3 trigger with too-short reason returns 422", async () => {
    const r = await apiPost(rootPage, "root", `v1/kyc/monitoring/admin/${encodeURIComponent(TRIG_USER)}/trigger`, {
      reason: "ab",
    });
    expect(r.status()).toBe(422);
  });

  test("751.4 GET /triggers returns an events array for the calling user", async () => {
    const r = await apiGet(alicePage, "v1/kyc/monitoring/triggers");
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { events: unknown[] };
    expect(Array.isArray(data.events)).toBe(true);
  });
});

// ─── 752. Review Checker & Re-screening API ─────────────────────────────────────

test.describe("752. KYC-016 Review Checker & Re-screening API", () => {
  test("752.1 review-check dry_run reports grace entries without mutating", async () => {
    const now = Math.floor(Date.now() / 1000);
    // Past-due but inside grace window.
    seedSchedule({
      userSub: GRACE_USER,
      riskTier: "medium",
      status: "active",
      nextReviewDate: now - 5 * 86400,
      graceDeadline: now + 25 * 86400,
    });
    const r = await apiPost(rootPage, "root", "v1/kyc/monitoring/admin/review-check?dry_run=true");
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { entered_grace_period: number; dry_run: boolean };
    expect(data.dry_run).toBe(true);
    expect(data.entered_grace_period).toBeGreaterThanOrEqual(1);
    // Unchanged because dry run.
    expect(readScheduleStatus(GRACE_USER)).toBe("active");
  });

  test("752.2 review-check without dry_run moves overdue schedule into grace_period", async () => {
    const r = await apiPost(rootPage, "root", "v1/kyc/monitoring/admin/review-check");
    expect(r.status()).toBe(200);
    expect(readScheduleStatus(GRACE_USER)).toBe("grace_period");
  });

  test("752.3 auto-downgrade when grace deadline has passed", async () => {
    const now = Math.floor(Date.now() / 1000);
    setUserTier(DOWNGRADE_USER, 2);
    seedSchedule({
      userSub: DOWNGRADE_USER,
      riskTier: "high",
      status: "active",
      nextReviewDate: now - 60 * 86400,
      graceDeadline: now - 10 * 86400,
    });
    const r = await apiPost(rootPage, "root", "v1/kyc/monitoring/admin/review-check");
    expect(r.status()).toBe(200);
    expect(readScheduleStatus(DOWNGRADE_USER)).toBe("downgraded");
    // Tier was reduced from 2 -> 1.
    const tier = runPy(`
tbl = ddb.Table(os.environ.get('USERS_TABLE_NAME','users'))
item = tbl.get_item(Key={'user_sub':'${DOWNGRADE_USER}'}, ConsistentRead=True).get('Item') or {}
print(int(item.get('kyc_tier',0)))
`);
    expect(Number(tier.trim())).toBe(1);
  });

  test("752.4 re-screening flags a sanctioned ('flagged') user and creates a trigger", async () => {
    const now = Math.floor(Date.now() / 1000);
    seedSchedule({
      userSub: FLAGGED_USER,
      riskTier: "medium",
      status: "active",
      nextReviewDate: now + 365 * 86400,
      graceDeadline: now + 395 * 86400,
    });
    const r = await apiPost(rootPage, "root", "v1/kyc/monitoring/admin/rescreening");
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      total_screened: number;
      matches_found: number;
      triggers_created: number;
    };
    expect(data.total_screened).toBeGreaterThanOrEqual(1);
    expect(data.matches_found).toBeGreaterThanOrEqual(1);
    expect(data.triggers_created).toBeGreaterThanOrEqual(1);
    // The flagged user now has a screening_hit trigger.
    const out = runPy(`
tbl = ddb.Table(os.environ.get('KYC_REVIEW_SCHEDULE_TABLE_NAME','kyc_review_schedule'))
from boto3.dynamodb.conditions import Key
resp = tbl.query(KeyConditionExpression=Key('pk').eq('USER#${FLAGGED_USER}') & Key('sk').begins_with('TRIGGER#'))
print(any(i.get('trigger_type')=='screening_hit' for i in resp.get('Items',[])))
`);
    expect(out.trim()).toBe("True");
  });

  test("752.5 non-admin user cannot run review-check (403)", async () => {
    const r = await apiPost(alicePage, "alice", "v1/kyc/monitoring/admin/review-check");
    expect(r.status()).toBe(403);
  });
});

// ─── 753. Monitoring Dashboard API + auth ───────────────────────────────────────

test.describe("753. KYC-016 Monitoring Dashboard API", () => {
  test("753.1 dashboard returns upcoming and overdue lists", async () => {
    const now = Math.floor(Date.now() / 1000);
    seedSchedule({
      userSub: UPCOMING_USER,
      riskTier: "medium",
      status: "active",
      nextReviewDate: now + 10 * 86400,
      graceDeadline: now + 40 * 86400,
    });
    const r = await apiGet(rootPage, "v1/kyc/monitoring/admin/dashboard");
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      upcoming_reviews: Array<{ user_sub: string; days_until_due: number }>;
      overdue_reviews: Array<{ days_overdue: number }>;
      generated_at: number;
    };
    expect(data.generated_at).toBeGreaterThan(0);
    const up = data.upcoming_reviews.find((u) => u.user_sub === UPCOMING_USER);
    expect(up).toBeTruthy();
    expect(up!.days_until_due).toBeGreaterThanOrEqual(0);
  });

  test("753.2 dashboard exposes days_overdue for overdue reviews", async () => {
    // GRACE_USER is in grace_period from section 752 -> appears as overdue.
    const r = await apiGet(rootPage, "v1/kyc/monitoring/admin/dashboard");
    const data = (await r.json()) as {
      overdue_reviews: Array<{ user_sub: string; days_overdue: number }>;
    };
    const od = data.overdue_reviews.find((o) => o.user_sub === GRACE_USER);
    expect(od).toBeTruthy();
    expect(Number(od!.days_overdue)).toBeGreaterThanOrEqual(0);
  });

  test("753.3 non-admin cannot read the dashboard (403)", async () => {
    const r = await apiGet(alicePage, "v1/kyc/monitoring/admin/dashboard");
    expect(r.status()).toBe(403);
  });

  test("753.4 unauthenticated request to dashboard returns 401", async ({ request }) => {
    const r = await request.get(`${API}/v1/kyc/monitoring/admin/dashboard`);
    expect(r.status()).toBe(401);
  });
});
