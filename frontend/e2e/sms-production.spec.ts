import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// PLATFORM-007 — SMS Production send pipeline.
//
// Exercises the production send path (app/services/sms_delivery.send_sms via
// the admin /ui/admin/sms/send-test endpoint). In DEV_MODE the path dev-logs
// and records a `dev_logged` delivery row (never touches real AWS), while
// still honouring the suppression list and the per-number daily limit — so
// these behaviours are fully deterministic for E2E.

const API = "http://localhost:8000";
const TS = Date.now();
const PHONE_OK = `+1555${String(TS).slice(-7)}`;
const PHONE_SUPP = `+1556${String(TS).slice(-7)}`;
const PHONE_RL = `+1557${String(TS).slice(-7)}`;
const DDB = "http://localhost:8001";
const SMS_TABLE = "sms_delivery";
const DAILY_LIMIT = 10;

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None"; expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py", {
      cwd: "/home/ubuntu/testlogon", timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await injectAuth(page, identity);
  // Seed the client-side auth store so ProtectedRoute treats the page as
  // authenticated (cookies alone only satisfy server-side API auth).
  await page.goto("/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, getSessions()[identity].user_sub);
  return page;
}

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

async function apiDelete(page: Page, identity: string, path: string) {
  const s = getSessions()[identity];
  return page.request.delete(`${API}${path}`, { headers: { "x-csrf-token": s.csrf_token } });
}

// Run a small python snippet against DDB local. Used to ensure the table
// exists and to pre-seed the per-number daily counter for the rate-limit test.
function ddbPy(snippet: string): string {
  const code = [
    "import boto3, os",
    `os.environ.setdefault('AWS_ACCESS_KEY_ID','test')`,
    `os.environ.setdefault('AWS_SECRET_ACCESS_KEY','test')`,
    `os.environ.setdefault('AWS_DEFAULT_REGION','us-east-1')`,
    `ddb = boto3.resource('dynamodb', endpoint_url='${DDB}')`,
    `client = boto3.client('dynamodb', endpoint_url='${DDB}')`,
    snippet,
  ].join("\n");
  return execSync(`/home/ubuntu/testlogon/.venv/bin/python -c "${code.replace(/"/g, '\\"')}"`, {
    timeout: 30_000,
  }).toString().trim();
}

function ensureTable() {
  ddbPy([
    "names = [t for _p in client.get_paginator('list_tables').paginate() for t in _p['TableNames']]",
    `if '${SMS_TABLE}' not in names:`,
    "    client.create_table(",
    `        TableName='${SMS_TABLE}',`,
    "        KeySchema=[{'AttributeName':'pk','KeyType':'HASH'},{'AttributeName':'sk','KeyType':'RANGE'}],",
    "        AttributeDefinitions=[",
    "            {'AttributeName':'pk','AttributeType':'S'},",
    "            {'AttributeName':'sk','AttributeType':'S'},",
    "            {'AttributeName':'status','AttributeType':'S'},",
    "            {'AttributeName':'created_at','AttributeType':'N'},",
    "        ],",
    "        BillingMode='PAY_PER_REQUEST',",
    "        GlobalSecondaryIndexes=[{",
    "            'IndexName':'ByStatus',",
    "            'KeySchema':[{'AttributeName':'status','KeyType':'HASH'},{'AttributeName':'created_at','KeyType':'RANGE'}],",
    "            'Projection':{'ProjectionType':'ALL'},",
    "        }],",
    "    )",
    "    client.get_waiter('table_exists').wait(TableName='" + SMS_TABLE + "')",
    "print('ok')",
  ].join("\n"));
}

function seedDailyCounter(phone: string, count: number) {
  ddbPy([
    "import time",
    "day_key = int(time.time()) // 86400",
    `t = ddb.Table('${SMS_TABLE}')`,
    "t.put_item(Item={",
    `    'pk': 'DAILY#${phone}',`,
    "    'sk': 'DAY#%d' % day_key,",
    `    'count': ${count},`,
    "    'updated_at': int(time.time()),",
    "    'ttl_epoch': int(time.time()) + 7*86400,",
    "})",
    "print('seeded')",
  ].join("\n"));
}

test.beforeAll(() => {
  ensureTable();
});

// ──────────────────────────────────────────────────────────────────────
// Section 1: Production send pipeline (admin send-test)
// ──────────────────────────────────────────────────────────────────────

test.describe("PLATFORM-007 SMS Production — send pipeline", () => {
  test("admin send-test records a delivery row", async ({ browser }) => {
    const root = await newIdentityPage(browser, "root");
    const resp = await apiPost(root, "root", "/ui/admin/sms/send-test", {
      phone: PHONE_OK,
      body: `prod-test-${TS}`,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.number).toBe(PHONE_OK);
    // In DEV_MODE the production path records a dev_logged delivery row.
    expect(["sent", "dev_logged"]).toContain(body.status);

    // The recorded delivery should be visible via the deliveries listing.
    const listResp = await apiGet(root, "/ui/admin/sms/deliveries", {
      limit: "200",
      status: body.status,
    });
    expect(listResp.status()).toBe(200);
    const list = await listResp.json();
    const found = (list.items ?? []).some((it: { phone?: string }) => it.phone === PHONE_OK);
    expect(found).toBe(true);
    await root.context().close();
  });

  test("send-test validates phone (422 on empty)", async ({ browser }) => {
    const root = await newIdentityPage(browser, "root");
    const resp = await apiPost(root, "root", "/ui/admin/sms/send-test", { phone: "", body: "x" });
    expect(resp.status()).toBe(422);
    await root.context().close();
  });

  test("non-admin user gets 403 on send-test", async ({ browser }) => {
    const alice = await newIdentityPage(browser, "alice");
    const resp = await apiPost(alice, "alice", "/ui/admin/sms/send-test", {
      phone: PHONE_OK,
      body: "nope",
    });
    expect(resp.status()).toBe(403);
    await alice.context().close();
  });
});

// ──────────────────────────────────────────────────────────────────────
// Section 2: Suppression enforced on the send path
// ──────────────────────────────────────────────────────────────────────

test.describe("PLATFORM-007 SMS Production — suppression", () => {
  test("suppressed number is not sent (status suppressed)", async ({ browser }) => {
    const root = await newIdentityPage(browser, "root");

    // Suppress the number via admin endpoint.
    const supp = await apiPost(root, "root", `/ui/admin/sms/suppressed/${encodeURIComponent(PHONE_SUPP)}`, {});
    expect(supp.status()).toBe(200);
    expect((await supp.json()).suppressed).toBe(true);

    // The production send-test should now short-circuit with status=suppressed.
    const resp = await apiPost(root, "root", "/ui/admin/sms/send-test", {
      phone: PHONE_SUPP,
      body: `supp-${TS}`,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("suppressed");
    expect(body.message_id).toBeFalsy();

    // Unsuppress for cleanliness and confirm it sends again.
    const un = await apiDelete(root, "root", `/ui/admin/sms/suppressed/${encodeURIComponent(PHONE_SUPP)}`);
    expect(un.status()).toBe(200);
    const resp2 = await apiPost(root, "root", "/ui/admin/sms/send-test", {
      phone: PHONE_SUPP,
      body: `unsupp-${TS}`,
    });
    expect(["sent", "dev_logged"]).toContain((await resp2.json()).status);
    await root.context().close();
  });
});

// ──────────────────────────────────────────────────────────────────────
// Section 3: Per-number daily rate limit enforced on the send path
// ──────────────────────────────────────────────────────────────────────

test.describe("PLATFORM-007 SMS Production — rate limit", () => {
  test("per-number daily limit returns status rate_limited", async ({ browser }) => {
    const root = await newIdentityPage(browser, "root");
    // Pre-seed the daily counter at the limit so the next send is rate-limited.
    seedDailyCounter(PHONE_RL, DAILY_LIMIT);
    const resp = await apiPost(root, "root", "/ui/admin/sms/send-test", {
      phone: PHONE_RL,
      body: `rl-${TS}`,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("rate_limited");
    expect(body.message_id).toBeFalsy();
    await root.context().close();
  });
});

// ──────────────────────────────────────────────────────────────────────
// Section 4: Admin delivery view + UI
// ──────────────────────────────────────────────────────────────────────

test.describe("PLATFORM-007 SMS Production — admin delivery view", () => {
  test("admin can read delivery stats", async ({ browser }) => {
    const root = await newIdentityPage(browser, "root");
    const resp = await apiGet(root, "/ui/admin/sms/stats", { days: "7" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body).toHaveProperty("sent");
    expect(body).toHaveProperty("failed");
    expect(body).toHaveProperty("success_rate");
    await root.context().close();
  });

  test("admin SMS dashboard renders Send test SMS control", async ({ browser }) => {
    const root = await newIdentityPage(browser, "root");
    await root.goto(`${API.replace(":8000", ":3000")}/admin/communications`);
    await root.getByRole("tab", { name: "SMS" }).click();
    await expect(root.getByTestId("sms-send-test")).toBeVisible();
    await root.context().close();
  });

  test("Send test SMS dialog opens and submits via UI", async ({ browser }) => {
    const root = await newIdentityPage(browser, "root");
    await root.goto(`${API.replace(":8000", ":3000")}/admin/communications`);
    await root.getByRole("tab", { name: "SMS" }).click();
    await root.getByTestId("sms-send-test").click();
    await root.getByTestId("sms-test-phone").fill(`+1558${String(TS).slice(-7)}`);
    await root.getByTestId("sms-send-test-submit").click();
    // Toast confirms the pipeline ran.
    await expect(root.getByText(/Test SMS:/)).toBeVisible({ timeout: 10_000 });
    await root.context().close();
  });
});
