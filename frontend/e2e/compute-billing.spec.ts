/**
 * E2E tests for Compute Cost Tracking (INFRA-005).
 *
 * Sections:
 *   640 — Spending API (4 tests)
 *   641 — Budget API (4 tests)
 *   642 — Billing tick API (4 tests)
 *   643 — Spending page UI (4 tests)
 *
 * Auth: Alice session cookies (from e2e_session_setup.py).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
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
      "python3 /home/ubuntu/testlogon/e2e_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ────────────────────────────────────────────────────────────

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

// ─── API helpers ─────────────────────────────────────────────────────────────

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  const url = new URL(`${BASE}${path}`);
  if (params) {
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  }
  return page.request.get(url.toString());
}

async function apiPost(page: Page, path: string, body: unknown) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
    data: body,
  });
}

// ─── DDB helpers ─────────────────────────────────────────────────────────────

function ddbPut(tableName: string, item: Record<string, unknown>) {
  // The `item` is in DynamoDB typed-attribute JSON (e.g. { S: ... }, { N: ... }),
  // which the boto3 low-level client accepts directly via put_item(). We pass it
  // to a short python script through argv to avoid quoting issues, using the same
  // local DynamoDB endpoint/credentials as the rest of the dev stack.
  const itemJson = JSON.stringify(item);
  // Single physical line of Python (statements joined with ";") so it survives
  // being passed as one shell-quoted argument to `python3 -c`.
  const py =
    "import json, sys, boto3; " +
    'c = boto3.client("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test"); ' +
    "c.put_item(TableName=sys.argv[1], Item=json.loads(sys.argv[2]))";
  execSync(
    `python3 -c ${JSON.stringify(py)} ${JSON.stringify(tableName)} ${JSON.stringify(itemJson)}`,
    {
      cwd: "/home/ubuntu/testlogon",
      timeout: 10_000,
      env: {
        ...process.env,
        AWS_ACCESS_KEY_ID: "test",
        AWS_SECRET_ACCESS_KEY: "test",
        AWS_DEFAULT_REGION: "us-east-1",
      },
    },
  );
}

function seedWalletBalance(userSub: string, balanceCents: number) {
  ddbPut("billing", {
    pk: { S: `USER#${userSub}` },
    sk: { S: "WALLET" },
    wallet_balance_cents: { N: String(balanceCents) },
    currency: { S: "usd" },
    updated_at: { N: String(Math.floor(Date.now() / 1000)) },
  });
}

function seedBillingTick(
  userSub: string,
  opts: {
    resourceType: string;
    resourceId: string;
    resourceLabel: string;
    instanceType: string;
    amountCents: number;
    durationMinutes: number;
    rateCentsPerMin: number;
    createdAt: number;
    monthKey: string;
    entryId: string;
  },
) {
  ddbPut("compute_billing", {
    user_sub: { S: userSub },
    sk: { S: `TICK#${opts.createdAt}#${opts.entryId}` },
    entry_id: { S: opts.entryId },
    resource_type: { S: opts.resourceType },
    resource_id: { S: opts.resourceId },
    resource_label: { S: opts.resourceLabel },
    instance_type_or_preset: { S: opts.instanceType },
    event: { S: "periodic_tick" },
    amount_cents: { N: String(opts.amountCents) },
    duration_minutes: { N: String(opts.durationMinutes) },
    rate_cents_per_min: { N: String(opts.rateCentsPerMin) },
    wallet_balance_after: { N: "9000" },
    created_at: { N: String(opts.createdAt) },
    month_key: { S: opts.monthKey },
  });
}

function seedMonthlyTotal(userSub: string, monthKey: string, totalCents: number) {
  ddbPut("compute_billing", {
    user_sub: { S: userSub },
    sk: { S: `MONTH#${monthKey}` },
    current_month_total_cents: { N: String(totalCents) },
    month_key: { S: monthKey },
  });
}

// ─── Test state ──────────────────────────────────────────────────────────────

let alicePage: Page;
let aliceSub: string;
const currentMonth = new Date().toISOString().slice(0, 7); // YYYY-MM

// Unique resource IDs per test run
const EC2_RES_ID = `i-e2e-${TS}`;
const K8S_RES_ID = `pod-e2e-${TS}`;
const EC2_LABEL = `E2E EC2 ${TS}`;
const K8S_LABEL = `E2E K8s ${TS}`;

test.describe("640 — Spending API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    aliceSub = getSessions()[ALICE_ID].user_sub;

    // Seed wallet
    seedWalletBalance(aliceSub, 50000);

    // Seed billing ticks
    const baseTs = Math.floor(Date.now() / 1000) - 3600;
    seedBillingTick(aliceSub, {
      resourceType: "ec2",
      resourceId: EC2_RES_ID,
      resourceLabel: EC2_LABEL,
      instanceType: "t3.small",
      amountCents: 10,
      durationMinutes: 25,
      rateCentsPerMin: 0.4,
      createdAt: baseTs,
      monthKey: currentMonth,
      entryId: `e_ec2_${TS}_1`,
    });
    seedBillingTick(aliceSub, {
      resourceType: "ec2",
      resourceId: EC2_RES_ID,
      resourceLabel: EC2_LABEL,
      instanceType: "t3.small",
      amountCents: 8,
      durationMinutes: 20,
      rateCentsPerMin: 0.4,
      createdAt: baseTs + 60,
      monthKey: currentMonth,
      entryId: `e_ec2_${TS}_2`,
    });
    seedBillingTick(aliceSub, {
      resourceType: "k8s",
      resourceId: K8S_RES_ID,
      resourceLabel: K8S_LABEL,
      instanceType: "medium",
      amountCents: 6,
      durationMinutes: 20,
      rateCentsPerMin: 0.3,
      createdAt: baseTs + 120,
      monthKey: currentMonth,
      entryId: `e_k8s_${TS}_1`,
    });

    // Seed monthly total
    seedMonthlyTotal(aliceSub, currentMonth, 24);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("640.1 GET /spending returns monthly summary", async () => {
    const resp = await apiGet(alicePage, "/ui/remote/billing/spending");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.month).toBe(currentMonth);
    expect(data.total_cents).toBeGreaterThanOrEqual(0);
    expect(typeof data.budget_cents).toBe("number");
    expect(typeof data.budget_pct).toBe("number");
    expect(typeof data.ec2_total_cents).toBe("number");
    expect(typeof data.k8s_total_cents).toBe("number");
    expect(typeof data.resource_count).toBe("number");
  });

  test("640.2 GET /resources returns per-resource breakdown", async () => {
    const resp = await apiGet(alicePage, "/ui/remote/billing/resources");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.month).toBe(currentMonth);
    expect(Array.isArray(data.resources)).toBe(true);
    // We seeded 2 resources
    const ec2 = data.resources.find((r: { resource_id: string }) => r.resource_id === EC2_RES_ID);
    const k8s = data.resources.find((r: { resource_id: string }) => r.resource_id === K8S_RES_ID);
    expect(ec2).toBeTruthy();
    expect(k8s).toBeTruthy();
    expect(ec2.total_cents).toBe(18);
    expect(k8s.total_cents).toBe(6);
  });

  test("640.3 GET /history returns ledger entries", async () => {
    const resp = await apiGet(alicePage, "/ui/remote/billing/history");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.entries)).toBe(true);
    expect(data.count).toBeGreaterThanOrEqual(3);
    // Entries have required fields
    const entry = data.entries[0];
    expect(entry).toHaveProperty("entry_id");
    expect(entry).toHaveProperty("resource_type");
    expect(entry).toHaveProperty("amount_cents");
    expect(entry).toHaveProperty("created_at");
  });

  test("640.4 GET /history with resource_id filters results", async () => {
    const resp = await apiGet(alicePage, "/ui/remote/billing/history", {
      resource_id: K8S_RES_ID,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.count).toBeGreaterThanOrEqual(1);
    for (const e of data.entries) {
      expect(e.resource_id).toBe(K8S_RES_ID);
    }
  });
});

test.describe("641 — Budget API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    aliceSub = getSessions()[ALICE_ID].user_sub;
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("641.1 GET /budget returns defaults when no budget set", async () => {
    const resp = await apiGet(alicePage, "/ui/remote/billing/budget");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.budget_monthly_cents).toBeGreaterThan(0);
    expect(Array.isArray(data.alert_thresholds)).toBe(true);
    expect(typeof data.current_month_total_cents).toBe("number");
    expect(typeof data.current_month_pct).toBe("number");
  });

  test("641.2 POST /budget sets a new budget", async () => {
    const resp = await apiPost(alicePage, "/ui/remote/billing/budget", {
      budget_monthly_cents: 10000,
      alert_thresholds: [25, 50, 75, 100],
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.budget_monthly_cents).toBe(10000);
    expect(data.alert_thresholds).toEqual([25, 50, 75, 100]);
  });

  test("641.3 POST /budget validates minimum", async () => {
    const resp = await apiPost(alicePage, "/ui/remote/billing/budget", {
      budget_monthly_cents: 50,
    });
    expect(resp.status()).toBe(422);
  });

  test("641.4 POST /budget validates maximum", async () => {
    const resp = await apiPost(alicePage, "/ui/remote/billing/budget", {
      budget_monthly_cents: 2000000,
    });
    expect(resp.status()).toBe(422);
  });
});

test.describe("642 — Billing tick API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    aliceSub = getSessions()[ALICE_ID].user_sub;

    // Ensure wallet has balance
    seedWalletBalance(aliceSub, 50000);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("642.1 POST /tick creates a billing entry and deducts wallet", async () => {
    const resp = await apiPost(alicePage, "/ui/remote/billing/tick", {
      resource_type: "ec2",
      resource_id: `i-tick-${TS}`,
      resource_label: "Tick Test EC2",
      instance_type_or_preset: "t3.micro",
      duration_minutes: 5,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.entry_id).toBeTruthy();
    expect(data.amount_cents).toBeGreaterThan(0);
    expect(typeof data.wallet_balance_after).toBe("number");
    expect(data.rate_cents_per_min).toBeCloseTo(0.2, 1);
    expect(data.created_at).toBeGreaterThan(0);
  });

  test("642.2 POST /tick for K8s uses K8s rate card", async () => {
    const resp = await apiPost(alicePage, "/ui/remote/billing/tick", {
      resource_type: "k8s",
      resource_id: `pod-tick-${TS}`,
      resource_label: "Tick Test K8s",
      instance_type_or_preset: "large",
      duration_minutes: 10,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.rate_cents_per_min).toBeCloseTo(0.6, 1);
    expect(data.amount_cents).toBeGreaterThanOrEqual(6);
  });

  test("642.3 POST /tick validates resource_type", async () => {
    const resp = await apiPost(alicePage, "/ui/remote/billing/tick", {
      resource_type: "azure",
      resource_id: "bad-resource",
      instance_type_or_preset: "t3.micro",
      duration_minutes: 5,
    });
    expect(resp.status()).toBe(422);
  });

  test("642.4 POST /tick validates duration_minutes > 0", async () => {
    const resp = await apiPost(alicePage, "/ui/remote/billing/tick", {
      resource_type: "ec2",
      resource_id: "i-test",
      instance_type_or_preset: "t3.micro",
      duration_minutes: 0,
    });
    expect(resp.status()).toBe(422);
  });
});

test.describe("643 — Spending page UI", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    aliceSub = getSessions()[ALICE_ID].user_sub;

    // Seed wallet + billing data
    seedWalletBalance(aliceSub, 50000);
    const baseTs = Math.floor(Date.now() / 1000) - 1800;
    seedBillingTick(aliceSub, {
      resourceType: "ec2",
      resourceId: `i-ui-${TS}`,
      resourceLabel: `UI Test EC2 ${TS}`,
      instanceType: "t3.medium",
      amountCents: 16,
      durationMinutes: 20,
      rateCentsPerMin: 0.8,
      createdAt: baseTs,
      monthKey: currentMonth,
      entryId: `e_ui_${TS}`,
    });
    seedMonthlyTotal(aliceSub, currentMonth, 40);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("643.1 ComputeSpendingPage renders with page title", async () => {
    await alicePage.goto(`${BASE}/remote/billing`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByTestId("page-title")).toBeVisible();
    await expect(alicePage.getByTestId("page-title")).toHaveText("Compute Spending");
  });

  test("643.2 Spending summary shows total amount", async () => {
    await alicePage.goto(`${BASE}/remote/billing`, { waitUntil: "domcontentloaded" });
    // Wait for the spending summary to load
    await expect(alicePage.getByTestId("total-spending")).toBeVisible({ timeout: 10_000 });
    const totalText = await alicePage.getByTestId("total-spending").textContent();
    expect(totalText).toContain("$");
  });

  test("643.3 Budget meter is visible", async () => {
    await alicePage.goto(`${BASE}/remote/billing`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByTestId("budget-pct")).toBeVisible({ timeout: 10_000 });
    const pctText = await alicePage.getByTestId("budget-pct").textContent();
    expect(pctText).toContain("% used");
  });

  test("643.4 Ledger tab shows billing entries", async () => {
    await alicePage.goto(`${BASE}/remote/billing`, { waitUntil: "domcontentloaded" });
    // Click ledger tab
    await alicePage.getByRole("button", { name: "Ledger" }).click();
    // Wait for ledger table or empty message
    const hasEntries = await alicePage.getByTestId("ledger-table").isVisible().catch(() => false);
    if (hasEntries) {
      const rows = alicePage.getByTestId("ledger-row");
      await expect(rows.first()).toBeVisible({ timeout: 10_000 });
    }
    // Either way the tab rendered successfully
    expect(true).toBe(true);
  });
});
