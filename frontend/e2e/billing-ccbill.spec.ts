/**
 * Section 105: Billing (CCBill) — config, settings, payment methods, balance, ledger
 *
 * Auth: Cookie sessions via e2e_admin_session_setup.py
 * Identities: alice (USER), root (ROOT)
 */
import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const TS = Date.now();

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
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function newPage(browser: Browser, identity: string): Promise<Page> {
  const page = await browser.newPage();
  await page.context().addCookies(getSessions()[identity].cookies);
  return page;
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

async function apiPost(page: Page, id: string, path: string, body?: unknown) {
  const s = getSessions()[id];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": s.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiDelete(page: Page, id: string, path: string) {
  const s = getSessions()[id];
  return page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": s.csrf_token },
  });
}

function seedPaymentMethod(userSub: string, pmId: string): void {
  execSync(
    `.venv/bin/python3 -c '
import boto3
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test")
from app.core.settings import S
tbl = ddb.Table(S.billing_table_name)
tbl.put_item(Item={
    "pk": "${userSub}",
    "sk": "PM#${pmId}",
    "payment_token_id": "${pmId}",
    "provider": "ccbill",
    "card_type": "Visa",
    "last4": "4242",
    "created_at": 1700000000,
    "priority": 1,
    "active": True,
})
tbl.put_item(Item={
    "pk": "${userSub}",
    "sk": "BILLING",
    "default_payment_token_id": "${pmId}",
    "autopay_enabled": False,
    "currency": "USD",
    "updated_at": 1700000000,
})
print("seeded")
'`,
    { cwd: "/home/ubuntu/testlogon", timeout: 10_000 },
  );
}

function cleanupBillingData(userSub: string): void {
  execSync(
    `.venv/bin/python3 -c '
import boto3
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test")
from app.core.settings import S
tbl = ddb.Table(S.billing_table_name)
resp = tbl.query(KeyConditionExpression="pk = :u", ExpressionAttributeValues={":u": "${userSub}"})
for item in resp.get("Items", []):
    tbl.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})
print("cleaned")
'`,
    { cwd: "/home/ubuntu/testlogon", timeout: 10_000 },
  );
}

// ─── 105. Billing (CCBill) ───────────────────────────────────────────────

test.describe.serial("105 — Billing (CCBill): config, settings, PM, balance, ledger", () => {
  let alicePage: Page;
  const aliceSub = () => getSessions()["alice"].user_sub;
  const pmId = `pm_e2e_${TS}`;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
    cleanupBillingData(aliceSub());
    seedPaymentMethod(aliceSub(), pmId);
  });

  test.afterAll(async () => {
    cleanupBillingData(aliceSub());
    await alicePage?.close();
  });

  test("105.1 Get billing config (public)", async () => {
    const resp = await apiGet(alicePage, "/api/billing/config");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data).toHaveProperty("ccbill_base_url");
    expect(data).toHaveProperty("default_currency");
  });

  test("105.2 Get billing settings", async () => {
    const resp = await apiGet(alicePage, "/api/billing/settings");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data).toHaveProperty("autopay_enabled");
    expect(data).toHaveProperty("currency");
  });

  test("105.3 List payment methods returns seeded PM", async () => {
    const resp = await apiGet(alicePage, "/api/billing/payment-methods");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data).toBeInstanceOf(Array);
    const found = data.find((pm: any) => pm.payment_token_id === pmId);
    expect(found).toBeTruthy();
    expect(found.provider).toBe("ccbill");
    expect(found.priority).toBe(1);
  });

  test("105.4 Set default payment method", async () => {
    const resp = await apiPost(alicePage, "alice", "/api/billing/payment-methods/default", {
      payment_token_id: pmId,
    });
    expect(resp.status()).toBe(200);

    const settingsResp = await apiGet(alicePage, "/api/billing/settings");
    const settings = await settingsResp.json();
    expect(settings.default_payment_token_id).toBe(pmId);
  });

  test("105.5 Enable autopay", async () => {
    const resp = await apiPost(alicePage, "alice", "/api/billing/autopay", {
      enabled: true,
    });
    expect(resp.status()).toBe(200);

    const settingsResp = await apiGet(alicePage, "/api/billing/settings");
    const settings = await settingsResp.json();
    expect(settings.autopay_enabled).toBe(true);
  });

  test("105.6 Disable autopay", async () => {
    const resp = await apiPost(alicePage, "alice", "/api/billing/autopay", {
      enabled: false,
    });
    expect(resp.status()).toBe(200);

    const settingsResp = await apiGet(alicePage, "/api/billing/settings");
    const settings = await settingsResp.json();
    expect(settings.autopay_enabled).toBe(false);
  });

  test("105.7 Get balance", async () => {
    const resp = await apiGet(alicePage, "/api/billing/balance");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data).toHaveProperty("owed_pending_cents");
    expect(data).toHaveProperty("owed_settled_cents");
    expect(data).toHaveProperty("currency");
  });

  test("105.8 Add dev charge to balance", async () => {
    const resp = await apiPost(alicePage, "alice", "/api/billing/_dev/add-charge", {
      amount_cents: 1500,
      state: "pending",
      reason: `E2E test charge ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
  });

  test("105.9 Get ledger entries", async () => {
    const resp = await apiGet(alicePage, "/api/billing/ledger");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items).toBeInstanceOf(Array);
    expect(data.items.length).toBeGreaterThanOrEqual(1);
  });

  test("105.10 Get payments list", async () => {
    const resp = await apiGet(alicePage, "/api/billing/payments");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items).toBeInstanceOf(Array);
  });

  test("105.11 Get subscriptions list", async () => {
    const resp = await apiGet(alicePage, "/api/billing/subscriptions");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items).toBeInstanceOf(Array);
  });

  test("105.12 Set payment method priority", async () => {
    const resp = await apiPost(alicePage, "alice", "/api/billing/payment-methods/priority", {
      payment_token_id: pmId,
      priority: 5,
    });
    expect(resp.status()).toBe(200);
  });

  test("105.13 Delete payment method", async () => {
    const resp = await apiDelete(alicePage, "alice", `/api/billing/payment-methods/${pmId}`);
    expect(resp.status()).toBe(200);

    const listResp = await apiGet(alicePage, "/api/billing/payment-methods");
    const data = await listResp.json();
    const found = data.find((pm: any) => pm.payment_token_id === pmId);
    expect(found).toBeUndefined();
  });
});
