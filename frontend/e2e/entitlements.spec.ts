/**
 * Section 94: User Entitlements — list + filter + usage
 * Section 95: Admin Entitlement Management — extend, credit, revoke
 *
 * Auth: Cookie sessions via e2e_admin_session_setup.py
 * Identities: root (ROOT), alice (USER)
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

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${BASE}${path}`, { params });
}

async function apiPost(page: Page, id: string, path: string, body?: unknown) {
  const s = getSessions()[id];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": s.csrf_token, "Content-Type": "application/json" },
  });
}

const ENT_ID = `ent_e2e_${TS}`;
const ENT_ID_2 = `ent_e2e_usage_${TS}`;

/** Seed an entitlement row directly into DynamoDB. */
function seedEntitlement(userId: string, entitlementId: string, extras: Record<string, unknown> = {}): void {
  const nowIso = new Date().toISOString();
  const endsAtIso = new Date(Date.now() + 365 * 86400_000).toISOString();
  const base: Record<string, unknown> = {
    user_id: userId,
    entitlement_id: entitlementId,
    sku: `sku_${TS}`,
    product_type: "api_package",
    status: "active",
    starts_at: nowIso,
    ends_at: endsAtIso,
    usage_limit: 1000,
    usage_consumed: 50,
    source_system: "subscription_cycle",
    ...extras,
  };
  // Build a Python dict literal to avoid JSON quoting issues in the shell
  const pairs = Object.entries(base)
    .map(([k, v]) => `"${k}": ${typeof v === "number" ? v : `"${v}"`}`)
    .join(", ");
  execSync(
    `.venv/bin/python3 -c '
import boto3
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test")
from app.core.settings import S
ddb.Table(S.entitlements_table_name).put_item(Item={${pairs}})
'`,
    { cwd: "/home/ubuntu/testlogon", timeout: 10_000 },
  );
}

function deleteEntitlement(userId: string, entitlementId: string): void {
  execSync(
    `.venv/bin/python3 -c 'import boto3; ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test"); from app.core.settings import S; ddb.Table(S.entitlements_table_name).delete_item(Key={"user_id": "${userId}", "entitlement_id": "${entitlementId}"})'`,
    { cwd: "/home/ubuntu/testlogon", timeout: 10_000 },
  );
}

// ─── 94. User Entitlements ─────────────────────────────────────────────────

test.describe.serial("94. User Entitlements — list + filter + usage", () => {
  let alicePage: Page;
  const aliceSub = () => getSessions()["alice"].user_sub;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
    seedEntitlement(aliceSub(), ENT_ID);
    seedEntitlement(aliceSub(), ENT_ID_2, { product_type: "api_package", sku: `sku_usage_${TS}` });
  });

  test.afterAll(async () => {
    try { deleteEntitlement(aliceSub(), ENT_ID); } catch { /* ignore */ }
    try { deleteEntitlement(aliceSub(), ENT_ID_2); } catch { /* ignore */ }
    await alicePage?.close();
  });

  test("94.1 List entitlements returns seeded items", async () => {
    const resp = await apiGet(alicePage, "/v1/entitlements");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items).toBeInstanceOf(Array);
    expect(data.count).toBeGreaterThanOrEqual(1);
    expect(data.generated_at).toBeTruthy();
    const found = data.items.find((e: any) => e.entitlement_id === ENT_ID);
    expect(found).toBeTruthy();
    expect(found.sku).toBe(`sku_${TS}`);
    expect(found.product_type).toBe("api_package");
    expect(found.status).toBe("active");
  });

  test("94.2 Filter by product_type", async () => {
    const resp = await apiGet(alicePage, "/v1/entitlements", { product_type: "api_package" });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.items.find((e: any) => e.entitlement_id === ENT_ID);
    expect(found).toBeTruthy();

    const respNone = await apiGet(alicePage, "/v1/entitlements", { product_type: "nonexistent_type" });
    expect(respNone.status()).toBe(200);
    const dataNone = await respNone.json();
    const notFound = dataNone.items.find((e: any) => e.entitlement_id === ENT_ID);
    expect(notFound).toBeUndefined();
  });

  test("94.3 Filter by status", async () => {
    const resp = await apiGet(alicePage, "/v1/entitlements", { status: "active" });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.items.find((e: any) => e.entitlement_id === ENT_ID);
    expect(found).toBeTruthy();

    const respExpired = await apiGet(alicePage, "/v1/entitlements", { status: "expired" });
    expect(respExpired.status()).toBe(200);
    const dataExpired = await respExpired.json();
    const notFound = dataExpired.items.find((e: any) => e.entitlement_id === ENT_ID);
    expect(notFound).toBeUndefined();
  });

  test("94.4 Usage endpoint returns items for api_package entitlements", async () => {
    const resp = await apiGet(alicePage, "/v1/entitlements/usage");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items).toBeInstanceOf(Array);
    expect(data.count).toBeGreaterThanOrEqual(1);
    const found = data.items.find((e: any) => e.entitlement_id === ENT_ID);
    expect(found).toBeTruthy();
    expect(found.usage_limit).toBe(1000);
    expect(found.usage_consumed).toBe(50);
    expect(found.remaining).toBe(950);
    expect(found.status).toBe("active");
  });

  test("94.5 Entitlement items include scope and billing metadata", async () => {
    const resp = await apiGet(alicePage, "/v1/entitlements");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.items.find((e: any) => e.entitlement_id === ENT_ID);
    expect(found).toBeTruthy();
    expect(found).toHaveProperty("scope");
    expect(found).toHaveProperty("billing_metadata");
    expect(found).toHaveProperty("source_system");
    expect(found.source_system).toBe("subscription_cycle");
    expect(found.denial_reason_hint).toBeNull();
  });
});

// ─── 95. Admin Entitlement Management ──────────────────────────────────────

test.describe.serial("95. Admin Entitlement Management — extend, credit, revoke", () => {
  let rootPage: Page;
  let alicePage: Page;
  const adminEntId = `ent_admin_e2e_${TS}`;
  const aliceSub = () => getSessions()["alice"].user_sub;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newPage(browser, "root");
    alicePage = await newPage(browser, "alice");
    seedEntitlement(aliceSub(), adminEntId, { usage_limit: 500, usage_consumed: 0 });
  });

  test.afterAll(async () => {
    try { deleteEntitlement(aliceSub(), adminEntId); } catch { /* ignore */ }
    await rootPage?.close();
    await alicePage?.close();
  });

  test("95.1 Non-admin (Alice) cannot revoke entitlements", async () => {
    const resp = await apiPost(alicePage, "alice", `/v1/admin/entitlements/${adminEntId}/revoke`, {
      reason_code: "customer_support",
      audit_comment: "Test revoke by non-admin",
    });
    expect(resp.status()).toBe(403);
  });

  test("95.2 Root extends an entitlement", async () => {
    const resp = await apiPost(rootPage, "root", `/v1/admin/entitlements/${adminEntId}/extend`, {
      reason_code: "goodwill",
      audit_comment: `E2E extend test ${TS}`,
      extend_hours: 48,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.entitlement_id).toBe(adminEntId);
    expect(data.extended_hours).toBe(48);
    expect(data.ends_at).toBeTruthy();
    expect(data.audit_event_id).toBeTruthy();
  });

  test("95.3 Root adds credits to an entitlement", async () => {
    const resp = await apiPost(rootPage, "root", `/v1/admin/entitlements/${adminEntId}/credits`, {
      reason_code: "incident_remediation",
      audit_comment: `E2E credit test ${TS}`,
      credit_units: 200,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.entitlement_id).toBe(adminEntId);
    expect(data.credited_units).toBe(200);
    expect(data.usage_limit).toBe(700); // 500 + 200
    expect(data.audit_event_id).toBeTruthy();
  });

  test("95.4 Root revokes an entitlement", async () => {
    const resp = await apiPost(rootPage, "root", `/v1/admin/entitlements/${adminEntId}/revoke`, {
      reason_code: "fraud_review",
      audit_comment: `E2E revoke test ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.entitlement_id).toBe(adminEntId);
    expect(data.status).toBe("revoked");
    expect(data.audit_event_id).toBeTruthy();
  });

  test("95.5 Revoked entitlement shows as revoked in user list", async () => {
    const resp = await apiGet(alicePage, "/v1/entitlements");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.items.find((e: any) => e.entitlement_id === adminEntId);
    expect(found).toBeTruthy();
    expect(found.status).toBe("revoked");
    expect(found.denial_reason_hint).toBe("no_entitlement");
  });

  test("95.6 Extending non-existent entitlement returns 404", async () => {
    const resp = await apiPost(rootPage, "root", `/v1/admin/entitlements/nonexistent_${TS}/extend`, {
      reason_code: "customer_support",
      audit_comment: "Should not find this entitlement",
      extend_hours: 1,
    });
    expect(resp.status()).toBe(404);
    const data = await resp.json();
    expect(data.detail.code).toBe("entitlement_not_found");
  });
});
