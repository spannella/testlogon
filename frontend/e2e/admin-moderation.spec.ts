/**
 * Section 87: Content Moderation — admin review + decision + feature flags
 * Section 88: Purchase History — CRUD + search + validation
 *
 * Auth: Cookie sessions via e2e_admin_session_setup.py
 * Identities: root (ROOT), alice (USER), compliance_admin (ADMIN + content_moderation)
 */
import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const TS = Date.now();

interface SessionData {
  user_sub: string; session_id: string; csrf_token: string; access_token: string;
  cookies: Array<{ name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax"|"Strict"|"None"; expires: number }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function newPage(browser: Browser, identity: string): Promise<Page> {
  const page = await browser.newPage();
  await page.context().addCookies(getSessions()[identity].cookies);
  return page;
}

async function apiPost(page: Page, id: string, path: string, body?: unknown, hdrs?: Record<string, string>) {
  const s = getSessions()[id];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": s.csrf_token, "Content-Type": "application/json", ...hdrs },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${BASE}${path}`, { params });
}

async function apiPut(page: Page, id: string, path: string, body?: unknown) {
  const s = getSessions()[id];
  return page.request.put(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": s.csrf_token, "Content-Type": "application/json" },
  });
}

/** Seed a moderation ticket + fake post into DynamoDB. */
function seedTicket(ticketId: string, contentId: string, offenderId: string): void {
  const now = Math.floor(Date.now() / 1000);
  execSync(`.venv/bin/python3 -c "
import boto3, os
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
from app.core.settings import S
ddb.Table(S.moderation_tickets_table_name).put_item(Item={
    'ticket_id':'${ticketId}','entity_type':'moderation_ticket','content_type':'feed_post',
    'content_id':'${contentId}','status':'open','priority':'medium','queue':'general',
    'report_count':1,'aggregated_topics':['spam'],'latest_report_at':'${now}',
    'latest_report_scope':'ALL','updated_at':'${now}','created_at':'${now}',
    'offender_user_id':'${offenderId}'})
app_table = os.environ.get('APP_TABLE','app_single_table')
ddb.Table(app_table).put_item(Item={
    'pk':'POST#${contentId}','sk':'META','user_sub':'${offenderId}',
    'text':'Spam post for moderation test','created_at':${now}})
"`, { cwd: "/home/ubuntu/testlogon", timeout: 10_000 });
}

// ─── 87. Content Moderation ─────────────────────────────────────────────────

test.describe("87. Content Moderation — admin review + feature flags", () => {
  let alicePage: Page;
  let rootPage: Page;
  let compliancePage: Page;
  const ticketId = `modtk_e2e_${TS}`;
  const contentId = `post_e2e_${TS}`;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
    rootPage = await newPage(browser, "root");
    compliancePage = await newPage(browser, "compliance_admin");
    seedTicket(ticketId, contentId, getSessions()["bob"].user_sub);
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await rootPage?.close();
    await compliancePage?.close();
  });

  test("87.1 Non-admin (Alice) cannot access moderation queue", async () => {
    const resp = await apiGet(alicePage, "/v1/admin/moderation/tickets");
    expect(resp.status()).toBe(403);
  });

  test("87.2 Admin (root) can list moderation tickets", async () => {
    const resp = await apiGet(rootPage, "/v1/admin/moderation/tickets");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items).toBeInstanceOf(Array);
    const ticket = data.items.find((t: any) => t.ticket_id === ticketId);
    expect(ticket).toBeTruthy();
    expect(ticket.content_type).toBe("feed_post");
    expect(ticket.status).toBe("open");
  });

  test("87.3 Compliance admin can view ticket detail", async () => {
    const resp = await apiGet(compliancePage, `/v1/admin/moderation/tickets/${ticketId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ticket.ticket_id).toBe(ticketId);
    expect(data.ticket.content_type).toBe("feed_post");
    expect(data.content_snapshot.exists).toBe(true);
    expect(data.offender_history_summary).toBeTruthy();
  });

  test("87.4 Admin claims and decides warn on the ticket", async () => {
    const claimResp = await apiPost(rootPage, "root", `/v1/admin/moderation/tickets/${ticketId}/claim`);
    expect(claimResp.status()).toBe(200);
    const claimed = await claimResp.json();
    expect(claimed.assigned_admin_user_id).toBe(getSessions()["root"].user_sub);

    const resp = await apiPost(rootPage, "root", `/v1/admin/moderation/tickets/${ticketId}/decision`,
      { decision: "warn", note: `Test warning ${TS}` });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ticket_id).toBe(ticketId);
    expect(data.status).toBe("closed");
  });

  test("87.5 Cannot claim an already-closed ticket", async () => {
    const resp = await apiPost(rootPage, "root", `/v1/admin/moderation/tickets/${ticketId}/claim`);
    expect(resp.status()).toBe(409);
  });

  test("87.6 Root can read and update moderation feature flags", async () => {
    const getResp = await apiGet(rootPage, "/v1/admin/moderation/feature-flags");
    expect(getResp.status()).toBe(200);
    const flags = await getResp.json();
    expect(typeof flags.enabled).toBe("boolean");
    expect(typeof flags.admin_board_enabled).toBe("boolean");

    const newVal = !flags.report_profile_enabled;
    const putResp = await apiPut(rootPage, "root", "/v1/admin/moderation/feature-flags",
      { report_profile_enabled: newVal });
    expect(putResp.status()).toBe(200);
    const updated = await putResp.json();
    expect(updated.report_profile_enabled).toBe(newVal);

    // Restore original value.
    await apiPut(rootPage, "root", "/v1/admin/moderation/feature-flags",
      { report_profile_enabled: flags.report_profile_enabled });
  });
});

// ─── 88. Purchase History ───────────────────────────────────────────────────

test.describe("88. Purchase History — transactions CRUD", () => {
  let alicePage: Page;
  let txnId: string;
  const idemKey = `idem_${TS}`;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("88.1 List transactions returns an array", async () => {
    const resp = await apiGet(alicePage, "/ui/purchase-history/transactions");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data).toBeInstanceOf(Array);
  });

  test("88.2 Create a purchase transaction", async () => {
    const resp = await apiPost(alicePage, "alice", "/ui/purchase-history/transactions",
      { merchant_id: `merchant_${TS}`, external_ref: `ref_${TS}`,
        money: { amount: 29.99, currency: "USD" }, description: `Test purchase ${TS}` },
      { "X-Idempotency-Key": idemKey });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.txn_id).toBeTruthy();
    expect(data.status).toBe("PENDING");
    txnId = data.txn_id;
  });

  test("88.3 Transaction appears in list with correct fields", async () => {
    const resp = await apiGet(alicePage, "/ui/purchase-history/transactions", { limit: "100" });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as any[];
    const found = data.find((t) => t.txn_id === txnId);
    expect(found).toBeTruthy();
    expect(found.amount).toBe(29.99);
    expect(found.currency).toBe("USD");
    expect(found.description).toBe(`Test purchase ${TS}`);
    expect(found.merchant_id).toBe(`merchant_${TS}`);
  });

  test("88.4 Search transactions by description", async () => {
    const resp = await apiGet(alicePage, "/ui/purchase-history/transactions/search",
      { q: `Test purchase ${TS}` });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as any[];
    const found = data.find((t) => t.txn_id === txnId);
    expect(found).toBeTruthy();
    expect(found.description).toBe(`Test purchase ${TS}`);
  });

  test("88.5 Create with missing idempotency key returns 400", async () => {
    const resp = await apiPost(alicePage, "alice", "/ui/purchase-history/transactions",
      { merchant_id: "m", money: { amount: 1, currency: "USD" } });
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(data.detail.code).toBe("idempotency_key_required");
  });
});
