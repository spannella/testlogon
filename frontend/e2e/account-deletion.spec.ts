/**
 * E2E tests for PLATFORM-018 Privacy & Account Deletion.
 *
 * Section 531: Password / confirm-text verification API
 * Section 532: Deletion request lifecycle API (create / cancel / grace expiry)
 * Section 533: Data export API
 * Section 534: Admin deletion management API (list / hold / release / audit / process-due)
 * Section 535: Privacy / Account Deletion page UI
 *
 * Auth: cookie-based sessions seeded by e2e_admin_session_setup.py. The user
 * side of the lifecycle is driven on Bob (a throwaway from this subsystem's
 * point of view — finalization is non-destructive in dev so Bob's real data
 * is never touched). Negative role checks use Alice. Admin uses root.
 *
 * Endpoints are all under /ui/privacy/account-deletion (+ /ui/admin/...),
 * backed by the dedicated account_deletion_requests table — distinct from the
 * pre-existing /ui/privacy/* GDPR feature.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";
const BOB_ID = "e2e_bob@test.local";
const ALICE_ID = "e2e_alice@test.local";
const BASE = "ui/privacy/account-deletion";
const ADMIN = "ui/admin/privacy/account-deletion";

interface SessionData {
  user_sub: string;
  csrf_token: string;
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

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const page = await browser.newPage();
  await page.context().addCookies(getSessions()[identity].cookies);
  return page;
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

/** Remove all account-deletion rows for a user (clean slate between runs). */
function cleanupUser(userSub: string): void {
  execSync(
    `python3 -c "
import boto3, os
from pathlib import Path
env = Path('/home/ubuntu/testlogon/.env.local')
for line in env.read_text().splitlines():
    line=line.strip()
    if line and not line.startswith('#') and '=' in line:
        k,v=line.split('=',1); os.environ.setdefault(k.strip(), v.strip())
ddb=boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
t=ddb.Table(os.environ.get('ACCOUNT_DELETION_REQUESTS_TABLE_NAME','account_deletion_requests'))
resp=t.query(KeyConditionExpression=boto3.dynamodb.conditions.Key('pk').eq('USER#${userSub}'))
for it in resp.get('Items', []):
    t.delete_item(Key={'pk':it['pk'],'sk':it['sk']})
print('cleaned')
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  );
}

/** Force a request's scheduled_for into the past so it becomes due. */
function expireGrace(userSub: string, requestId: string): void {
  execSync(
    `python3 -c "
import boto3, os, time
from pathlib import Path
env = Path('/home/ubuntu/testlogon/.env.local')
for line in env.read_text().splitlines():
    line=line.strip()
    if line and not line.startswith('#') and '=' in line:
        k,v=line.split('=',1); os.environ.setdefault(k.strip(), v.strip())
ddb=boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
t=ddb.Table(os.environ.get('ACCOUNT_DELETION_REQUESTS_TABLE_NAME','account_deletion_requests'))
t.update_item(Key={'pk':'USER#${userSub}','sk':'REQUEST#${requestId}'}, UpdateExpression='SET scheduled_for=:s', ExpressionAttributeValues={':s': int(time.time())-10})
print('expired')
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  );
}

// ─── 531. Password / confirm-text verification API ───────────────────────────

test.describe("531. Account deletion — password / confirm verification", () => {
  let bob: Page;
  test.beforeAll(async ({ browser }) => { getSessions(); cleanupUser(BOB_ID); bob = await newIdentityPage(browser, "bob"); });
  test.afterAll(async () => { cleanupUser(BOB_ID); await bob?.close(); });

  test("531.1 empty password returns 401/422", async () => {
    const r = await apiPost(bob, "bob", `${BASE}/request`, { password: "", confirm_text: "DELETE MY ACCOUNT" });
    expect([401, 422]).toContain(r.status());
  });

  test("531.3 missing confirm_text returns 422", async () => {
    const r = await apiPost(bob, "bob", `${BASE}/request`, { password: "pw" });
    expect(r.status()).toBe(422);
  });

  test("531.4 wrong confirm_text returns 422", async () => {
    const r = await apiPost(bob, "bob", `${BASE}/request`, { password: "pw", confirm_text: "delete" });
    expect(r.status()).toBe(422);
  });
});

// ─── 532. Deletion request lifecycle API ─────────────────────────────────────

test.describe("532. Account deletion — lifecycle", () => {
  let bob: Page;
  test.beforeAll(async ({ browser }) => { getSessions(); cleanupUser(BOB_ID); bob = await newIdentityPage(browser, "bob"); });
  test.afterAll(async () => { cleanupUser(BOB_ID); await bob?.close(); });

  test("532.1 create deletion request sets pending + future scheduled_for", async () => {
    const r = await apiPost(bob, "bob", `${BASE}/request`, { password: "pw", confirm_text: "DELETE MY ACCOUNT", reason: "leaving" });
    expect(r.status()).toBe(201);
    const body = await r.json();
    expect(body.status).toBe("pending");
    expect(body.scheduled_for).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(body.can_cancel).toBe(true);
  });

  test("532.2 cannot create a second pending deletion (409)", async () => {
    const r = await apiPost(bob, "bob", `${BASE}/request`, { password: "pw", confirm_text: "DELETE MY ACCOUNT" });
    expect(r.status()).toBe(409);
  });

  test("532.3 cancel during grace period (200 -> cancelled)", async () => {
    const list = await (await apiGet(bob, `${BASE}/requests`)).json();
    const req = list.requests.find((x: any) => x.status === "pending");
    expect(req).toBeTruthy();
    const r = await apiPost(bob, "bob", `${BASE}/requests/${req.request_id}/cancel`);
    expect(r.status()).toBe(200);
    expect((await r.json()).status).toBe("cancelled");
  });

  test("532.4 cancel after grace expiry returns 409", async () => {
    const created = await (await apiPost(bob, "bob", `${BASE}/request`, { password: "pw", confirm_text: "DELETE MY ACCOUNT" })).json();
    expireGrace(BOB_ID, created.request_id);
    const r = await apiPost(bob, "bob", `${BASE}/requests/${created.request_id}/cancel`);
    expect(r.status()).toBe(409);
  });

  test("532.5 list requests includes the request with all fields", async () => {
    const list = await (await apiGet(bob, `${BASE}/requests`)).json();
    expect(list.total).toBeGreaterThanOrEqual(1);
    expect(list.requests[0]).toHaveProperty("request_id");
    expect(list.requests[0]).toHaveProperty("status");
    expect(list.requests[0]).toHaveProperty("scheduled_for");
  });
});

// ─── 533. Data export API ────────────────────────────────────────────────────

test.describe("533. Privacy data export", () => {
  let bob: Page;
  test.beforeAll(async ({ browser }) => { getSessions(); cleanupUser(BOB_ID); bob = await newIdentityPage(browser, "bob"); });
  test.afterAll(async () => { cleanupUser(BOB_ID); await bob?.close(); });

  test("533.1 create export with all categories (201, completed)", async () => {
    const cats = { profile: true, messages: true, posts: true, billing: true, files: true, contacts: true, calendar: true, subscriptions: true, push_devices: true, tickets: true, sessions: true };
    const r = await apiPost(bob, "bob", `${BASE}/export`, { categories: cats });
    expect(r.status()).toBe(201);
    const body = await r.json();
    expect(body.status).toBe("completed");
    expect(body.categories_requested).toBe(11);
    expect(body.download_expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  test("533.2 export rate limiting prevents rapid repeat (429)", async () => {
    const r = await apiPost(bob, "bob", `${BASE}/export`, { categories: { profile: true } });
    expect(r.status()).toBe(429);
  });

  test("533.5 invalid category name returns 422", async () => {
    cleanupUser(BOB_ID);
    const r = await apiPost(bob, "bob", `${BASE}/export`, { categories: { invalid_cat: true } });
    expect(r.status()).toBe(422);
  });

  test("533.4 selective categories only count chosen ones", async () => {
    cleanupUser(BOB_ID);
    const r = await apiPost(bob, "bob", `${BASE}/export`, { categories: { profile: true, billing: true } });
    expect(r.status()).toBe(201);
    expect((await r.json()).categories_requested).toBe(2);
  });
});

// ─── 534. Admin deletion management API ──────────────────────────────────────

test.describe("534. Admin account-deletion management", () => {
  let root: Page;
  let bob: Page;
  let alice: Page;
  let reqId = "";

  test.beforeAll(async ({ browser }) => {
    getSessions();
    cleanupUser(BOB_ID);
    root = await newIdentityPage(browser, "root");
    bob = await newIdentityPage(browser, "bob");
    alice = await newIdentityPage(browser, "alice");
    const created = await (await apiPost(bob, "bob", `${BASE}/request`, { password: "pw", confirm_text: "DELETE MY ACCOUNT" })).json();
    reqId = created.request_id;
  });
  test.afterAll(async () => { cleanupUser(BOB_ID); await root?.close(); await bob?.close(); await alice?.close(); });

  test("534.1 admin lists pending deletion requests", async () => {
    const r = await apiGet(root, `${ADMIN}/requests`, { status: "pending" });
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(body.requests.some((x: any) => x.request_id === reqId)).toBe(true);
  });

  test("534.2 admin places retention hold", async () => {
    const r = await apiPost(root, "root", `${ADMIN}/requests/${reqId}/hold`, { reason: "fraud investigation case 1" });
    expect(r.status()).toBe(200);
    expect((await r.json()).retention_hold).toBe(true);
  });

  test("534.6 retention hold blocks finalize even after grace expiry", async () => {
    expireGrace(BOB_ID, reqId);
    const r = await apiPost(root, "root", `${ADMIN}/process-due`);
    expect(r.status()).toBe(200);
    const status = await (await apiGet(bob, `${BASE}/requests/${reqId}`)).json();
    expect(status.status).toBe("pending"); // still held, not completed
  });

  test("534.3 admin releases retention hold", async () => {
    const r = await apiPost(root, "root", `${ADMIN}/requests/${reqId}/release-hold`);
    expect(r.status()).toBe(200);
    expect((await r.json()).retention_hold).toBe(false);
  });

  test("534.7 after release, process-due finalizes the due request", async () => {
    const r = await apiPost(root, "root", `${ADMIN}/process-due`);
    expect(r.status()).toBe(200);
    const status = await (await apiGet(bob, `${BASE}/requests/${reqId}`)).json();
    expect(status.status).toBe("completed");
    expect(status.deletion_summary).toBeTruthy();
  });

  test("534.4 admin views audit trail (created/hold/release/completed)", async () => {
    const r = await apiGet(root, `${ADMIN}/requests/${reqId}/audit`);
    expect(r.status()).toBe(200);
    const events = (await r.json()).events.map((e: any) => e.event_type);
    expect(events).toContain("deletion_requested");
    expect(events).toContain("hold_placed");
    expect(events).toContain("hold_released");
    expect(events).toContain("deletion_completed");
  });

  test("534.5 non-admin cannot place hold (403)", async () => {
    const r = await apiPost(alice, "alice", `${ADMIN}/requests/${reqId}/hold`, { reason: "should fail here" });
    expect(r.status()).toBe(403);
  });

  test("534.8 non-admin cannot view admin list (403)", async () => {
    const r = await apiGet(alice, `${ADMIN}/requests`, { status: "pending" });
    expect(r.status()).toBe(403);
  });
});

// ─── 535. Privacy / Account Deletion page UI ─────────────────────────────────

test.describe("535. Account Deletion page UI", () => {
  test.beforeAll(() => { getSessions(); });
  test.afterAll(() => { cleanupUser(BOB_ID); });

  test.beforeEach(async ({ page }) => {
    // Each UI test must start from a clean slate: a leftover pending deletion
    // request disables the "open delete dialog" button (disabled={!!activeRequest}),
    // causing click() to hang. Wipe rows before every test.
    cleanupUser(BOB_ID);
    await page.context().addCookies(getSessions()["bob"].cookies);
    // Seed the client-side auth store so ProtectedRoute treats the page as
    // authenticated (cookies alone only satisfy server-side API auth).
    await page.goto("/login", { waitUntil: "domcontentloaded" });
    await page.evaluate((uid: string) => {
      const state = { userId: uid, accessToken: null, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    }, getSessions()["bob"].user_sub);
  });

  test("535.1 dialog shows password + confirm inputs", async ({ page }) => {
    await page.goto("/settings/account-deletion");
    await page.getByTestId("open-delete-dialog-btn").click();
    await expect(page.getByTestId("delete-password-input")).toBeVisible();
    await expect(page.getByTestId("delete-confirm-input")).toBeVisible();
    await expect(page.getByTestId("confirm-delete-btn")).toBeVisible();
  });

  test("535.2 confirm button enables only with password + exact confirm text", async ({ page }) => {
    await page.goto("/settings/account-deletion");
    await page.getByTestId("open-delete-dialog-btn").click();
    await expect(page.getByTestId("confirm-delete-btn")).toBeDisabled();
    await page.getByTestId("delete-password-input").fill("secret");
    await page.getByTestId("delete-confirm-input").fill("DELETE MY ACCOUNT");
    await expect(page.getByTestId("confirm-delete-btn")).toBeEnabled();
  });

  test("535.5 export category checkboxes all checked by default", async ({ page }) => {
    await page.goto("/settings/account-deletion");
    for (const key of ["profile", "messages", "billing", "sessions"]) {
      await expect(page.getByTestId(`export-cat-${key}`)).toBeChecked();
    }
  });

  test("535.3 grace countdown + cancel appear after creating a deletion", async ({ page }) => {
    await page.goto("/settings/account-deletion");
    await page.getByTestId("open-delete-dialog-btn").click();
    await page.getByTestId("delete-password-input").fill("secret");
    await page.getByTestId("delete-confirm-input").fill("DELETE MY ACCOUNT");
    await page.getByTestId("confirm-delete-btn").click();
    await expect(page.getByTestId("active-deletion-banner")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId("grace-days-remaining")).toBeVisible();
    await expect(page.getByTestId("cancel-deletion-btn")).toBeEnabled();
  });

  test("535.4 cancel button cancels the active deletion", async ({ page }) => {
    // beforeEach wipes all rows, so create a fresh pending deletion to cancel.
    const r = await apiPost(page, "bob", `${BASE}/request`, { password: "pw", confirm_text: "DELETE MY ACCOUNT" });
    expect(r.ok()).toBeTruthy();
    await page.goto("/settings/account-deletion");
    await expect(page.getByTestId("cancel-deletion-btn")).toBeVisible({ timeout: 10_000 });
    await page.getByTestId("cancel-deletion-btn").click();
    await expect(page.getByTestId("active-deletion-banner")).toBeHidden({ timeout: 10_000 });
  });

  test("535.6 export request shows a download link", async ({ page }) => {
    cleanupUser(BOB_ID);
    await page.goto("/settings/account-deletion");
    await page.getByTestId("request-export-btn").click();
    await expect(page.getByTestId("export-download-link")).toBeVisible({ timeout: 10_000 });
  });
});
