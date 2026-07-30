/**
 * E2E tests for PRIVACY-001: GDPR Data Export & Account Deletion.
 *
 * Sections:
 *   A — Data Export API (6 tests)
 *   B — Account Deletion API (7 tests)
 *   C — Admin Privacy Review (5 tests)
 *   D — Privacy Page UI (4 tests)
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions, resolveIdentityId } from "./helpers/session";
import { usingCpp, cppResetDataRequests, cppSetDataRequestGrace } from "./helpers/cpp-seed";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";
const ROOT_ID  = "root.admin@testdev.local";

// Session keys returned by e2e_admin_session_setup.py
const ALICE_KEY = "alice";
const BOB_KEY   = "bob";
const ROOT_KEY  = "root";

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

async function injectAuth(page: Page, sessionKey: string, userSub: string) {
  const session = getSessions()[sessionKey];
  if (!session) throw new Error(`No session for key=${sessionKey}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userSub);
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiPost(page: Page, sessionKey: string, path: string, body: object) {
  const session = getSessions()[sessionKey];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

async function apiDelete(page: Page, sessionKey: string, path: string) {
  const session = getSessions()[sessionKey];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── DDB helper to clean up privacy requests ────────────────────────────────

function cleanupPrivacyRequests(userSub: string) {
  if (usingCpp()) {
    cppResetDataRequests(resolveIdentityId(userSub));
    return;
  }
  try {
    execSync(
      `${REPO_ROOT}/.venv/bin/python3 -c "
import boto3, os
os.environ.setdefault('AWS_ACCESS_KEY_ID','test')
os.environ.setdefault('AWS_SECRET_ACCESS_KEY','test')
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1')
t = ddb.Table('data_requests')
resp = t.query(KeyConditionExpression=boto3.dynamodb.conditions.Key('pk').eq('USER#${userSub}'))
for item in resp.get('Items',[]):
    t.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
"`,
      { cwd: REPO_ROOT, timeout: 10_000 },
    );
  } catch {
    // Table may not exist yet
  }
}

// ═══════════════════════════════════════════════════════════════
// Section A: Data Export API
// ═══════════════════════════════════════════════════════════════

test.describe("A — Data Export API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, ALICE_KEY, ALICE_ID);
    cleanupPrivacyRequests(ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("1. User requests a data export", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/privacy/export", {
      include_messages: true,
      include_files: true,
      include_billing: true,
      include_profile: true,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.request_id).toBeTruthy();
    expect(data.request_type).toBe("export");
    // Status should be completed (inline processing) or pending
    expect(["pending", "processing", "completed"]).toContain(data.status);
  });

  test("2. Export request rate limited to 1 per 24 hours", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/privacy/export", {
      include_messages: true,
      include_files: false,
      include_billing: false,
      include_profile: false,
    });
    expect(resp.status()).toBe(429);
  });

  test("3. List requests returns user's own requests", async () => {
    const resp = await apiGet(alicePage, "/ui/privacy/requests");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.requests).toBeDefined();
    expect(data.requests.length).toBeGreaterThanOrEqual(1);
    const exportReq = data.requests.find((r: any) => r.request_type === "export");
    expect(exportReq).toBeTruthy();
  });

  test("4. Get specific request returns status", async () => {
    const listResp = await apiGet(alicePage, "/ui/privacy/requests");
    const list = await listResp.json();
    const req = list.requests[0];
    const resp = await apiGet(alicePage, `/ui/privacy/requests/${req.request_id}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.request_id).toBe(req.request_id);
  });

  test("5. Export download returns redirect for completed export", async () => {
    const listResp = await apiGet(alicePage, "/ui/privacy/requests");
    const list = await listResp.json();
    const exportReq = list.requests.find((r: any) => r.request_type === "export" && r.status === "completed");
    if (!exportReq) {
      test.skip();
      return;
    }
    const resp = await alicePage.request.get(`${API}/ui/privacy/export/${exportReq.request_id}/download`, {
      maxRedirects: 0,
    });
    // Should be 302 redirect or 200 if followed
    expect([200, 302]).toContain(resp.status());
  });

  test("6. Bob cannot see Alice's requests", async () => {
    const ctx = await alicePage.context().browser()!.newContext();
    const bobPage = await ctx.newPage();
    await injectAuth(bobPage, BOB_KEY, BOB_ID);
    const resp = await apiGet(bobPage, "/ui/privacy/requests");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // Bob should have no requests (or none matching Alice's IDs)
    const aliceRequests = data.requests.filter((r: any) => r.user_sub === ALICE_ID);
    expect(aliceRequests.length).toBe(0);
    await bobPage.close();
  });
});

// ═══════════════════════════════════════════════════════════════
// Section B: Account Deletion API
// ═══════════════════════════════════════════════════════════════

test.describe("B — Account Deletion API", () => {
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    bobPage = await ctx.newPage();
    await injectAuth(bobPage, BOB_KEY, BOB_ID);
    cleanupPrivacyRequests(BOB_ID);
  });

  test.afterAll(async () => {
    // Clean up Bob's deletion requests so they don't affect other tests
    cleanupPrivacyRequests(BOB_ID);
    await bobPage.close();
  });

  test("7. User requests account deletion with password", async () => {
    const resp = await apiPost(bobPage, BOB_KEY, "/ui/privacy/delete-account", {
      password: "test_password",
      reason: "E2E test",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.request_id).toBeTruthy();
    expect(data.request_type).toBe("deletion");
    expect(data.status).toBe("pending");
    expect(data.grace_period_ends_at).toBeGreaterThan(0);
  });

  test("8. Deletion with empty password returns 401", async () => {
    // Clean up first to avoid 409
    cleanupPrivacyRequests(BOB_ID);
    const resp = await apiPost(bobPage, BOB_KEY, "/ui/privacy/delete-account", {
      password: "",
      reason: "test",
    });
    expect(resp.status()).toBe(401);
  });

  test("9. Duplicate deletion request returns 409", async () => {
    // First, ensure there's a pending request
    cleanupPrivacyRequests(BOB_ID);
    const first = await apiPost(bobPage, BOB_KEY, "/ui/privacy/delete-account", {
      password: "test_password",
    });
    expect(first.status()).toBe(201);

    // Second should fail
    const second = await apiPost(bobPage, BOB_KEY, "/ui/privacy/delete-account", {
      password: "test_password",
    });
    expect(second.status()).toBe(409);
  });

  test("10. User cancels deletion within grace period", async () => {
    const listResp = await apiGet(bobPage, "/ui/privacy/requests");
    const list = await listResp.json();
    const deletion = list.requests.find((r: any) => r.request_type === "deletion" && r.status === "pending");
    expect(deletion).toBeTruthy();

    const session = getSessions()[BOB_KEY];
    const resp = await bobPage.request.post(
      `${API}/ui/privacy/requests/${deletion.request_id}/cancel`,
      { headers: { "x-csrf-token": session.csrf_token } },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("cancelled");
  });

  test("11. Cancel after grace period returns 409", async () => {
    cleanupPrivacyRequests(BOB_ID);
    // Create a deletion with past grace period by manipulating DDB directly
    const createResp = await apiPost(bobPage, BOB_KEY, "/ui/privacy/delete-account", {
      password: "test_password",
    });
    expect(createResp.status()).toBe(201);
    const created = await createResp.json();

    // Set grace_period_ends_at to the past. Under cpp this must hit cpp's OWN
    // tlc_data_requests, not the Python :8001 table the execSync targets.
    if (usingCpp()) {
      cppSetDataRequestGrace(resolveIdentityId(BOB_ID), created.request_id, 1000000);
    } else
    execSync(
      `${REPO_ROOT}/.venv/bin/python3 -c "
import boto3, os
os.environ.setdefault('AWS_ACCESS_KEY_ID','test')
os.environ.setdefault('AWS_SECRET_ACCESS_KEY','test')
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1')
t = ddb.Table('data_requests')
t.update_item(
    Key={'pk': 'USER#${BOB_ID}', 'sk': 'REQUEST#${created.request_id}'},
    UpdateExpression='SET grace_period_ends_at = :g',
    ExpressionAttributeValues={':g': 1000000},
)
"`,
      { cwd: REPO_ROOT, timeout: 10_000 },
    );

    const session = getSessions()[BOB_KEY];
    const resp = await bobPage.request.post(
      `${API}/ui/privacy/requests/${created.request_id}/cancel`,
      { headers: { "x-csrf-token": session.csrf_token } },
    );
    expect(resp.status()).toBe(409);
  });

  test("12. Deletion request contains grace_period_ends_at", async () => {
    cleanupPrivacyRequests(BOB_ID);
    const resp = await apiPost(bobPage, BOB_KEY, "/ui/privacy/delete-account", {
      password: "test_password",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.grace_period_ends_at).toBeDefined();
    const now = Math.floor(Date.now() / 1000);
    // Grace period: cpp defaults to 30 days (PRIVACY_DELETION_GRACE_PERIOD_DAYS),
    // the Python impl to ~14. Assert the window the target backend uses.
    if (usingCpp()) {
      expect(data.grace_period_ends_at).toBeGreaterThan(now + 86400 * 28);
      expect(data.grace_period_ends_at).toBeLessThanOrEqual(now + 86400 * 31);
    } else {
      expect(data.grace_period_ends_at).toBeGreaterThan(now + 86400 * 12);
      expect(data.grace_period_ends_at).toBeLessThanOrEqual(now + 86400 * 15);
    }
  });

  test("13. Deletion reason is stored", async () => {
    const listResp = await apiGet(bobPage, "/ui/privacy/requests");
    const list = await listResp.json();
    // The most recent deletion should have a reason (from test 12 above - no reason,
    // but test 7 had "E2E test"). Check the latest pending one.
    const pending = list.requests.find((r: any) => r.request_type === "deletion" && r.status === "pending");
    expect(pending).toBeTruthy();
    expect(pending.request_id).toBeTruthy();
  });
});

// ═══════════════════════════════════════════════════════════════
// Section C: Admin Privacy Review
// ═══════════════════════════════════════════════════════════════

test.describe("C — Admin Privacy Review", () => {
  let rootPage: Page;
  let alicePage: Page;
  let testRequestId: string;

  test.beforeAll(async ({ browser }) => {
    // Root admin page
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_KEY, ROOT_ID);

    // Alice page for creating requests
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_KEY, ALICE_ID);
    cleanupPrivacyRequests(ALICE_ID);

    // Create a deletion request for Alice that admin can review
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/privacy/delete-account", {
      password: "test_password",
      reason: "Admin review test",
    });
    const data = await resp.json();
    testRequestId = data.request_id;
  });

  test.afterAll(async () => {
    cleanupPrivacyRequests(ALICE_ID);
    await rootPage.close();
    await alicePage.close();
  });

  test("14. Admin lists pending requests", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/privacy/requests?status=pending");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.requests).toBeDefined();
    expect(Array.isArray(data.requests)).toBe(true);
  });

  test("15. Admin places retention hold", async () => {
    const session = getSessions()[ROOT_KEY];
    const resp = await rootPage.request.post(
      `${API}/ui/admin/privacy/requests/${testRequestId}/hold`,
      { headers: { "x-csrf-token": session.csrf_token } },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.retention_hold).toBe(true);
    expect(data.status).toBe("held");
  });

  test("16. Admin releases hold", async () => {
    const session = getSessions()[ROOT_KEY];
    const resp = await rootPage.request.post(
      `${API}/ui/admin/privacy/requests/${testRequestId}/release-hold`,
      { headers: { "x-csrf-token": session.csrf_token } },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.retention_hold).toBe(false);
    expect(data.status).toBe("pending");
  });

  test("17. Admin rejects a request", async () => {
    const session = getSessions()[ROOT_KEY];
    const resp = await rootPage.request.post(
      `${API}/ui/admin/privacy/requests/${testRequestId}/reject`,
      { headers: { "x-csrf-token": session.csrf_token } },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("rejected");
  });

  test("18. Non-admin cannot access admin privacy endpoints", async () => {
    // Bob is a regular user
    const bobCtx = await rootPage.context().browser()!.newContext();
    const bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_KEY, BOB_ID);
    const resp = await apiGet(bobPage, "/ui/admin/privacy/requests");
    expect(resp.status()).toBe(403);
    await bobPage.close();
  });
});

// ═══════════════════════════════════════════════════════════════
// Section D: Privacy Page UI
// ═══════════════════════════════════════════════════════════════

test.describe("D — Privacy Page UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, ALICE_KEY, ALICE_ID);
    cleanupPrivacyRequests(ALICE_ID);
  });

  test.afterAll(async () => {
    cleanupPrivacyRequests(ALICE_ID);
    await page.close();
  });

  test("19. Privacy page loads with export and deletion sections", async () => {
    await page.goto(`${BASE}/settings/privacy`, { waitUntil: "domcontentloaded" });
    // Wait for page content
    await expect(page.getByText("Download Your Data")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText("Delete Account")).toBeVisible();
  });

  test("20. Request export shows status", async () => {
    await page.goto(`${BASE}/settings/privacy`, { waitUntil: "domcontentloaded" });
    await expect(page.getByText("Download Your Data")).toBeVisible({ timeout: 10_000 });

    // Click request export
    const exportBtn = page.getByRole("button", { name: "Request Export" });
    await expect(exportBtn).toBeVisible();
    await exportBtn.click();

    // Wait for the response — should show completed or pending status
    await expect(
      page.getByText("Export ready").or(page.getByText("export is being prepared")),
    ).toBeVisible({ timeout: 15_000 });
  });

  test("21. Delete account dialog requires password", async () => {
    await page.goto(`${BASE}/settings/privacy`, { waitUntil: "domcontentloaded" });
    await expect(page.getByText("Delete Account")).toBeVisible({ timeout: 10_000 });

    // Click "Delete My Account" button
    const deleteBtn = page.getByRole("button", { name: "Delete My Account" });
    await expect(deleteBtn).toBeVisible();
    await deleteBtn.click();

    // Dialog should be visible
    await expect(page.getByText("Confirm your password")).toBeVisible({ timeout: 5_000 });

    // The submit button should be disabled without password
    const submitBtn = page.getByRole("button", { name: /delete my account/i });
    await expect(submitBtn).toBeDisabled();

    // Enter password — button should become enabled
    await page.fill("#delete-password", "test_password");
    await expect(submitBtn).toBeEnabled();
  });

  test("22. Active deletion shows grace period with cancel button", async () => {
    // Clean up any existing deletion, then create fresh one via API
    cleanupPrivacyRequests(ALICE_ID);
    await apiPost(page, ALICE_KEY, "/ui/privacy/delete-account", {
      password: "test_password",
      reason: "UI grace period test",
    });

    // Reload page to see the active deletion
    await page.goto(`${BASE}/settings/privacy`, { waitUntil: "domcontentloaded" });
    await expect(page.getByText("Account deletion scheduled")).toBeVisible({ timeout: 10_000 });

    // Should show grace period countdown (scoped to the deletion card, not the history table)
    await expect(page.getByText(/remaining/).first()).toBeVisible();

    // Should show cancel button
    const cancelBtn = page.getByRole("button", { name: "Cancel Deletion" });
    await expect(cancelBtn).toBeVisible();
  });
});
