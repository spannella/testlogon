import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const API = "http://localhost:8000";
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
    const raw = execSync("python3 " + REPO_ROOT + "/e2e_admin_session_setup.py", {
      cwd: REPO_ROOT, timeout: 30_000,
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
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": s.csrf_token },
  });
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await injectAuth(page, identity);
  return page;
}

const ROOT_ID = "root";
const CHARLIE_ADMIN_ID = "charlie_admin";
const ALICE_ID = "alice";

// ─── PLATFORM-007: SMS Delivery Admin Dashboard ────────────────────────────

test.describe("84 · SMS Delivery — Admin monitoring API", () => {
  let rootPage: Page;
  let adminPage: Page;
  let alicePage: Page;
  const TEST_PHONE = `+1555${TS.toString().slice(-7)}`;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, ROOT_ID);
    adminPage = await newIdentityPage(browser, CHARLIE_ADMIN_ID);
    alicePage = await newIdentityPage(browser, ALICE_ID);
  });

  test.afterAll(async () => {
    // Clean up test suppression
    await apiDelete(rootPage, ROOT_ID, `/ui/admin/sms/suppressed/${encodeURIComponent(TEST_PHONE)}`);
    await rootPage?.context().close();
    await adminPage?.context().close();
    await alicePage?.context().close();
  });

  test("84.1 GET /stats returns SMS delivery metrics", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/sms/stats", { days: "7" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.period_days).toBe(7);
    expect(typeof body.sent).toBe("number");
    expect(typeof body.failed).toBe("number");
    expect(typeof body.total).toBe("number");
    expect(typeof body.total_segments).toBe("number");
    expect(typeof body.estimated_cost_usd).toBe("number");
    expect(typeof body.suppressed_numbers).toBe("number");
    expect(typeof body.success_rate).toBe("number");
    expect(body.sent).toBeGreaterThanOrEqual(0);
  });

  test("84.2 GET /stats accepts custom days parameter", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/sms/stats", { days: "30" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.period_days).toBe(30);
  });

  test("84.3 GET /deliveries returns paginated list", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/sms/deliveries", { limit: "10" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body).toHaveProperty("items");
    expect(body.items).toBeInstanceOf(Array);
    expect(body).toHaveProperty("next_cursor");
  });

  test("84.4 GET /failures returns failure list", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/sms/failures", { limit: "10" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body).toHaveProperty("items");
    expect(body.items).toBeInstanceOf(Array);
  });

  test("84.5 GET /suppressed returns suppression list", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/sms/suppressed");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body).toHaveProperty("items");
    expect(body).toHaveProperty("count");
    expect(body.items).toBeInstanceOf(Array);
    expect(typeof body.count).toBe("number");
  });

  test("84.6 POST + GET + DELETE suppression lifecycle", async () => {
    // Suppress a phone number
    const suppressResp = await apiPost(rootPage, ROOT_ID, `/ui/admin/sms/suppressed/${encodeURIComponent(TEST_PHONE)}`, {});
    expect(suppressResp.status()).toBe(200);
    const suppressBody = await suppressResp.json();
    expect(suppressBody.ok).toBe(true);
    expect(suppressBody.suppressed).toBe(true);

    // Check suppression
    const checkResp = await apiGet(rootPage, `/ui/admin/sms/suppressed/${encodeURIComponent(TEST_PHONE)}`);
    expect(checkResp.status()).toBe(200);
    const checkBody = await checkResp.json();
    expect(checkBody.phone).toBe(TEST_PHONE);
    expect(checkBody.suppressed).toBe(true);

    // Remove suppression
    const delResp = await apiDelete(rootPage, ROOT_ID, `/ui/admin/sms/suppressed/${encodeURIComponent(TEST_PHONE)}`);
    expect(delResp.status()).toBe(200);
    const delBody = await delResp.json();
    expect(delBody.ok).toBe(true);
    expect(delBody.suppressed).toBe(false);

    // Verify removed
    const recheckResp = await apiGet(rootPage, `/ui/admin/sms/suppressed/${encodeURIComponent(TEST_PHONE)}`);
    expect(recheckResp.status()).toBe(200);
    const recheckBody = await recheckResp.json();
    expect(recheckBody.suppressed).toBe(false);
  });

  test("84.7 GET /dev-log returns dev SMS log entries", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/sms/dev-log");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body).toHaveProperty("entries");
    expect(body).toHaveProperty("count");
    expect(body.entries).toBeInstanceOf(Array);
    expect(typeof body.count).toBe("number");
  });

  test("84.8 Admin (charlie) can access SMS stats", async () => {
    const resp = await apiGet(adminPage, "/ui/admin/sms/stats");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(typeof body.sent).toBe("number");
  });

  test("84.9 Non-admin (alice) gets 403 on SMS stats", async () => {
    const resp = await apiGet(alicePage, "/ui/admin/sms/stats");
    expect([401, 403]).toContain(resp.status());
  });

  test("84.10 Non-admin (alice) gets 403 on SMS deliveries", async () => {
    const resp = await apiGet(alicePage, "/ui/admin/sms/deliveries");
    expect([401, 403]).toContain(resp.status());
  });

  test("84.11 Non-admin (alice) gets 403 on dev-log", async () => {
    const resp = await apiGet(alicePage, "/ui/admin/sms/dev-log");
    expect([401, 403]).toContain(resp.status());
  });

  test("84.12 Non-admin (alice) gets 403 on suppression check", async () => {
    const resp = await apiGet(alicePage, `/ui/admin/sms/suppressed/${encodeURIComponent("+15551234567")}`);
    expect([401, 403]).toContain(resp.status());
  });
});
