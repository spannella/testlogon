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

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await injectAuth(page, identity);
  return page;
}

const ROOT_ID = "root";
const CHARLIE_ADMIN_ID = "charlie_admin";
const ALICE_ID = "alice";

// ─── PLATFORM-006: Email Delivery Admin Dashboard ───────────────────────────

test.describe("83 · Email Delivery — Admin monitoring API", () => {
  let rootPage: Page;
  let adminPage: Page;
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, ROOT_ID);
    adminPage = await newIdentityPage(browser, CHARLIE_ADMIN_ID);
    alicePage = await newIdentityPage(browser, ALICE_ID);
  });

  test.afterAll(async () => {
    await rootPage?.context().close();
    await adminPage?.context().close();
    await alicePage?.context().close();
  });

  test("83.1 GET /stats returns email delivery metrics", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/email/stats", { days: "7" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.period_days).toBe(7);
    expect(typeof body.sent).toBe("number");
    expect(typeof body.bounced).toBe("number");
    expect(typeof body.complained).toBe("number");
    expect(typeof body.failed).toBe("number");
    expect(typeof body.suppressed).toBe("number");
    expect(typeof body.total).toBe("number");
    expect(typeof body.bounce_rate).toBe("number");
    expect(typeof body.complaint_rate).toBe("number");
    expect(typeof body.success_rate).toBe("number");
    expect(body.sent).toBeGreaterThanOrEqual(0);
  });

  test("83.2 GET /stats accepts custom days parameter", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/email/stats", { days: "30" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.period_days).toBe(30);
  });

  test("83.3 GET /deliveries returns paginated list", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/email/deliveries", { limit: "10" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body).toHaveProperty("items");
    expect(body.items).toBeInstanceOf(Array);
    expect(body).toHaveProperty("next_cursor");
  });

  test("83.4 GET /bounces returns bounce list", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/email/bounces", { limit: "10" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body).toHaveProperty("items");
    expect(body.items).toBeInstanceOf(Array);
  });

  test("83.5 GET /complaints returns complaint list", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/email/complaints", { limit: "10" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body).toHaveProperty("items");
    expect(body.items).toBeInstanceOf(Array);
  });

  test("83.6 GET /suppressed returns suppression list", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/email/suppressed");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body).toHaveProperty("items");
    expect(body).toHaveProperty("count");
    expect(body.items).toBeInstanceOf(Array);
    expect(typeof body.count).toBe("number");
  });

  test("83.7 GET /dev-log returns logged emails in dev mode", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/email/dev-log", { limit: "50" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body).toHaveProperty("entries");
    expect(body).toHaveProperty("count");
    expect(body.entries).toBeInstanceOf(Array);
    expect(typeof body.count).toBe("number");
  });

  test("83.8 GET /preview renders email template", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/email/preview", {
      event_type: "login.success",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.event_type).toBe("login.success");
    expect(typeof body.available).toBe("boolean");
  });

  test("83.9 Admin (charlie) can access email stats", async () => {
    const resp = await apiGet(adminPage, "/ui/admin/email/stats");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(typeof body.sent).toBe("number");
  });

  test("83.10 Non-admin (alice) gets 403 on email stats", async () => {
    const resp = await apiGet(alicePage, "/ui/admin/email/stats");
    expect([401, 403]).toContain(resp.status());
  });

  test("83.11 Non-admin (alice) gets 403 on email deliveries", async () => {
    const resp = await apiGet(alicePage, "/ui/admin/email/deliveries");
    expect([401, 403]).toContain(resp.status());
  });

  test("83.12 Non-admin (alice) gets 403 on dev-log", async () => {
    const resp = await apiGet(alicePage, "/ui/admin/email/dev-log");
    expect([401, 403]).toContain(resp.status());
  });

  test("83.13 Non-admin (alice) gets 403 on email preview", async () => {
    const resp = await apiGet(alicePage, "/ui/admin/email/preview");
    expect([401, 403]).toContain(resp.status());
  });
});
