import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");


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
    _sessions = loadSessions();
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

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await injectAuth(page, identity);
  return page;
}

const ROOT_ID = "root";
const ALICE_ID = "alice";

// ---------------------------------------------------------------------------
// Section 77: Background Job Dashboard
// ---------------------------------------------------------------------------
test.describe("77 · Job Dashboard — Admin background task monitoring", () => {
  let rootPage: Page;
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, ROOT_ID);
    alicePage = await newIdentityPage(browser, ALICE_ID);
  });

  test.afterAll(async () => {
    await rootPage?.context().close();
    await alicePage?.context().close();
  });

  test("77.1 GET /ui/admin/jobs/status returns job list", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/jobs/status");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body).toBeTruthy();
    expect(typeof body).toBe("object");
    // Response has tasks, queues, and timestamp
    expect(body).toHaveProperty("tasks");
    expect(body).toHaveProperty("queues");
    expect(body).toHaveProperty("timestamp");
  });

  test("77.2 Job status includes expected task fields", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/jobs/status");
    const body = await resp.json();
    const tasks = body.tasks;
    // tasks is an object mapping task names to their status
    expect(typeof tasks).toBe("object");
    const taskNames = Object.keys(tasks);
    if (taskNames.length > 0) {
      const first = tasks[taskNames[0]];
      expect(first).toHaveProperty("name");
      expect(first).toHaveProperty("status");
      expect(first).toHaveProperty("enabled");
    }
  });

  test("77.3 Job status includes queue depths", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/jobs/status");
    const body = await resp.json();
    const queues = body.queues;
    expect(queues).toHaveProperty("scheduled_actions");
    expect(queues.scheduled_actions).toHaveProperty("pending");
    expect(queues.scheduled_actions).toHaveProperty("failed");
  });

  test("77.4 GET /ui/admin/jobs/failed returns items array", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/jobs/failed");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    // Response shape is { items: [...], count: N }
    expect(body).toHaveProperty("items");
    expect(body).toHaveProperty("count");
    expect(Array.isArray(body.items)).toBe(true);
    expect(body.count).toBe(body.items.length);
  });

  test("77.5 GET task detail for non-existent task returns 404", async () => {
    const resp = await apiGet(
      rootPage,
      "/ui/admin/jobs/task/nonexistent_task_name_xyz",
    );
    expect(resp.status()).toBe(404);
  });

  test("77.6 Non-admin user gets 403 on job status", async () => {
    const resp = await apiGet(alicePage, "/ui/admin/jobs/status");
    expect(resp.status()).toBe(403);
  });

  test("77.7 Non-admin user gets 403 on failed jobs", async () => {
    const resp = await apiGet(alicePage, "/ui/admin/jobs/failed");
    expect(resp.status()).toBe(403);
  });
});
