/**
 * E2E tests for the SuiteCRM ACTIVITIES (ACT) frontend.
 *
 * Cluster routers (live backend — gated by S.crm_activities_enabled + per-module flag):
 *   /ui/calls/logs      (ACT-006/007 — call logs)
 *   /ui/crm/tasks       (ACT-008 — tasks)
 *   /ui/crm/timeline    (ACT-009 — activity timeline)
 *   /ui/crm/notes       (ACT-010 — notes)
 *
 * Flags default OFF — when disabled the API returns 404 and the UI shows a
 * graceful "not enabled" state. These tests assert behaviour that holds in
 * BOTH states (enabled → data flows; disabled → not-enabled UI / 404 API).
 *
 * Auth: e2e_admin_session_setup.py (cookie-based UI sessions + CSRF).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();

// ─── Session bootstrap ──────────────────────────────────────────────────────

interface AdminSessionData {
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

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    const raw = execSync("python3 " + REPO_ROOT + "/e2e_admin_session_setup.py", {
      cwd: REPO_ROOT,
      timeout: 30_000,
    }).toString();
    _adminSessions = JSON.parse(raw);
  }
  return _adminSessions!;
}

async function injectAuth(page: Page, identity: string): Promise<void> {
  const session = getAdminSessions()[identity];
  if (!session) throw new Error(`No session for identity: ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate(
    ([userId, accessToken]: [string, string]) => {
      const state = { userId, accessToken, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    [session.user_sub, session.access_token],
  );
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getAdminSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

/** True when the CRM activities feature flag is on (POST call log succeeds). */
async function activitiesEnabled(page: Page): Promise<boolean> {
  const resp = await apiPost(page, "alice", "ui/calls/logs", {
    subject: `probe-${TS}`,
    direction: "outbound",
    outcome: "connected",
  });
  return resp.status() === 201;
}

// ─────────────────────────────────────────────────────────────────────────────
// Section ACT-1 — Call logs API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("ACT-1: Call logs API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test("create + list + get + update + delete call log (or 404 when disabled)", async () => {
    const create = await apiPost(alicePage, "alice", "ui/calls/logs", {
      subject: `Call ${TS}`,
      description: "discovery call",
      direction: "outbound",
      duration_seconds: 120,
      outcome: "connected",
      call_type: "phone",
    });

    if (create.status() === 404) {
      // Feature disabled — every endpoint should 404.
      const list = await apiGet(alicePage, "ui/calls/logs");
      expect(list.status()).toBe(404);
      return;
    }

    expect(create.status()).toBe(201);
    const created = await create.json();
    expect(created.subject).toBe(`Call ${TS}`);
    expect(created.outcome).toBe("connected");
    const id = created.call_id as string;

    const list = await apiGet(alicePage, "ui/calls/logs", { limit: "50" });
    expect(list.ok()).toBeTruthy();
    const listed = await list.json();
    expect(listed.items.some((c: { call_id: string }) => c.call_id === id)).toBeTruthy();

    const got = await apiGet(alicePage, `ui/calls/logs/${id}`);
    expect(got.ok()).toBeTruthy();

    const upd = await alicePage.request.patch(`${API}/ui/calls/logs/${id}`, {
      data: { outcome: "left_message" },
      headers: { "x-csrf-token": getAdminSessions()["alice"].csrf_token, "Content-Type": "application/json" },
    });
    expect(upd.ok()).toBeTruthy();
    expect((await upd.json()).outcome).toBe("left_message");

    const del = await apiDelete(alicePage, "alice", `ui/calls/logs/${id}`);
    expect(del.ok()).toBeTruthy();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section ACT-2 — Tasks API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("ACT-2: Tasks API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test("create + list + status filter + delete task (or 404 when disabled)", async () => {
    const create = await apiPost(alicePage, "alice", "ui/crm/tasks", {
      subject: `Task ${TS}`,
      priority: "high",
      status: "in_progress",
    });

    if (create.status() === 404) {
      const list = await apiGet(alicePage, "ui/crm/tasks");
      expect(list.status()).toBe(404);
      return;
    }

    expect(create.status()).toBe(201);
    const created = await create.json();
    expect(created.priority).toBe("high");
    const id = created.task_id as string;

    const filtered = await apiGet(alicePage, "ui/crm/tasks", { status: "in_progress", limit: "50" });
    expect(filtered.ok()).toBeTruthy();
    const items = (await filtered.json()).items;
    expect(items.some((t: { task_id: string }) => t.task_id === id)).toBeTruthy();

    const del = await apiDelete(alicePage, "alice", `ui/crm/tasks/${id}`);
    expect(del.ok()).toBeTruthy();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section ACT-3 — Notes + Timeline API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("ACT-3: Notes + Timeline API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test("create note linked to entity + read timeline (or 404 when disabled)", async () => {
    const entityType = "contact";
    const entityId = `c_${TS}`;

    const create = await apiPost(alicePage, "alice", "ui/crm/notes", {
      body: `Note ${TS}`,
      linked_entity_type: entityType,
      linked_entity_id: entityId,
    });

    if (create.status() === 404) {
      const tl = await apiGet(alicePage, `ui/crm/timeline/${entityType}/${entityId}`);
      expect(tl.status()).toBe(404);
      return;
    }

    expect(create.status()).toBe(201);
    const noteId = (await create.json()).note_id as string;

    const byEntity = await apiGet(alicePage, "ui/crm/notes/by-entity", {
      entity_type: entityType,
      entity_id: entityId,
    });
    expect(byEntity.ok()).toBeTruthy();

    const tl = await apiGet(alicePage, `ui/crm/timeline/${entityType}/${entityId}`);
    // Timeline is gated by an additional flag; accept 200 or 404 but never 500.
    expect([200, 404]).toContain(tl.status());

    await apiDelete(alicePage, "alice", `ui/crm/notes/${noteId}`);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section ACT-4 — My Activities UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("ACT-4: My Activities UI", () => {
  test("renders header + tabs, or graceful not-enabled state", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto(`${BASE}/crm/activities`, { waitUntil: "domcontentloaded" });

    await expect(page.getByRole("heading", { name: "My Activities" })).toBeVisible();

    const enabled = await activitiesEnabled(page);
    if (enabled) {
      await expect(page.getByRole("tab", { name: /Calls/ })).toBeVisible();
      await expect(page.getByRole("tab", { name: /Tasks/ })).toBeVisible();
      await expect(page.getByRole("tab", { name: /Notes/ })).toBeVisible();
    } else {
      await expect(page.getByText(/is not enabled/i)).toBeVisible();
    }
  });

  test("log-activity dialog opens with call/task/note tabs (enabled only)", async ({ page }) => {
    await injectAuth(page, "alice");
    const enabled = await activitiesEnabled(page);
    test.skip(!enabled, "CRM Activities disabled");

    await page.goto(`${BASE}/crm/activities`, { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: /Log activity/ }).first().click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(page.getByRole("tab", { name: "Call" })).toBeVisible();
    await expect(page.getByRole("tab", { name: "Task" })).toBeVisible();
    await expect(page.getByRole("tab", { name: "Note" })).toBeVisible();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section ACT-5 — Activity Timeline UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("ACT-5: Activity Timeline UI", () => {
  test("record selector renders + prompts to select", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto(`${BASE}/crm/timeline`, { waitUntil: "domcontentloaded" });

    await expect(page.getByRole("heading", { name: "Activity Timeline" })).toBeVisible();
    await expect(page.getByText("Select a record")).toBeVisible();
  });

  test("deep link to an entity timeline loads its view", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto(`${BASE}/crm/timeline/contact/c_${TS}`, { waitUntil: "domcontentloaded" });

    await expect(page.getByRole("heading", { name: "Activity Timeline" })).toBeVisible();
    // Either the empty/timeline state or the not-enabled card — never an error page.
    const empty = page.getByText("No activity yet");
    const notEnabled = page.getByText(/is not enabled/i);
    await expect(empty.or(notEnabled)).toBeVisible({ timeout: 10_000 });
  });
});

// keep ALICE_ID referenced (used implicitly via sessions)
void ALICE_ID;
