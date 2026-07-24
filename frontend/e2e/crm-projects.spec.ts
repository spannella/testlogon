/**
 * E2E tests for the SuiteCRM PROJECTS (PRJ) cluster.
 *
 * Backend router: app/routers/crm_projects.py (prefix /v1/crm/projects)
 * Feature flag: S.crm_projects_enabled (CRM_PROJECTS_ENABLED) — default OFF.
 *   When OFF, every route returns 404 → the API tests below skip gracefully
 *   and the UI tests assert the "not enabled" state.
 *
 * Sections:
 *   PRJ-A — Project CRUD (create / list / get / patch / delete) — API
 *   PRJ-B — Task CRUD + reorder + milestones + workload — API
 *   PRJ-C — Members + contact links + status history — API
 *   PRJ-D — Templates — API
 *   PRJ-E — ProjectsPage + ProjectDetailPage UI
 *
 * Auth: e2e_admin_session_setup.py (cookie sessions + CSRF).
 *
 * NOTE: authored to mirror frontend/e2e/tickets.spec.ts. DO NOT RUN as part of
 * authoring — the orchestrator runs the suite after wiring routes.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();

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
    _adminSessions = loadSessions();
  }
  return _adminSessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const s = sessions[identity];
  if (!s) throw new Error(`No session for ${identity}`);
  const ctx = await browser.newContext();
  await ctx.addCookies(s.cookies);
  // Seed the auth-store so the React route guard treats the page as
  // authenticated (cookie-only contexts otherwise redirect to /login).
  await ctx.addInitScript(
    ([userId, accessToken]: [string, string]) => {
      localStorage.setItem(
        "auth-store",
        JSON.stringify({ state: { userId, accessToken, isAuthenticated: true }, version: 0 }),
      );
    },
    [s.user_sub, s.access_token] as [string, string],
  );
  return ctx.newPage();
}

function csrf(identity: string): string {
  return getAdminSessions()[identity]!.csrf_token;
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  const qs = params ? "?" + new URLSearchParams(params).toString() : "";
  return page.request.get(`${API}${path}${qs}`);
}
async function apiPost(page: Page, identity: string, path: string, body: unknown) {
  return page.request.post(`${API}${path}`, {
    headers: { "x-csrf-token": csrf(identity), "content-type": "application/json" },
    data: body,
  });
}
async function apiPatch(page: Page, identity: string, path: string, body: unknown) {
  return page.request.patch(`${API}${path}`, {
    headers: { "x-csrf-token": csrf(identity), "content-type": "application/json" },
    data: body,
  });
}
async function apiPut(page: Page, identity: string, path: string, body: unknown) {
  return page.request.put(`${API}${path}`, {
    headers: { "x-csrf-token": csrf(identity), "content-type": "application/json" },
    data: body,
  });
}
async function apiDelete(page: Page, identity: string, path: string) {
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": csrf(identity) },
  });
}

/** When the flag is OFF every route 404s. Detect once so tests can skip. */
async function featureEnabled(page: Page): Promise<boolean> {
  const r = await apiGet(page, "/v1/crm/projects", { limit: "1" });
  return r.status() !== 404;
}

// ─── PRJ-A: Project CRUD ────────────────────────────────────────────────────

test.describe("PRJ-A: Project CRUD API", () => {
  let alice: Page;
  let enabled = false;

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    enabled = await featureEnabled(alice);
  });

  test("create + get + list + patch + delete project", async () => {
    test.skip(!enabled, "crm_projects feature flag is OFF (404)");

    const createResp = await apiPost(alice, "alice", "/v1/crm/projects", {
      name: `PRJ E2E ${TS}`,
      description: "created by e2e",
      status: "draft",
      priority: 2,
    });
    expect(createResp.status()).toBe(201);
    const project = await createResp.json();
    expect(project.id).toBeTruthy();
    expect(project.name).toBe(`PRJ E2E ${TS}`);
    expect(project.status).toBe("draft");
    const pid = project.id;

    const getResp = await apiGet(alice, `/v1/crm/projects/${pid}`);
    expect(getResp.status()).toBe(200);
    expect((await getResp.json()).id).toBe(pid);

    const listResp = await apiGet(alice, "/v1/crm/projects", { limit: "50" });
    expect(listResp.status()).toBe(200);
    const list = await listResp.json();
    expect(Array.isArray(list.items)).toBe(true);
    expect(list.items.some((p: any) => p.id === pid)).toBe(true);

    const patchResp = await apiPatch(alice, "alice", `/v1/crm/projects/${pid}`, {
      status: "underway",
    });
    expect(patchResp.status()).toBe(200);
    expect((await patchResp.json()).status).toBe("underway");

    const delResp = await apiDelete(alice, "alice", `/v1/crm/projects/${pid}`);
    expect([200, 204]).toContain(delResp.status());
  });
});

// ─── PRJ-B: Tasks / milestones / workload ────────────────────────────────────

test.describe("PRJ-B: Task + milestone + workload API", () => {
  let alice: Page;
  let enabled = false;
  let pid = "";

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    enabled = await featureEnabled(alice);
    if (enabled) {
      const r = await apiPost(alice, "alice", "/v1/crm/projects", {
        name: `PRJ Tasks ${TS}`,
      });
      pid = (await r.json()).id;
    }
  });

  test("create tasks, reorder, milestone summary, workload", async () => {
    test.skip(!enabled, "crm_projects feature flag is OFF (404)");

    const t1 = await apiPost(alice, "alice", `/v1/crm/projects/${pid}/tasks`, {
      name: "Task one",
      duration_days: 3,
      assigned_user_sub: ALICE_ID,
    });
    expect(t1.status()).toBe(201);
    const task1 = await t1.json();

    const t2 = await apiPost(alice, "alice", `/v1/crm/projects/${pid}/tasks`, {
      name: "Milestone",
      is_milestone: true,
    });
    expect(t2.status()).toBe(201);
    const task2 = await t2.json();

    const listTasks = await apiGet(alice, `/v1/crm/projects/${pid}/tasks`, { limit: "50" });
    expect(listTasks.status()).toBe(200);
    expect((await listTasks.json()).items.length).toBeGreaterThanOrEqual(2);

    const reorder = await apiPut(alice, "alice", `/v1/crm/projects/${pid}/tasks/order`, {
      task_ids: [task2.id, task1.id],
    });
    expect(reorder.status()).toBe(200);
    expect((await reorder.json()).items.length).toBe(2);

    const milestones = await apiGet(alice, `/v1/crm/projects/${pid}/milestones`);
    expect(milestones.status()).toBe(200);
    const ms = await milestones.json();
    expect(ms.total_milestones).toBeGreaterThanOrEqual(1);

    const workload = await apiGet(alice, `/v1/crm/projects/${pid}/workload`);
    expect(workload.status()).toBe(200);
    expect(Array.isArray((await workload.json()).entries)).toBe(true);

    const patchTask = await apiPatch(
      alice,
      "alice",
      `/v1/crm/projects/${pid}/tasks/${task1.id}`,
      { percent_complete: 50 },
    );
    expect(patchTask.status()).toBe(200);
    expect((await patchTask.json()).percent_complete).toBe(50);

    const delTask = await apiDelete(alice, "alice", `/v1/crm/projects/${pid}/tasks/${task2.id}`);
    expect([200, 204]).toContain(delTask.status());
  });
});

// ─── PRJ-C: Members + contact links + status history ─────────────────────────

test.describe("PRJ-C: Members + links + history API", () => {
  let alice: Page;
  let enabled = false;
  let pid = "";

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    enabled = await featureEnabled(alice);
    if (enabled) {
      const r = await apiPost(alice, "alice", "/v1/crm/projects", {
        name: `PRJ Team ${TS}`,
      });
      pid = (await r.json()).id;
    }
  });

  test("members, contact links, status history", async () => {
    test.skip(!enabled, "crm_projects feature flag is OFF (404)");

    const addMember = await apiPost(alice, "alice", `/v1/crm/projects/${pid}/members`, {
      user_sub: "e2e_bob@test.local",
      role: "member",
    });
    expect(addMember.status()).toBe(201);

    const listMembers = await apiGet(alice, `/v1/crm/projects/${pid}/members`);
    expect(listMembers.status()).toBe(200);
    expect((await listMembers.json()).items.length).toBeGreaterThanOrEqual(1);

    const addLink = await apiPost(alice, "alice", `/v1/crm/projects/${pid}/contact-links`, {
      linked_entity_id: `contact_${TS}`,
      linked_entity_type: "contact_party",
      note: "primary stakeholder",
    });
    expect(addLink.status()).toBe(201);

    const listLinks = await apiGet(alice, `/v1/crm/projects/${pid}/contact-links`);
    expect(listLinks.status()).toBe(200);
    expect((await listLinks.json()).items.length).toBeGreaterThanOrEqual(1);

    // trigger a status change so history has an entry
    await apiPatch(alice, "alice", `/v1/crm/projects/${pid}`, { status: "underway" });
    const history = await apiGet(alice, `/v1/crm/projects/${pid}/status-history`);
    expect(history.status()).toBe(200);
    expect(Array.isArray((await history.json()).items)).toBe(true);
  });
});

// ─── PRJ-D: Templates ────────────────────────────────────────────────────────

test.describe("PRJ-D: Templates API", () => {
  let alice: Page;
  let enabled = false;

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    enabled = await featureEnabled(alice);
  });

  test("create, list, instantiate, delete template", async () => {
    test.skip(!enabled, "crm_projects feature flag is OFF (404)");

    const create = await apiPost(alice, "alice", "/v1/crm/projects/templates", {
      name: `Tmpl ${TS}`,
      task_defs: [
        { template_task_id: "tt1", name: "Kickoff", task_order: 0, duration_days: 1 },
        { template_task_id: "tt2", name: "Build", task_order: 1, duration_days: 5 },
      ],
    });
    expect(create.status()).toBe(201);
    const tmpl = await create.json();

    const list = await apiGet(alice, "/v1/crm/projects/templates");
    expect(list.status()).toBe(200);
    expect((await list.json()).items.some((t: any) => t.id === tmpl.id)).toBe(true);

    const inst = await apiPost(
      alice,
      "alice",
      `/v1/crm/projects/templates/${tmpl.id}/instantiate`,
      { project_name: `From Tmpl ${TS}` },
    );
    expect(inst.status()).toBe(201);
    expect((await inst.json()).name).toBe(`From Tmpl ${TS}`);

    const del = await apiDelete(alice, "alice", `/v1/crm/projects/templates/${tmpl.id}`);
    expect([200, 204]).toContain(del.status());
  });
});

// ─── PRJ-E: UI ───────────────────────────────────────────────────────────────

test.describe("PRJ-E: Projects UI", () => {
  let alice: Page;
  let enabled = false;

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    enabled = await featureEnabled(alice);
  });

  test("project list page renders (list or not-enabled)", async () => {
    await alice.goto(`${BASE}/crm/projects`);
    await expect(alice.getByRole("heading", { name: "CRM Projects" })).toBeVisible();
    if (!enabled) {
      await expect(alice.getByText("CRM Projects is not enabled")).toBeVisible();
    } else {
      await expect(alice.getByRole("button", { name: /new project/i })).toBeVisible();
    }
  });

  test("create a project via UI and open detail", async () => {
    test.skip(!enabled, "crm_projects feature flag is OFF (404)");

    await alice.goto(`${BASE}/crm/projects`);
    await alice.getByRole("button", { name: /new project/i }).first().click();

    const name = `UI PRJ ${Date.now()}`;
    await alice.getByLabel("Name").fill(name);
    await alice.getByRole("button", { name: /create project/i }).click();

    await expect(alice.getByText(name)).toBeVisible({ timeout: 10_000 });
    await alice.getByText(name).first().click();

    await expect(alice.getByRole("tab", { name: /tasks/i })).toBeVisible();
    await expect(alice.getByRole("tab", { name: /milestones/i })).toBeVisible();
  });
});
