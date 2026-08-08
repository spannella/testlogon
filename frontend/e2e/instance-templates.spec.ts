/**
 * E2E tests for Instance Templates & Presets (INFRA-007).
 *
 * Sections:
 *   701 — Template CRUD API (6 tests)
 *   702 — Template Clone & Launch API (5 tests)
 *   703 — System Template Protection & Multi-User Isolation (5 tests)
 *   704 — Validation & Edge Cases (4 tests)
 *   705 — Templates UI (3 tests)
 *
 * Auth: Alice & Bob session cookies (from e2e_admin_session_setup.py).
 * Prefix under test: /ui/remote/templates
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions, unauthContext } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const API = BASE;
const ALICE_ID = "alice";
const BOB_ID = "bob";
const TS = Date.now();

// ─── Session bootstrap ───────────────────────────────────────────────────────

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

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

function csrfHeaders(identity: string) {
  return { "x-csrf-token": getSessions()[identity].csrf_token };
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  return page.request.post(`${API}${path}`, {
    headers: csrfHeaders(identity),
    data: body ?? {},
  });
}

async function apiPatch(page: Page, identity: string, path: string, body?: unknown) {
  return page.request.patch(`${API}${path}`, {
    headers: csrfHeaders(identity),
    data: body ?? {},
  });
}

async function apiDelete(page: Page, identity: string, path: string) {
  return page.request.delete(`${API}${path}`, { headers: csrfHeaders(identity) });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  let url = `${API}${path}`;
  if (params) url += "?" + new URLSearchParams(params).toString();
  return page.request.get(url);
}

const TPL = "/ui/remote/templates";

// ─── Test state ──────────────────────────────────────────────────────────────

let alicePage: Page;
let bobPage: Page;
const createdIds: string[] = [];

// ─────────────────────────────────────────────────────────────────────────────
// Section 701: Template CRUD API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("701 — Template CRUD API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    for (const id of createdIds) {
      try {
        await apiDelete(alicePage, ALICE_ID, `${TPL}/${id}`);
      } catch {
        /* ignore */
      }
    }
    await alicePage.close();
  });

  test("701.1 System templates are seeded", async () => {
    const resp = await apiGet(alicePage, TPL);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const system = data.templates.filter((t: any) => t.is_system);
    expect(system.length).toBeGreaterThanOrEqual(4);
    for (const t of system) {
      expect(t.is_system).toBe(true);
    }
  });

  test("701.2 Alice creates a custom EC2 template", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, TPL, {
      name: `E2E Custom ${TS}`,
      description: "custom ec2 template",
      category: "compute",
      target: "ec2",
      instance_type: "t3.small",
      ami_id: "ami-ubuntu-2204",
      startup_script: "#!/bin/bash\necho hi",
      ports: [22, 8080],
      env_vars: { FOO: "bar" },
      auto_terminate_after: 14400,
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.is_system).toBe(false);
    expect(body.owner_sub).toBe(getSessions()[ALICE_ID].user_sub);
    expect(body.instance_type).toBe("t3.small");
    expect(body.template_id).toBeTruthy();
    createdIds.push(body.template_id);
  });

  test("701.3 Alice updates her template", async () => {
    const id = createdIds[0];
    const resp = await apiPatch(alicePage, ALICE_ID, `${TPL}/${id}`, {
      description: "updated desc",
      instance_type: "t3.medium",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.description).toBe("updated desc");
    expect(body.instance_type).toBe("t3.medium");
  });

  test("701.4 Alice cannot modify system template", async () => {
    const resp = await apiPatch(alicePage, ALICE_ID, `${TPL}/sys-dev-workspace`, {
      description: "hacked",
    });
    expect(resp.status()).toBe(403);
    const body = await resp.json();
    expect(JSON.stringify(body)).toMatch(/system template/i);
  });

  test("701.5 Alice deletes her template", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, TPL, {
      name: `E2E Delete ${TS}`,
      target: "ec2",
      instance_type: "t3.micro",
      ami_id: "ami-ubuntu-2204",
    });
    const created = await resp.json();
    const id = created.template_id;
    const del = await apiDelete(alicePage, ALICE_ID, `${TPL}/${id}`);
    expect(del.status()).toBe(200);
    const get = await apiGet(alicePage, `${TPL}/${id}`);
    expect(get.status()).toBe(404);
  });

  test("701.6 Unauthenticated request returns 401", async () => {
    const anon = await unauthContext(API);
    const resp = await anon.get(`${TPL}`);
    expect(resp.status()).toBe(401);
    await anon.dispose();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 702: Template Clone & Launch API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("702 — Template Clone & Launch API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("702.1 Clone system template", async () => {
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `${TPL}/sys-dev-workspace/clone`,
      { new_name: `Cloned Dev ${TS}` },
    );
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.is_system).toBe(false);
    expect(body.instance_type).toBe("t3.small");
    expect(body.owner_sub).toBe(getSessions()[ALICE_ID].user_sub);
    createdIds.push(body.template_id);
  });

  test("702.2 Launch EC2 from template produces correct payload", async () => {
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `${TPL}/sys-web-server/launch`,
      {},
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.target).toBe("ec2");
    expect(body.resource_id).toBeTruthy();
    expect(body.instance).toBeTruthy();
    expect(body.instance.instance_type).toBe("t3.small");
    expect(body.instance.ami_id).toBe("ami-ubuntu-2204");
  });

  test("702.3 Launch K8s from template", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `${TPL}/sys-k8s-dev/launch`, {});
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.target).toBe("k8s");
    expect(body.pod).toBeTruthy();
    expect(body.pod.image).toBe("dev-workspace");
    expect(body.pod.preset).toBe("medium");
  });

  test("702.4 Template use_count increments on launch", async () => {
    const before = await (await apiGet(alicePage, `${TPL}/sys-ml-workspace`)).json();
    const launch = await apiPost(
      alicePage,
      ALICE_ID,
      `${TPL}/sys-ml-workspace/launch`,
      {},
    );
    expect(launch.status()).toBe(200);
    const after = await (await apiGet(alicePage, `${TPL}/sys-ml-workspace`)).json();
    expect(after.use_count).toBe(before.use_count + 1);
  });

  test("702.5 Explicit params override template defaults", async () => {
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `${TPL}/sys-web-server/launch`,
      { instance_type: "t3.large" },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.instance.instance_type).toBe("t3.large");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 703: System Template Protection & Multi-User Isolation
// ─────────────────────────────────────────────────────────────────────────────

test.describe("703 — System Protection & Isolation", () => {
  let aliceTemplateId = "";

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_ID);

    const resp = await apiPost(alicePage, ALICE_ID, TPL, {
      name: `Alice Private ${TS}`,
      target: "ec2",
      instance_type: "t3.small",
      ami_id: "ami-ubuntu-2204",
    });
    aliceTemplateId = (await resp.json()).template_id;
    createdIds.push(aliceTemplateId);
  });

  test.afterAll(async () => {
    try {
      await apiDelete(alicePage, ALICE_ID, `${TPL}/${aliceTemplateId}`);
    } catch {
      /* ignore */
    }
    await alicePage.close();
    await bobPage.close();
  });

  test("703.1 System templates seeded count >= 6", async () => {
    const data = await (await apiGet(alicePage, TPL)).json();
    const system = data.templates.filter((t: any) => t.is_system);
    expect(system.length).toBeGreaterThanOrEqual(6);
  });

  test("703.2 Bob cannot see Alice's template", async () => {
    const data = await (await apiGet(bobPage, TPL)).json();
    const found = data.templates.find((t: any) => t.template_id === aliceTemplateId);
    expect(found).toBeUndefined();
  });

  test("703.3 Bob cannot edit Alice's template (403/404)", async () => {
    const resp = await apiPatch(bobPage, BOB_ID, `${TPL}/${aliceTemplateId}`, {
      description: "bob was here",
    });
    expect([403, 404]).toContain(resp.status());
  });

  test("703.4 System template cannot be deleted (403)", async () => {
    const resp = await apiDelete(alicePage, ALICE_ID, `${TPL}/sys-database-server`);
    expect(resp.status()).toBe(403);
  });

  test("703.5 User template returned with owner_sub set", async () => {
    const body = await (await apiGet(alicePage, `${TPL}/${aliceTemplateId}`)).json();
    expect(body.owner_sub).toBe(getSessions()[ALICE_ID].user_sub);
    expect(body.is_system).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 704: Validation & Edge Cases
// ─────────────────────────────────────────────────────────────────────────────

test.describe("704 — Validation & Edge Cases", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("704.1 Name exceeding 100 chars rejected (422)", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, TPL, {
      name: "x".repeat(101),
      target: "ec2",
    });
    expect(resp.status()).toBe(422);
  });

  test("704.2 auto_terminate_after below 600 rejected (422)", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, TPL, {
      name: `Edge ${TS}`,
      target: "ec2",
      auto_terminate_after: 500,
    });
    expect(resp.status()).toBe(422);
  });

  test("704.3 Empty env_vars accepted (201)", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, TPL, {
      name: `Edge Env ${TS}`,
      target: "ec2",
      instance_type: "t3.small",
      ami_id: "ami-ubuntu-2204",
      env_vars: {},
    });
    expect(resp.status()).toBe(201);
    createdIds.push((await resp.json()).template_id);
  });

  test("704.4 Clone preserves all config fields", async () => {
    const src = await (await apiGet(alicePage, `${TPL}/sys-dev-workspace`)).json();
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `${TPL}/sys-dev-workspace/clone`,
      { new_name: `Preserve ${TS}` },
    );
    const clone = await resp.json();
    createdIds.push(clone.template_id);
    expect(clone.instance_type).toBe(src.instance_type);
    expect(clone.ami_id).toBe(src.ami_id);
    expect(clone.startup_script).toBe(src.startup_script);
    expect(clone.ports).toEqual(src.ports);
    expect(clone.env_vars).toEqual(src.env_vars);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 705: Templates UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("705 — Templates UI", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("705.1 TemplateBrowserPage shows system templates", async () => {
    await alicePage.goto(`${BASE}/remote/templates`, { waitUntil: "domcontentloaded" });
    await expect(
      alicePage.getByRole("heading", { name: "Templates" }),
    ).toBeVisible({ timeout: 10_000 });
    await expect(alicePage.getByText("Dev Workspace").first()).toBeVisible();
    await expect(alicePage.getByText("Database Server").first()).toBeVisible();
  });

  test("705.2 Category tabs filter templates", async () => {
    await alicePage.goto(`${BASE}/remote/templates`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByText("Dev Workspace").first()).toBeVisible({ timeout: 10_000 });
    await alicePage.getByRole("tab", { name: "Database" }).click();
    await expect(alicePage.getByText("Database Server").first()).toBeVisible();
    await expect(alicePage.getByText("Dev Workspace")).toHaveCount(0);
  });

  test("705.3 Create template dialog works", async () => {
    await alicePage.goto(`${BASE}/remote/templates`, { waitUntil: "domcontentloaded" });
    await alicePage.getByRole("button", { name: /create template/i }).click();
    await expect(alicePage.getByRole("dialog")).toBeVisible();
    const uiName = `UI Created ${TS}`;
    await alicePage.getByLabel("Name").fill(uiName);
    await alicePage
      .getByRole("button", { name: /create template/i })
      .last()
      .click();
    await expect(alicePage.getByText(uiName).first()).toBeVisible({ timeout: 10_000 });
  });
});
