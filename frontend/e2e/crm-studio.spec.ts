/**
 * E2E tests for the SuiteCRM SECURITY/STUDIO (STU) cluster.
 *
 * Sections:
 *   90 — ACL roles CRUD + permission matrix — API
 *   91 — ACL role assignments (user + group) — API
 *   92 — Security groups CRUD + members + records — API
 *   93 — Studio custom fields CRUD — API
 *   94 — CRM Security / Studio UI
 *
 * Flags: crm_acl_enabled + crm_studio_enabled default OFF → routers not
 * registered → all paths 404. These tests are written to be tolerant: when the
 * cluster is disabled they assert the 404/empty-state behaviour rather than
 * failing. DO NOT RUN as part of authoring.
 *
 * Auth: e2e_admin_session_setup.py. ROOT performs create/mutations (ACL role
 * + studio field creation require root; admin can read).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ROOT_SUB = "root.admin@testdev.local";
const BOB_ID   = "e2e_bob@test.local";
const TS       = Date.now();

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
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
    _adminSessions = JSON.parse(raw);
  }
  return _adminSessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
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

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiPatch(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.patch(`${API}/${path}`, {
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

/** True when the cluster flag is off → router not registered. */
function clusterDisabled(status: number): boolean {
  return status === 404;
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 90 — ACL roles CRUD + permission matrix (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 90: ACL roles CRUD (API)", () => {
  let rootPage: Page;
  let roleId = "";
  const NAME = `E2E ACL Role ${TS}`;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
  });

  test("90.1 Create role with permission matrix", async () => {
    const resp = await apiPost(rootPage, "root", "ui/admin/crm/acl-roles/", {
      name: NAME,
      description: "e2e",
      permissions: { contacts: { read: true, create: true } },
    });
    if (clusterDisabled(resp.status())) {
      expect(resp.status()).toBe(404);
      return;
    }
    expect(resp.status()).toBe(201);
    const data = (await resp.json()) as { role_id: string; name: string };
    expect(data.name).toBe(NAME);
    roleId = data.role_id;
  });

  test("90.2 List roles includes created role", async () => {
    const resp = await apiGet(rootPage, "ui/admin/crm/acl-roles/", { limit: "200" });
    if (clusterDisabled(resp.status())) return;
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { roles: Array<{ role_id: string }> };
    expect(Array.isArray(data.roles)).toBe(true);
    if (roleId) expect(data.roles.some((r) => r.role_id === roleId)).toBe(true);
  });

  test("90.3 Patch role permissions", async () => {
    test.skip(!roleId, "cluster disabled");
    const resp = await apiPatch(rootPage, "root", `ui/admin/crm/acl-roles/${roleId}`, {
      permissions: { contacts: { read: true, update: true, delete: true } },
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { permissions: Record<string, Record<string, boolean>> };
    expect(data.permissions.contacts.update).toBe(true);
  });

  test("90.4 Get my-permissions returns union", async () => {
    const resp = await apiGet(rootPage, "ui/admin/crm/acl-roles/my-permissions");
    if (clusterDisabled(resp.status())) return;
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { user_sub: string; permissions: object };
    expect(data.user_sub).toBe(ROOT_SUB);
  });

  test("90.5 Delete role", async () => {
    test.skip(!roleId, "cluster disabled");
    const resp = await apiDelete(rootPage, "root", `ui/admin/crm/acl-roles/${roleId}`);
    expect(resp.status()).toBe(204);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 91 — ACL role assignments (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 91: ACL role assignments (API)", () => {
  let rootPage: Page;
  let roleId = "";

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    const resp = await apiPost(rootPage, "root", "ui/admin/crm/acl-roles/", {
      name: `E2E Assign Role ${TS}`,
      description: "assign",
      permissions: {},
    });
    if (resp.status() === 201) {
      roleId = ((await resp.json()) as { role_id: string }).role_id;
    }
  });

  test("91.1 Assign user to role", async () => {
    test.skip(!roleId, "cluster disabled");
    const resp = await apiPost(rootPage, "root", `ui/admin/crm/acl-roles/${roleId}/assignments`, {
      user_sub: BOB_ID,
    });
    expect(resp.status()).toBe(201);
  });

  test("91.2 List assignments shows the user", async () => {
    test.skip(!roleId, "cluster disabled");
    const resp = await apiGet(rootPage, `ui/admin/crm/acl-roles/${roleId}/assignments`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { user_assignments: unknown[]; group_assignments: unknown[] };
    expect(Array.isArray(data.user_assignments)).toBe(true);
  });

  test("91.3 Assign + revoke group", async () => {
    test.skip(!roleId, "cluster disabled");
    const assign = await apiPost(
      rootPage,
      "root",
      `ui/admin/crm/acl-roles/${roleId}/group-assignments`,
      { group_key: "e2e_group" },
    );
    expect(assign.status()).toBe(200);
    const revoke = await apiDelete(
      rootPage,
      "root",
      `ui/admin/crm/acl-roles/${roleId}/group-assignments/e2e_group`,
    );
    expect(revoke.status()).toBe(204);
  });

  test("91.4 Revoke user", async () => {
    test.skip(!roleId, "cluster disabled");
    const resp = await apiDelete(
      rootPage,
      "root",
      `ui/admin/crm/acl-roles/${roleId}/assignments/${encodeURIComponent(BOB_ID)}`,
    );
    expect(resp.status()).toBe(204);
  });

  test.afterAll(async () => {
    if (roleId) await apiDelete(rootPage, "root", `ui/admin/crm/acl-roles/${roleId}`);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 92 — Security groups CRUD + members + records (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 92: Security groups (API)", () => {
  let rootPage: Page;
  let groupId = "";

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test("92.1 Create security group", async () => {
    const resp = await apiPost(rootPage, "root", "ui/admin/crm/security-groups/", {
      name: `E2E SG ${TS}`,
      description: "sg",
      is_global: false,
    });
    if (clusterDisabled(resp.status())) {
      expect(resp.status()).toBe(404);
      return;
    }
    expect(resp.status()).toBe(201);
    groupId = ((await resp.json()) as { group_id: string }).group_id;
  });

  test("92.2 Add member", async () => {
    test.skip(!groupId, "cluster disabled");
    const resp = await apiPost(rootPage, "root", `ui/admin/crm/security-groups/${groupId}/members`, {
      user_sub: BOB_ID,
      can_edit: true,
    });
    expect(resp.status()).toBe(204);
  });

  test("92.3 Assign record", async () => {
    test.skip(!groupId, "cluster disabled");
    const resp = await apiPost(rootPage, "root", `ui/admin/crm/security-groups/${groupId}/records`, {
      entity_type: "contact",
      record_id: `rec_${TS}`,
    });
    expect(resp.status()).toBe(204);
  });

  test("92.4 Get detail shows member + record", async () => {
    test.skip(!groupId, "cluster disabled");
    const resp = await apiGet(rootPage, `ui/admin/crm/security-groups/${groupId}`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as {
      members: Array<{ user_sub: string }>;
      records: Array<{ record_id: string }>;
    };
    expect(data.members.some((m) => m.user_sub === BOB_ID)).toBe(true);
    expect(data.records.some((r) => r.record_id === `rec_${TS}`)).toBe(true);
  });

  test("92.5 Remove member + unassign record + delete group", async () => {
    test.skip(!groupId, "cluster disabled");
    const rm = await apiDelete(
      rootPage,
      "root",
      `ui/admin/crm/security-groups/${groupId}/members/${encodeURIComponent(BOB_ID)}`,
    );
    expect(rm.status()).toBe(204);
    const un = await apiDelete(
      rootPage,
      "root",
      `ui/admin/crm/security-groups/${groupId}/records/contact/rec_${TS}`,
    );
    expect(un.status()).toBe(204);
    const del = await apiDelete(rootPage, "root", `ui/admin/crm/security-groups/${groupId}`);
    expect(del.status()).toBe(204);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 93 — Studio custom fields CRUD (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 93: Studio custom fields (API)", () => {
  let rootPage: Page;
  const FIELD_KEY = `e2e_field_${TS}`.toLowerCase().replace(/[^a-z0-9_]/g, "_").slice(0, 49);

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test("93.1 Create custom field on contact", async () => {
    const resp = await apiPost(rootPage, "root", "ui/admin/studio/fields/contact", {
      field_key: FIELD_KEY,
      label: "E2E Field",
      field_type: "text",
      required: false,
      max_length: 200,
      sort_order: 5,
    });
    if (clusterDisabled(resp.status())) {
      expect(resp.status()).toBe(404);
      return;
    }
    expect(resp.status()).toBe(201);
    const data = (await resp.json()) as { field_key: string; entity_type: string };
    expect(data.field_key).toBe(FIELD_KEY);
    expect(data.entity_type).toBe("contact");
  });

  test("93.2 List fields includes created field", async () => {
    const resp = await apiGet(rootPage, "ui/admin/studio/fields/contact", { limit: "500" });
    if (clusterDisabled(resp.status())) return;
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { fields: Array<{ field_key: string }> };
    expect(data.fields.some((f) => f.field_key === FIELD_KEY)).toBe(true);
  });

  test("93.3 Patch field label + sort", async () => {
    const resp = await apiPatch(rootPage, "root", `ui/admin/studio/fields/contact/${FIELD_KEY}`, {
      label: "E2E Field Updated",
      sort_order: 9,
    });
    if (clusterDisabled(resp.status())) return;
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { label: string; sort_order: number };
    expect(data.label).toBe("E2E Field Updated");
    expect(data.sort_order).toBe(9);
  });

  test("93.4 Invalid entity type → 400", async () => {
    const resp = await apiGet(rootPage, "ui/admin/studio/fields/not_a_real_entity");
    if (clusterDisabled(resp.status())) return;
    expect(resp.status()).toBe(400);
  });

  test("93.5 Deactivate field", async () => {
    const resp = await apiDelete(rootPage, "root", `ui/admin/studio/fields/contact/${FIELD_KEY}`);
    if (clusterDisabled(resp.status())) return;
    expect(resp.status()).toBe(204);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 94 — CRM Security / Studio UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 94: CRM Security / Studio UI", () => {
  test.beforeEach(async ({ page }) => {
    await injectAuth(page, "root");
  });

  test("94.1 Security page renders tabs", async ({ page }) => {
    await page.goto(`${BASE}/crm/security`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "CRM Security", exact: true })).toBeVisible();
    // Either the tabs render (flag on) or the not-enabled card shows (flag off).
    const tab = page.getByRole("tab", { name: /ACL Roles/i });
    const disabled = page.getByText(/is not enabled/i);
    await expect(tab.or(disabled).first()).toBeVisible();
  });

  test("94.2 Studio page renders entity selector", async ({ page }) => {
    await page.goto(`${BASE}/crm/studio`, { waitUntil: "domcontentloaded" });
    await expect(page.getByText("Studio — Custom Fields", { exact: true })).toBeVisible();
    const newBtn = page.getByRole("button", { name: /New field/i });
    await expect(newBtn.first()).toBeVisible();
  });
});
