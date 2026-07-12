/**
 * E2E tests for Multi-Hop SSH Bastion (INFRA-011).
 *
 * Sections:
 *   277 — Bastion Path CRUD API (5 tests)
 *   278 — Chain Validation API (5 tests)
 *   279 — Resolve / ProxyJump API (3 tests)
 *   280 — Multi-User Isolation (3 tests)
 *   281 — Bastion Path UI (2 tests)
 *
 * Auth: Alice & Bob session cookies (from e2e_admin_session_setup.py).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const API = BASE;
const ALICE_ID = "alice";
const BOB_ID = "bob";
const TS = Date.now();
const BP_BASE = "/ui/compute/bastion";

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
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

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
  return page.request.post(`${API}${path}`, { headers: csrfHeaders(identity), data: body });
}
async function apiPatch(page: Page, identity: string, path: string, body?: unknown) {
  return page.request.patch(`${API}${path}`, { headers: csrfHeaders(identity), data: body });
}
async function apiDelete(page: Page, identity: string, path: string) {
  return page.request.delete(`${API}${path}`, { headers: csrfHeaders(identity) });
}
async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  let url = `${API}${path}`;
  if (params) url += "?" + new URLSearchParams(params).toString();
  return page.request.get(url);
}

function pathBody(label: string) {
  return {
    label,
    description: "test path",
    jump_hops: [{ hostname: "bastion1.example.com", port: 22, username: "ubuntu", ssh_key_id: "key-bastion" }],
    target: { hostname: "target.example.com", port: 22, username: "ubuntu", ssh_key_id: "key-target" },
  };
}

let alicePage: Page;
let bobPage: Page;

// ─────────────────────────────────────────────────────────────────────────────
// Section 277: Bastion Path CRUD API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("277 — Bastion Path CRUD API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });
  test.afterAll(async () => {
    await alicePage.close();
  });

  test("277.1 Create a 2-hop bastion path", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `${BP_BASE}/paths`, pathBody(`crud-${TS}-1`));
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.path_id).toBeTruthy();
    expect(data.total_hops).toBe(2);
    expect(data.hops[0].is_bastion).toBe(true);
    expect(data.hops[1].is_bastion).toBe(false);
    expect(data.hops[1].hop_number).toBe(2);
  });

  test("277.2 Get a created path", async () => {
    const created = await (await apiPost(alicePage, ALICE_ID, `${BP_BASE}/paths`, pathBody(`crud-${TS}-2`))).json();
    const resp = await apiGet(alicePage, `${BP_BASE}/paths/${created.path_id}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.label).toBe(`crud-${TS}-2`);
  });

  test("277.3 List paths includes created path", async () => {
    const created = await (await apiPost(alicePage, ALICE_ID, `${BP_BASE}/paths`, pathBody(`crud-${TS}-3`))).json();
    const resp = await apiGet(alicePage, `${BP_BASE}/paths`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.paths.some((p: any) => p.path_id === created.path_id)).toBe(true);
    expect(data.total).toBe(data.paths.length);
  });

  test("277.4 Update path label and hops", async () => {
    const created = await (await apiPost(alicePage, ALICE_ID, `${BP_BASE}/paths`, pathBody(`crud-${TS}-4`))).json();
    const resp = await apiPatch(alicePage, ALICE_ID, `${BP_BASE}/paths/${created.path_id}`, {
      label: `crud-${TS}-4-renamed`,
      jump_hops: [
        { hostname: "bastion1.example.com", port: 22, username: "ubuntu" },
        { hostname: "bastion2.example.com", port: 2222, username: "admin" },
      ],
      target: { hostname: "target9.example.com", port: 22, username: "deploy" },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.label).toBe(`crud-${TS}-4-renamed`);
    expect(data.total_hops).toBe(3);
  });

  test("277.5 Delete path returns 204 and then 404", async () => {
    const created = await (await apiPost(alicePage, ALICE_ID, `${BP_BASE}/paths`, pathBody(`crud-${TS}-5`))).json();
    const del = await apiDelete(alicePage, ALICE_ID, `${BP_BASE}/paths/${created.path_id}`);
    expect(del.status()).toBe(204);
    const get = await apiGet(alicePage, `${BP_BASE}/paths/${created.path_id}`);
    expect(get.status()).toBe(404);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 278: Chain Validation API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("278 — Chain Validation API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });
  test.afterAll(async () => {
    await alicePage.close();
  });

  test("278.1 Invalid hostname returns 422", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `${BP_BASE}/paths`, {
      label: `val-${TS}-1`,
      jump_hops: [{ hostname: "not a host!!", port: 22, username: "ubuntu" }],
      target: { hostname: "target.example.com", port: 22, username: "ubuntu" },
    });
    expect(resp.status()).toBe(422);
  });

  test("278.2 Chain exceeding max hops returns 422", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `${BP_BASE}/paths`, {
      label: `val-${TS}-2`,
      jump_hops: [
        { hostname: "bastion1.example.com", port: 22, username: "u" },
        { hostname: "bastion2.example.com", port: 22, username: "u" },
        { hostname: "bastion3.example.com", port: 22, username: "u" },
      ],
      target: { hostname: "target4.example.com", port: 22, username: "u" },
    });
    expect(resp.status()).toBe(422);
  });

  test("278.3 Circular chain (duplicate hop) returns 422", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `${BP_BASE}/paths`, {
      label: `val-${TS}-3`,
      jump_hops: [{ hostname: "bastion1.example.com", port: 22, username: "u" }],
      target: { hostname: "bastion1.example.com", port: 22, username: "u" },
    });
    expect(resp.status()).toBe(422);
  });

  test("278.4 Missing username returns 422 (pydantic)", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `${BP_BASE}/paths`, {
      label: `val-${TS}-4`,
      jump_hops: [],
      target: { hostname: "target.example.com", port: 22 },
    });
    expect(resp.status()).toBe(422);
  });

  test("278.5 Zero jump hops is allowed (direct, 1 hop)", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `${BP_BASE}/paths`, {
      label: `val-${TS}-5`,
      jump_hops: [],
      target: { hostname: "target.example.com", port: 22, username: "ubuntu" },
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.total_hops).toBe(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 279: Resolve / ProxyJump API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("279 — Resolve / ProxyJump API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });
  test.afterAll(async () => {
    await alicePage.close();
  });

  test("279.1 Resolve 2-hop path returns ProxyJump + ssh_config", async () => {
    const created = await (await apiPost(alicePage, ALICE_ID, `${BP_BASE}/paths`, pathBody(`res-${TS}-1`))).json();
    const resp = await apiGet(alicePage, `${BP_BASE}/paths/${created.path_id}/resolve`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.proxy_jump).toBe("ubuntu@bastion1.example.com");
    expect(data.ssh_command).toContain("ssh -J ubuntu@bastion1.example.com ubuntu@target.example.com");
    expect(data.ssh_config).toContain("ProxyJump ubuntu@bastion1.example.com");
    expect(data.ssh_config).toContain("HostName target.example.com");
    expect(data.target.hostname).toBe("target.example.com");
    expect(data.jump_hops.length).toBe(1);
  });

  test("279.2 Resolve direct path has empty ProxyJump", async () => {
    const created = await (await apiPost(alicePage, ALICE_ID, `${BP_BASE}/paths`, {
      label: `res-${TS}-2`,
      jump_hops: [],
      target: { hostname: "target.example.com", port: 2200, username: "ubuntu" },
    })).json();
    const resp = await apiGet(alicePage, `${BP_BASE}/paths/${created.path_id}/resolve`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.proxy_jump).toBe("");
    expect(data.ssh_command).toBe("ssh ubuntu@target.example.com:2200");
  });

  test("279.3 Resolve non-existent path returns 404", async () => {
    const resp = await apiGet(alicePage, `${BP_BASE}/paths/bp_doesnotexist/resolve`);
    expect(resp.status()).toBe(404);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 280: Multi-User Isolation
// ─────────────────────────────────────────────────────────────────────────────

test.describe("280 — Multi-User Isolation", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_ID);
  });
  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("280.1 Bob cannot read Alice's path (404)", async () => {
    const created = await (await apiPost(alicePage, ALICE_ID, `${BP_BASE}/paths`, pathBody(`iso-${TS}-1`))).json();
    const resp = await apiGet(bobPage, `${BP_BASE}/paths/${created.path_id}`);
    expect(resp.status()).toBe(404);
  });

  test("280.2 Bob cannot delete Alice's path (404)", async () => {
    const created = await (await apiPost(alicePage, ALICE_ID, `${BP_BASE}/paths`, pathBody(`iso-${TS}-2`))).json();
    const del = await apiDelete(bobPage, BOB_ID, `${BP_BASE}/paths/${created.path_id}`);
    expect(del.status()).toBe(404);
    // Alice's path still exists.
    const get = await apiGet(alicePage, `${BP_BASE}/paths/${created.path_id}`);
    expect(get.status()).toBe(200);
  });

  test("280.3 Bob's list does not include Alice's paths", async () => {
    const created = await (await apiPost(alicePage, ALICE_ID, `${BP_BASE}/paths`, pathBody(`iso-${TS}-3`))).json();
    const resp = await apiGet(bobPage, `${BP_BASE}/paths`);
    const data = await resp.json();
    expect(data.paths.some((p: any) => p.path_id === created.path_id)).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 281: Bastion Path UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("281 — Bastion Path UI", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });
  test.afterAll(async () => {
    await alicePage.close();
  });

  test("281.1 Bastion page renders heading and New Path button", async () => {
    await apiPost(alicePage, ALICE_ID, `${BP_BASE}/paths`, pathBody(`ui-${TS}-1`));
    await alicePage.goto(`${BASE}/remote/bastion`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByRole("heading", { name: /SSH Bastion Paths/i })).toBeVisible();
    await expect(alicePage.getByTestId("bastion-new")).toBeVisible();
  });

  test("281.2 Resolve dialog shows ProxyJump config", async () => {
    await apiPost(alicePage, ALICE_ID, `${BP_BASE}/paths`, pathBody(`ui-${TS}-2`));
    await alicePage.goto(`${BASE}/remote/bastion`, { waitUntil: "domcontentloaded" });
    await alicePage.getByTestId("bastion-resolve").first().click();
    await expect(alicePage.getByTestId("resolved-proxyjump")).toBeVisible();
    await expect(alicePage.getByTestId("resolved-config")).toContainText("ProxyJump");
  });
});
