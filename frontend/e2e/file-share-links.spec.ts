/**
 * E2E tests for Encrypted One-Time Share Links (FILES-001).
 *
 * Sections 695-700.
 *
 * Auth strategy:
 *  - Owner (management) endpoints use page.request with session cookies + CSRF.
 *  - Public recipient endpoints (info + download) are tested WITHOUT any auth
 *    using the global Playwright `request` fixture (no cookies injected).
 *
 * Owner API prefix:  /ui/files/share-links
 * Public API prefix: /public/files/share
 */

import { test, expect, type Page, request as pwRequest } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

const TS = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None";
    expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

/** Upload a small text file via the file manager and return its path. */
async function uploadFile(page: Page, userId: string, name: string, content: string): Promise<string> {
  const session = getSessions()[userId];
  const resp = await page.request.post(`${API}/v1/fs/upload`, {
    params: { path: `/${name}` },
    multipart: {
      file: { name, mimeType: "text/plain", buffer: Buffer.from(content) },
    },
    headers: { "x-csrf-token": session.csrf_token },
  });
  expect(resp.ok()).toBe(true);
  return `/${name}`;
}

// Owner management helpers (session auth + CSRF).
async function ownerPost(page: Page, userId: string, body: object) {
  const session = getSessions()[userId];
  return page.request.post(`${API}/ui/files/share-links`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}
async function ownerList(page: Page) {
  return page.request.get(`${API}/ui/files/share-links`);
}
async function ownerRevoke(page: Page, userId: string, linkId: string) {
  const session = getSessions()[userId];
  return page.request.delete(`${API}/ui/files/share-links/${linkId}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── 695. Share Link Creation API ─────────────────────────────────────────────

test.describe("695. Share Link Creation API", () => {
  let page: Page;
  let filePath: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    filePath = await uploadFile(page, ALICE_ID, `fsl_create_${TS}.txt`, "share me");
  });
  test.afterAll(async () => page.close());

  test("695.1 create share link for owned file", async () => {
    const resp = await ownerPost(page, ALICE_ID, { file_node_id: filePath });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.link_id).toMatch(/^fsl_/);
    expect(typeof body.share_url).toBe("string");
    expect(typeof body.expires_at).toBe("number");
    expect(body.max_downloads).toBe(1);
    expect(body.has_password).toBe(false);
  });

  test("695.2 create share link with password", async () => {
    const resp = await ownerPost(page, ALICE_ID, {
      file_node_id: filePath,
      password: "s3cretP@ss",
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.has_password).toBe(true);
  });

  test("695.3 custom expiry and max_downloads", async () => {
    const resp = await ownerPost(page, ALICE_ID, {
      file_node_id: filePath,
      expiry_hours: 168,
      max_downloads: 5,
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.max_downloads).toBe(5);
  });

  test("695.4 reject share link for non-existent file", async () => {
    const resp = await ownerPost(page, ALICE_ID, {
      file_node_id: `/does_not_exist_${TS}.txt`,
    });
    expect(resp.status()).toBe(404);
  });

  test("695.5 reject create for another user's file (404 — not visible)", async () => {
    // Bob tries to share Alice's file → get_node(Bob, alice path) → 404.
    const bobPage = await page.context().browser()!.newPage();
    await injectAuth(bobPage, BOB_ID);
    const resp = await ownerPost(bobPage, BOB_ID, { file_node_id: filePath });
    expect([403, 404]).toContain(resp.status());
    await bobPage.close();
  });
});

// ─── 696. Share Link Download API (public, no auth) ───────────────────────────

test.describe("696. Share Link Download API", () => {
  let page: Page;
  let filePath: string;
  const CONTENT = `download-content-${TS}`;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    filePath = await uploadFile(page, ALICE_ID, `fsl_dl_${TS}.txt`, CONTENT);
  });
  test.afterAll(async () => page.close());

  test("696.1 download via share link (no password, no auth)", async () => {
    const created = await (await ownerPost(page, ALICE_ID, { file_node_id: filePath })).json();
    // public request — NO auth context.
    const anon = await pwRequest.newContext();
    const resp = await anon.post(`${API}/public/files/share/${created.link_id}/download`, {
      data: { password: null },
    });
    expect(resp.status()).toBe(200);
    expect(await resp.text()).toBe(CONTENT);
    await anon.dispose();
  });

  test("696.2 download with correct password", async () => {
    const created = await (await ownerPost(page, ALICE_ID, {
      file_node_id: filePath,
      password: "goodpass",
    })).json();
    const anon = await pwRequest.newContext();
    const resp = await anon.post(`${API}/public/files/share/${created.link_id}/download`, {
      data: { password: "goodpass" },
    });
    expect(resp.status()).toBe(200);
    expect(await resp.text()).toBe(CONTENT);
    await anon.dispose();
  });

  test("696.3 reject download with wrong password", async () => {
    const created = await (await ownerPost(page, ALICE_ID, {
      file_node_id: filePath,
      password: "goodpass",
    })).json();
    const anon = await pwRequest.newContext();
    const resp = await anon.post(`${API}/public/files/share/${created.link_id}/download`, {
      data: { password: "wrongpass" },
    });
    expect(resp.status()).toBe(403);
    await anon.dispose();
  });

  test("696.4 link becomes 410 Gone after max_downloads reached", async () => {
    const created = await (await ownerPost(page, ALICE_ID, {
      file_node_id: filePath,
      max_downloads: 1,
    })).json();
    const anon = await pwRequest.newContext();
    const first = await anon.post(`${API}/public/files/share/${created.link_id}/download`, { data: {} });
    expect(first.status()).toBe(200);
    const second = await anon.post(`${API}/public/files/share/${created.link_id}/download`, { data: {} });
    expect(second.status()).toBe(410);
    await anon.dispose();
  });

  test("696.5 revoked link returns 410", async () => {
    const created = await (await ownerPost(page, ALICE_ID, { file_node_id: filePath })).json();
    const rev = await ownerRevoke(page, ALICE_ID, created.link_id);
    expect(rev.ok()).toBe(true);
    const anon = await pwRequest.newContext();
    const resp = await anon.post(`${API}/public/files/share/${created.link_id}/download`, { data: {} });
    expect(resp.status()).toBe(410);
    await anon.dispose();
  });
});

// ─── 697. Share Link Management API ───────────────────────────────────────────

test.describe("697. Share Link Management API", () => {
  let page: Page;
  let filePath: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    filePath = await uploadFile(page, ALICE_ID, `fsl_mgmt_${TS}.txt`, "manage");
  });
  test.afterAll(async () => page.close());

  test("697.1 list share links includes created link", async () => {
    const created = await (await ownerPost(page, ALICE_ID, { file_node_id: filePath })).json();
    const resp = await ownerList(page);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    const ids = (body.items ?? []).map((l: { link_id: string }) => l.link_id);
    expect(ids).toContain(created.link_id);
  });

  test("697.2 revoke share link", async () => {
    const created = await (await ownerPost(page, ALICE_ID, { file_node_id: filePath })).json();
    const resp = await ownerRevoke(page, ALICE_ID, created.link_id);
    expect(resp.status()).toBe(200);
  });

  test("697.3 list shows revoked link with is_revoked=true", async () => {
    const created = await (await ownerPost(page, ALICE_ID, { file_node_id: filePath })).json();
    await ownerRevoke(page, ALICE_ID, created.link_id);
    const body = await (await ownerList(page)).json();
    const found = (body.items ?? []).find((l: { link_id: string }) => l.link_id === created.link_id);
    expect(found?.is_revoked).toBe(true);
  });

  test("697.4 non-owner cannot revoke (403)", async () => {
    const created = await (await ownerPost(page, ALICE_ID, { file_node_id: filePath })).json();
    const bobPage = await page.context().browser()!.newPage();
    await injectAuth(bobPage, BOB_ID);
    const resp = await ownerRevoke(bobPage, BOB_ID, created.link_id);
    expect(resp.status()).toBe(403);
    await bobPage.close();
  });
});

// ─── 698. Public Link Info API ────────────────────────────────────────────────

test.describe("698. Public Link Info API", () => {
  let page: Page;
  let filePath: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    filePath = await uploadFile(page, ALICE_ID, `fsl_info_${TS}.txt`, "info-content");
  });
  test.afterAll(async () => page.close());

  test("698.1 info shows file details without auth", async () => {
    const created = await (await ownerPost(page, ALICE_ID, { file_node_id: filePath })).json();
    const anon = await pwRequest.newContext();
    const resp = await anon.get(`${API}/public/files/share/${created.link_id}/info`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(typeof body.file_name).toBe("string");
    expect(typeof body.file_size_bytes).toBe("number");
    expect(body.requires_password).toBe(false);
    await anon.dispose();
  });

  test("698.2 info does not reveal owner or s3 key", async () => {
    const created = await (await ownerPost(page, ALICE_ID, { file_node_id: filePath })).json();
    const anon = await pwRequest.newContext();
    const resp = await anon.get(`${API}/public/files/share/${created.link_id}/info`);
    const body = await resp.json();
    expect(body).not.toHaveProperty("owner_sub");
    expect(body).not.toHaveProperty("encrypted_s3_key");
    expect(body).not.toHaveProperty?.("encryption_key_wrapped");
    expect(body.owner_sub).toBeUndefined();
    await anon.dispose();
  });

  test("698.3 password-protected link shows requires_password=true", async () => {
    const created = await (await ownerPost(page, ALICE_ID, {
      file_node_id: filePath,
      password: "pw1234",
    })).json();
    const anon = await pwRequest.newContext();
    const resp = await anon.get(`${API}/public/files/share/${created.link_id}/info`);
    const body = await resp.json();
    expect(body.requires_password).toBe(true);
    await anon.dispose();
  });

  test("698.4 used link shows remaining_downloads=0 and is_used=true", async () => {
    const created = await (await ownerPost(page, ALICE_ID, {
      file_node_id: filePath,
      max_downloads: 1,
    })).json();
    const anon = await pwRequest.newContext();
    await anon.post(`${API}/public/files/share/${created.link_id}/download`, { data: {} });
    const resp = await anon.get(`${API}/public/files/share/${created.link_id}/info`);
    const body = await resp.json();
    expect(body.remaining_downloads).toBe(0);
    expect(body.is_used).toBe(true);
    await anon.dispose();
  });

  test("698.5 info for non-existent link returns 404", async () => {
    const anon = await pwRequest.newContext();
    const resp = await anon.get(`${API}/public/files/share/fsl_nope_${TS}/info`);
    expect(resp.status()).toBe(404);
    await anon.dispose();
  });
});

// ─── 699. Share Links UI ──────────────────────────────────────────────────────

test.describe("699. Share Links UI", () => {
  let page: Page;
  let filePath: string;
  let linkId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    filePath = await uploadFile(page, ALICE_ID, `fsl_ui_${TS}.txt`, "ui-content");
    const created = await (await ownerPost(page, ALICE_ID, { file_node_id: filePath })).json();
    linkId = created.link_id;
  });
  test.afterAll(async () => page.close());

  test("699.1 management page renders and lists links", async () => {
    await page.goto(`${BASE}/files/share-links`, { waitUntil: "load" });
    await expect(page.locator("[data-testid='share-links-page']")).toBeVisible({ timeout: 8000 });
    await expect(page.locator("[data-testid='share-link-row']").first()).toBeVisible({ timeout: 8000 });
  });

  test("699.2 share link dialog opens from file context menu", async () => {
    await page.goto(`${BASE}/files`, { waitUntil: "load" });
    await page.waitForTimeout(1500);
    const row = page.locator("tr", { hasText: `fsl_ui_${TS}.txt` }).first();
    await expect(row).toBeVisible({ timeout: 8000 });
    await row.locator("button").last().click();
    await page.getByText("Create Share Link").click();
    await expect(page.locator("[data-testid='share-link-dialog']")).toBeVisible({ timeout: 5000 });
  });

  test("699.3 public download page shows file info (unauthenticated)", async ({ browser }) => {
    // Fresh context with NO auth cookies.
    const anonPage = await browser.newPage();
    await anonPage.goto(`${BASE}/share/${linkId}`, { waitUntil: "load" });
    await expect(anonPage.locator("[data-testid='public-download-page']")).toBeVisible({ timeout: 8000 });
    await expect(anonPage.locator("[data-testid='public-download-button']")).toBeVisible({ timeout: 8000 });
    await anonPage.close();
  });
});

// ─── 700. Edge cases ──────────────────────────────────────────────────────────

test.describe("700. Share Link Edge Cases", () => {
  let page: Page;
  let filePath: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    filePath = await uploadFile(page, ALICE_ID, `fsl_edge_${TS}.txt`, "edge-content");
  });
  test.afterAll(async () => page.close());

  test("700.1 two downloads on max_downloads=2 succeed, third is 410", async () => {
    const created = await (await ownerPost(page, ALICE_ID, {
      file_node_id: filePath,
      max_downloads: 2,
    })).json();
    const anon = await pwRequest.newContext();
    const r1 = await anon.post(`${API}/public/files/share/${created.link_id}/download`, { data: {} });
    const r2 = await anon.post(`${API}/public/files/share/${created.link_id}/download`, { data: {} });
    const r3 = await anon.post(`${API}/public/files/share/${created.link_id}/download`, { data: {} });
    expect(r1.status()).toBe(200);
    expect(r2.status()).toBe(200);
    expect(r3.status()).toBe(410);
    await anon.dispose();
  });

  test("700.2 management endpoints require auth (401 without session)", async () => {
    const anon = await pwRequest.newContext();
    const resp = await anon.get(`${API}/ui/files/share-links`);
    expect(resp.status()).toBe(401);
    await anon.dispose();
  });

  test("700.3 download with GET also works (no password link)", async () => {
    const created = await (await ownerPost(page, ALICE_ID, {
      file_node_id: filePath,
      max_downloads: 1,
    })).json();
    const anon = await pwRequest.newContext();
    const resp = await anon.get(`${API}/public/files/share/${created.link_id}/download`);
    expect(resp.status()).toBe(200);
    await anon.dispose();
  });
});
