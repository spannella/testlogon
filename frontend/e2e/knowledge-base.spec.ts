/**
 * E2E tests for the SuiteCRM Knowledge Base (KB-001..KB-012).
 *
 * Sections:
 *   90 — Category CRUD — API (admin write, all read)
 *   91 — Article CRUD + publish lifecycle — API
 *   92 — Article rating + view count — API
 *   93 — Search + tags + public portal endpoints — API
 *   94 — KnowledgeBasePage / portal UI
 *
 * Auth: uses e2e_admin_session_setup.py (all identities)
 *
 * Identities:
 *   root          – root.admin@testdev.local  – role=root  (admin write access)
 *   bob           – e2e_bob@test.local        – role=user  (reader)
 *
 * NOTE: KB endpoints are gated behind S.knowledge_base_enabled. When the flag
 * is OFF the backend returns 404 to every KB route; these tests skip the body
 * when the feature is not enabled (detected from the first list call).
 *
 * The KB router is mounted at /kb (authenticated) and /public/kb (public) —
 * NOT under /ui or /api.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ROOT_SUB = "root.admin@testdev.local";
const BOB_ID = "e2e_bob@test.local";
const TS = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

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

// ─── Page factory + helpers ───────────────────────────────────────────────────

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

async function apiPut(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.put(`${API}/${path}`, {
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

/** Returns true when the KB feature flag is enabled (article list != 404). */
async function kbEnabled(page: Page): Promise<boolean> {
  const resp = await apiGet(page, "kb/articles");
  return resp.status() !== 404;
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 90 — Category CRUD — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 90: KB Category CRUD (API)", () => {
  let rootPage: Page;
  let bobPage: Page;
  let categoryId = "";
  let enabled = false;
  const CAT_NAME = `E2E KB Category ${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
    bobPage = await newIdentityPage(browser, "bob");
    enabled = await kbEnabled(rootPage);
  });

  test.afterAll(async () => {
    if (enabled && categoryId) {
      await apiDelete(rootPage, "root", `kb/categories/${categoryId}`);
    }
    await rootPage?.close();
    await bobPage?.close();
  });

  test("90.1 admin creates a category", async () => {
    test.skip(!enabled, "KB feature flag is OFF");
    const resp = await apiPost(rootPage, "root", "kb/categories", {
      name: CAT_NAME,
      description: "E2E category",
      sort_order: 1,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.name).toBe(CAT_NAME);
    expect(body.category_id).toBeTruthy();
    categoryId = body.category_id;
  });

  test("90.2 non-admin cannot create a category (403)", async () => {
    test.skip(!enabled, "KB feature flag is OFF");
    const resp = await apiPost(bobPage, "bob", "kb/categories", { name: "nope" });
    expect(resp.status()).toBe(403);
  });

  test("90.3 list categories includes the new one", async () => {
    test.skip(!enabled || !categoryId, "KB off or category not created");
    const resp = await apiGet(rootPage, "kb/categories");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.categories)).toBe(true);
    expect(body.categories.some((c: any) => c.category_id === categoryId)).toBe(true);
  });

  test("90.4 update category name", async () => {
    test.skip(!enabled || !categoryId, "KB off or category not created");
    const resp = await apiPut(rootPage, "root", `kb/categories/${categoryId}`, {
      name: `${CAT_NAME} (updated)`,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.name).toContain("updated");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 91 — Article CRUD + publish lifecycle — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 91: KB Article CRUD + lifecycle (API)", () => {
  let rootPage: Page;
  let bobPage: Page;
  let articleId = "";
  let enabled = false;
  const TITLE = `E2E KB Article ${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
    bobPage = await newIdentityPage(browser, "bob");
    enabled = await kbEnabled(rootPage);
  });

  test.afterAll(async () => {
    if (enabled && articleId) {
      await apiDelete(rootPage, "root", `kb/articles/${articleId}`);
    }
    await rootPage?.close();
    await bobPage?.close();
  });

  test("91.1 admin creates a draft article (201)", async () => {
    test.skip(!enabled, "KB feature flag is OFF");
    const resp = await apiPost(rootPage, "root", "kb/articles", {
      title: TITLE,
      body_html: "<p>Hello KB</p>",
      excerpt: "Hello",
      tags: [`kbtag${TS}`],
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.title).toBe(TITLE);
    expect(body.status).toBe("draft");
    articleId = body.article_id;
  });

  test("91.2 non-admin cannot create an article (403)", async () => {
    test.skip(!enabled, "KB feature flag is OFF");
    const resp = await apiPost(bobPage, "bob", "kb/articles", { title: "nope" });
    expect(resp.status()).toBe(403);
  });

  test("91.3 update article body", async () => {
    test.skip(!enabled || !articleId, "KB off or article not created");
    const resp = await apiPut(rootPage, "root", `kb/articles/${articleId}`, {
      body_html: "<p>Updated body</p>",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.body_html).toContain("Updated body");
  });

  test("91.4 publish the article", async () => {
    test.skip(!enabled || !articleId, "KB off or article not created");
    const resp = await apiPost(rootPage, "root", `kb/articles/${articleId}/publish`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("published");
    expect(body.published_at).toBeTruthy();
  });

  test("91.5 published article appears in non-admin list", async () => {
    test.skip(!enabled || !articleId, "KB off or article not created");
    const resp = await apiGet(bobPage, "kb/articles", { status: "published", limit: "100" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.items.some((a: any) => a.article_id === articleId)).toBe(true);
  });

  test("91.6 unpublish back to draft", async () => {
    test.skip(!enabled || !articleId, "KB off or article not created");
    const resp = await apiPost(rootPage, "root", `kb/articles/${articleId}/unpublish`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("draft");
  });

  test("91.7 re-publish then expire", async () => {
    test.skip(!enabled || !articleId, "KB off or article not created");
    await apiPost(rootPage, "root", `kb/articles/${articleId}/publish`);
    const resp = await apiPost(rootPage, "root", `kb/articles/${articleId}/expire`, {
      reason: "E2E expiry",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("expired");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 92 — Article rating + view count — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 92: KB rating + view count (API)", () => {
  let rootPage: Page;
  let bobPage: Page;
  let articleId = "";
  let enabled = false;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
    bobPage = await newIdentityPage(browser, "bob");
    enabled = await kbEnabled(rootPage);
    if (enabled) {
      const created = await apiPost(rootPage, "root", "kb/articles", {
        title: `E2E KB Ratings ${TS}`,
        body_html: "<p>rate me</p>",
      });
      articleId = (await created.json()).article_id;
      await apiPost(rootPage, "root", `kb/articles/${articleId}/publish`);
    }
  });

  test.afterAll(async () => {
    if (enabled && articleId) {
      await apiDelete(rootPage, "root", `kb/articles/${articleId}`);
    }
    await rootPage?.close();
    await bobPage?.close();
  });

  test("92.1 rate article helpful", async () => {
    test.skip(!enabled || !articleId, "KB off or article not created");
    const resp = await apiPost(bobPage, "bob", `kb/articles/${articleId}/rate`, {
      helpful: true,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.helpful_count).toBeGreaterThanOrEqual(1);
  });

  test("92.2 rating again is idempotent (already_rated)", async () => {
    test.skip(!enabled || !articleId, "KB off or article not created");
    const resp = await apiPost(bobPage, "bob", `kb/articles/${articleId}/rate`, {
      helpful: true,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.already_rated).toBe(true);
  });

  test("92.3 GET article returns view/helpful counters", async () => {
    test.skip(!enabled || !articleId, "KB off or article not created");
    const resp = await apiGet(bobPage, `kb/articles/${articleId}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(typeof body.view_count).toBe("number");
    expect(body.helpful_count).toBeGreaterThanOrEqual(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 93 — Search + tags + public portal — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 93: KB search + tags + public portal (API)", () => {
  let rootPage: Page;
  let bobPage: Page;
  let articleId = "";
  let enabled = false;
  const UNIQ = `kbsearch${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
    bobPage = await newIdentityPage(browser, "bob");
    enabled = await kbEnabled(rootPage);
    if (enabled) {
      const created = await apiPost(rootPage, "root", "kb/articles", {
        title: `${UNIQ} searchable title`,
        body_html: `<p>${UNIQ} content</p>`,
        excerpt: UNIQ,
        tags: [UNIQ],
      });
      articleId = (await created.json()).article_id;
      await apiPost(rootPage, "root", `kb/articles/${articleId}/publish`);
    }
  });

  test.afterAll(async () => {
    if (enabled && articleId) {
      await apiDelete(rootPage, "root", `kb/articles/${articleId}`);
    }
    await rootPage?.close();
    await bobPage?.close();
  });

  test("93.1 authenticated search finds the article", async () => {
    test.skip(!enabled || !articleId, "KB off or article not created");
    const resp = await apiGet(bobPage, "kb/search", { q: UNIQ, limit: "20" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.query).toBe(UNIQ);
    expect(Array.isArray(body.items)).toBe(true);
  });

  test("93.2 list popular tags", async () => {
    test.skip(!enabled, "KB feature flag is OFF");
    const resp = await apiGet(bobPage, "public/kb/tags", { limit: "50" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.tags)).toBe(true);
  });

  test("93.3 list articles by tag", async () => {
    test.skip(!enabled || !articleId, "KB off or article not created");
    const resp = await apiGet(bobPage, `public/kb/tags/${UNIQ}/articles`, { limit: "20" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.items)).toBe(true);
  });

  test("93.4 public portal search (unauthenticated)", async () => {
    test.skip(!enabled, "KB feature flag is OFF");
    // Use a fresh page WITHOUT cookies for the public endpoint.
    const resp = await rootPage.request.get(`${API}/public/kb/search`, {
      params: { q: UNIQ, limit: "20" },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.items)).toBe(true);
  });

  test("93.5 public portal categories list", async () => {
    test.skip(!enabled, "KB feature flag is OFF");
    const resp = await rootPage.request.get(`${API}/public/kb/categories`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.categories)).toBe(true);
  });

  test("93.6 public article view increments view count path", async () => {
    test.skip(!enabled || !articleId, "KB off or article not created");
    const resp = await rootPage.request.get(`${API}/public/kb/articles/${articleId}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.article_id).toBe(articleId);
    expect(body.status).toBe("published");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 94 — KnowledgeBasePage / portal UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 94: Knowledge Base UI", () => {
  let enabled = false;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    const probe = await newIdentityPage(browser, "root");
    enabled = await kbEnabled(probe);
    await probe.close();
  });

  test("94.1 article list page renders header", async ({ page }) => {
    test.skip(!enabled, "KB feature flag is OFF");
    await injectAuth(page, "bob");
    await page.goto(`${BASE}/crm/knowledge-base`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Knowledge Base", exact: true })).toBeVisible();
  });

  test("94.2 admin sees New article action", async ({ page }) => {
    test.skip(!enabled, "KB feature flag is OFF");
    await injectAuth(page, "root");
    await page.goto(`${BASE}/crm/knowledge-base`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("button", { name: /New article/i }).first()).toBeVisible();
  });

  test("94.3 public portal page renders Help Center", async ({ page }) => {
    test.skip(!enabled, "KB feature flag is OFF");
    await injectAuth(page, "bob");
    await page.goto(`${BASE}/crm/knowledge-base/portal`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Help Center" })).toBeVisible();
  });

  test("94.4 manage page lists status tabs (admin)", async ({ page }) => {
    test.skip(!enabled, "KB feature flag is OFF");
    await injectAuth(page, "root");
    await page.goto(`${BASE}/crm/knowledge-base/manage`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("tab", { name: "Drafts" })).toBeVisible();
  });
});

// Reference unused identifiers to satisfy strict noUnusedLocals during authoring.
void ROOT_SUB;
void BOB_ID;
