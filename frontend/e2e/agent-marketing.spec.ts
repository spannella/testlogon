/**
 * E2E tests for the Marketing Agent (AGENT-017).
 *
 * Section 687: Content CRUD API (5 tests)
 * Section 688: Content Lifecycle API (5 tests)
 * Section 689: Calendar & Engagement API (4 tests)
 * Section 690: Marketing UI (4 tests)
 *
 * Auth: cookie-based sessions from e2e_admin_session_setup.py.
 *   alice – role=user (platform owner / primary actor)
 *   bob   – role=user (non-owner isolation)
 * POST/PUT/DELETE requests carry an x-csrf-token header (cookie auth).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");


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

let _sessions: Record<string, AdminSessionData> | null = null;
function getSessions(): Record<string, AdminSessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  const uid = sessions[identity].user_sub;
  await page.addInitScript((userId: string) => {
    const state = { userId, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, uid);
  return page;
}

async function injectAuth(page: Page, identity: string): Promise<void> {
  const sessions = getSessions();
  await page.context().addCookies(sessions[identity].cookies);
  // Seed the persisted auth store so ProtectedRoute treats the page as
  // authenticated (cookie injection alone leaves isAuthenticated=false → /login).
  const uid = sessions[identity].user_sub;
  await page.addInitScript((userId: string) => {
    const state = { userId, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, uid);
}

async function apiPut(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.put(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: { "x-csrf-token": sess.csrf_token },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

const TS = Date.now();
let contentId1 = ""; // blog post
let contentId2 = ""; // social post
let contentId3 = ""; // release notes

// ─── 687: Content CRUD API ──────────────────────────────────────────────────

test.describe("687. Marketing Content CRUD API", () => {
  let alicePage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("687.1 create blog post draft", async () => {
    const r = await apiPost(alicePage, "alice", "ui/agents/marketing/content", {
      content_type: "blog_post",
      title: `Launch ${TS}`,
      body: "## Big launch\n\nWe shipped a thing.",
      tags: ["launch"],
    });
    expect(r.status()).toBe(201);
    const data = (await r.json()) as Record<string, unknown>;
    contentId1 = data.content_id as string;
    expect(data.status).toBe("draft");
    expect(data.content_type).toBe("blog_post");
  });

  test("687.2 create social media post", async () => {
    const r = await apiPost(alicePage, "alice", "ui/agents/marketing/content", {
      content_type: "social_twitter",
      title: `Tweet ${TS}`,
      body: "We shipped something awesome today!",
    });
    expect(r.status()).toBe(201);
    const data = (await r.json()) as Record<string, unknown>;
    contentId2 = data.content_id as string;
    expect(data.content_type).toBe("social_twitter");
  });

  test("687.3 create release notes with feature refs", async () => {
    const r = await apiPost(alicePage, "alice", "ui/agents/marketing/content", {
      content_type: "release_notes",
      title: `Release ${TS}`,
      body: "# Release notes\n\n- Feature A",
      feature_refs: [`TICKET-${TS}`],
    });
    expect(r.status()).toBe(201);
    const data = (await r.json()) as { content_id: string; feature_refs: string[] };
    contentId3 = data.content_id;
    expect(data.feature_refs).toContain(`TICKET-${TS}`);
  });

  test("687.4 get content detail", async () => {
    const r = await apiGet(alicePage, `ui/agents/marketing/content/${contentId1}`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.title).toBe(`Launch ${TS}`);
    expect((data.tags as string[]) ?? []).toContain("launch");
  });

  test("687.5 list content by type", async () => {
    const r = await apiGet(alicePage, "ui/agents/marketing/content", { type: "blog_post", limit: "50" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { items: Array<{ content_type: string; content_id: string }> };
    expect(data.items.length).toBeGreaterThan(0);
    expect(data.items.every((c) => c.content_type === "blog_post")).toBe(true);
    expect(data.items.some((c) => c.content_id === contentId1)).toBe(true);
  });

  test("687.6 invalid content_type rejected", async () => {
    const r = await apiPost(alicePage, "alice", "ui/agents/marketing/content", {
      content_type: "not_a_type",
      title: "x",
      body: "y",
    });
    expect(r.status()).toBe(422);
  });

  test("687.7 non-owner cannot see content", async ({ browser }) => {
    const bobPage = await newIdentityPage(browser, "bob");
    const r = await apiGet(bobPage, `ui/agents/marketing/content/${contentId1}`);
    expect(r.status()).toBe(404);
    await bobPage.close();
  });
});

// ─── 688: Content Lifecycle API ──────────────────────────────────────────────

test.describe("688. Marketing Content Lifecycle API", () => {
  let alicePage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("688.1 approve content", async () => {
    const r = await apiPost(alicePage, "alice", `ui/agents/marketing/content/${contentId1}/approve`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.status).toBe("approved");
  });

  test("688.2 schedule content for the future", async () => {
    const publishAt = Math.floor(Date.now() / 1000) + 3600;
    const r = await apiPost(
      alicePage,
      "alice",
      `ui/agents/marketing/content/${contentId1}/schedule`,
      { publish_at: publishAt },
    );
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.status).toBe("scheduled");
    expect(data.scheduled_publish_at).toBe(publishAt);
  });

  test("688.3 schedule in the past rejected", async () => {
    // contentId2 must first be approved.
    await apiPost(alicePage, "alice", `ui/agents/marketing/content/${contentId2}/approve`);
    const r = await apiPost(
      alicePage,
      "alice",
      `ui/agents/marketing/content/${contentId2}/schedule`,
      { publish_at: Math.floor(Date.now() / 1000) - 60 },
    );
    expect(r.status()).toBe(400);
  });

  test("688.4 publish content immediately then archive", async () => {
    const pub = await apiPost(alicePage, "alice", `ui/agents/marketing/content/${contentId2}/publish`);
    expect(pub.status()).toBe(200);
    const pubData = (await pub.json()) as Record<string, unknown>;
    expect(pubData.status).toBe("published");
    expect(pubData.published_at).toBeTruthy();

    const arch = await apiPost(alicePage, "alice", `ui/agents/marketing/content/${contentId2}/archive`);
    expect(arch.status()).toBe(200);
    expect(((await arch.json()) as Record<string, unknown>).status).toBe("archived");
  });

  test("688.5 delete draft content; subsequent GET 404", async () => {
    const del = await apiDelete(alicePage, "alice", `ui/agents/marketing/content/${contentId3}`);
    expect(del.status()).toBe(200);
    const get = await apiGet(alicePage, `ui/agents/marketing/content/${contentId3}`);
    expect(get.status()).toBe(404);
  });

  test("688.6 delete non-draft content rejected (409)", async () => {
    // contentId1 is scheduled; cannot delete.
    const del = await apiDelete(alicePage, "alice", `ui/agents/marketing/content/${contentId1}`);
    expect(del.status()).toBe(409);
  });
});

// ─── 689: Calendar & Engagement API ───────────────────────────────────────────

test.describe("689. Calendar, Engagement & Generation API", () => {
  let alicePage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("689.1 get content calendar", async () => {
    // contentId1 was scheduled +1h => this month or next; query current month.
    const d = new Date();
    const month = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
    const r = await apiGet(alicePage, "ui/agents/marketing/calendar", { month });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Array<Record<string, unknown>>;
    expect(Array.isArray(data)).toBe(true);
  });

  test("689.2 get engagement stats for content", async () => {
    const r = await apiGet(alicePage, `ui/agents/marketing/content/${contentId1}/engagement`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, number>;
    expect(typeof data.total_views).toBe("number");
    expect(typeof data.total_clicks).toBe("number");
  });

  test("689.3 get engagement summary", async () => {
    const r = await apiGet(alicePage, "ui/agents/marketing/engagement/summary");
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { total_content: number };
    expect(data.total_content).toBeGreaterThanOrEqual(1);
  });

  test("689.4 update marketing config", async () => {
    const r = await apiPut(alicePage, "alice", "ui/agents/marketing/config", {
      brand_voice: { tone: "friendly" },
      ab_test_variations: 3,
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { brand_voice: { tone: string }; ab_test_variations: number };
    expect(data.brand_voice.tone).toBe("friendly");
    expect(data.ab_test_variations).toBe(3);
  });

  test("689.5 generate content for a feature", async () => {
    const r = await apiPost(alicePage, "alice", "ui/agents/marketing/generate", {
      feature_ticket_ids: [`FEED-${TS}`],
      content_types: ["blog_post", "changelog"],
    });
    expect(r.status()).toBe(201);
    const data = (await r.json()) as { status: string; count: number; contents: unknown[] };
    expect(data.status).toBe("completed");
    expect(data.count).toBe(2);
    expect(data.contents.length).toBe(2);
  });
});

// ─── 690: Marketing UI ────────────────────────────────────────────────────────

test.describe("690. Marketing UI", () => {
  test("690.1 content dashboard loads", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "alice");
    await page.goto("/agents/marketing");
    await expect(page.locator('[data-testid="content-dashboard-page"]')).toBeVisible();
    await expect(page.getByRole("heading", { name: "Marketing Content" })).toBeVisible();
    await page.close();
  });

  test("690.2 content editor opens", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "alice");
    await page.goto(`/agents/marketing/content/${contentId1}`);
    await expect(page.locator('[data-testid="content-editor-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="editor-body"]')).toBeVisible();
    await page.close();
  });

  test("690.3 calendar page shows", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "alice");
    await page.goto("/agents/marketing/calendar");
    await expect(page.locator('[data-testid="content-calendar-page"]')).toBeVisible();
    await page.close();
  });

  test("690.4 engagement dashboard loads", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "alice");
    await page.goto("/agents/marketing/engagement");
    await expect(page.locator('[data-testid="engagement-dashboard-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="summary-cards"]')).toBeVisible();
    await page.close();
  });
});
