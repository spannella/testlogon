/**
 * E2E tests for Newsfeed Drafts API (/posts/drafts).
 *
 * Auth: all endpoints use require_ui_session (session cookies + x-csrf-token).
 * Test user: Alice (e2e_alice@test.local)
 *
 * Endpoints tested:
 *   POST   /posts/drafts                   — create draft
 *   GET    /posts/drafts                   — list drafts
 *   GET    /posts/drafts/{draft_id}        — get single draft
 *   PATCH  /posts/drafts/{draft_id}        — update draft
 *   DELETE /posts/drafts/{draft_id}        — delete draft
 *   POST   /posts/drafts/{draft_id}/publish — publish draft
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";
const BASE = "http://localhost:3000";
const REPO_ROOT = REPO_ROOT;
const ALICE_ID = "e2e_alice@test.local";

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
    const raw = execSync(
      "python3 e2e_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiPost(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}${path}`, { params });
}

async function apiPatch(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.patch(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiDelete(page: Page, path: string, params?: Record<string, string>) {
  const session = getSessions()[ALICE_ID];
  return page.request.delete(`${API}${path}`, {
    params,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── Cleanup helper ───────────────────────────────────────────────────────────

async function deleteDraft(page: Page, draftId: string) {
  try {
    await apiDelete(page, `/posts/drafts/${draftId}`);
  } catch {
    // best-effort cleanup
  }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

test.describe("76 — Newsfeed drafts API", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("76.1 create draft returns correct structure", async () => {
    test.setTimeout(60_000);
    const suffix = Date.now();
    const body = `Draft body ${suffix}`;
    let draftId: string | undefined;

    try {
      const resp = await apiPost(page, "/posts/drafts", { body });
      expect(resp.status()).toBe(200);

      const data = await resp.json();
      expect(data.draft_id).toBeTruthy();
      expect(data.author_id).toBeTruthy();
      expect(data.body).toBe(body);
      expect(data.created_at).toBeTruthy();
      expect(data.updated_at).toBeTruthy();

      draftId = data.draft_id;
    } finally {
      if (draftId) await deleteDraft(page, draftId);
    }
  });

  test("76.2 list drafts returns created draft", async () => {
    test.setTimeout(60_000);
    const suffix = Date.now();
    const body = `List draft ${suffix}`;
    let draftId: string | undefined;

    try {
      const createResp = await apiPost(page, "/posts/drafts", { body });
      expect(createResp.status()).toBe(200);
      const created = await createResp.json();
      draftId = created.draft_id;

      const listResp = await apiGet(page, "/posts/drafts");
      expect(listResp.status()).toBe(200);
      const listData = await listResp.json();

      expect(Array.isArray(listData.items)).toBe(true);
      const found = listData.items.find((d: any) => d.draft_id === draftId);
      expect(found).toBeTruthy();
      expect(found.body).toBe(body);
    } finally {
      if (draftId) await deleteDraft(page, draftId);
    }
  });

  test("76.3 get single draft by ID", async () => {
    test.setTimeout(60_000);
    const suffix = Date.now();
    const body = `Single draft ${suffix}`;
    let draftId: string | undefined;

    try {
      const createResp = await apiPost(page, "/posts/drafts", { body });
      expect(createResp.status()).toBe(200);
      const created = await createResp.json();
      draftId = created.draft_id;

      const getResp = await apiGet(page, `/posts/drafts/${draftId}`);
      expect(getResp.status()).toBe(200);
      const data = await getResp.json();
      expect(data.draft_id).toBe(draftId);
      expect(data.body).toBe(body);
    } finally {
      if (draftId) await deleteDraft(page, draftId);
    }
  });

  test("76.4 update draft body", async () => {
    test.setTimeout(60_000);
    const suffix = Date.now();
    const originalBody = `Original ${suffix}`;
    const updatedBody = `Updated ${suffix}`;
    let draftId: string | undefined;

    try {
      const createResp = await apiPost(page, "/posts/drafts", { body: originalBody });
      expect(createResp.status()).toBe(200);
      const created = await createResp.json();
      draftId = created.draft_id;
      const originalUpdatedAt = created.updated_at;

      const patchResp = await apiPatch(page, `/posts/drafts/${draftId}`, {
        body: updatedBody,
      });
      expect(patchResp.status()).toBe(200);
      const patched = await patchResp.json();
      expect(patched.body).toBe(updatedBody);
      expect(patched.updated_at).not.toBe(originalUpdatedAt);
    } finally {
      if (draftId) await deleteDraft(page, draftId);
    }
  });

  test("76.5 delete draft", async () => {
    test.setTimeout(60_000);
    const suffix = Date.now();
    const body = `Delete me ${suffix}`;

    const createResp = await apiPost(page, "/posts/drafts", { body });
    expect(createResp.status()).toBe(200);
    const created = await createResp.json();
    const draftId = created.draft_id;

    const deleteResp = await apiDelete(page, `/posts/drafts/${draftId}`);
    expect(deleteResp.status()).toBe(200);
    const deleteData = await deleteResp.json();
    expect(deleteData.ok).toBe(true);

    const getResp = await apiGet(page, `/posts/drafts/${draftId}`);
    expect(getResp.status()).toBe(404);
  });

  test("76.6 publish draft creates a post", async () => {
    test.setTimeout(60_000);
    const suffix = Date.now();
    const body = `Publish me ${suffix}`;
    let draftId: string | undefined;

    try {
      const createResp = await apiPost(page, "/posts/drafts", { body });
      expect(createResp.status()).toBe(200);
      const created = await createResp.json();
      draftId = created.draft_id;

      const publishResp = await apiPost(page, `/posts/drafts/${draftId}/publish`, {});
      expect(publishResp.status()).toBe(200);
      const published = await publishResp.json();
      expect(published.post_id).toBeTruthy();
      expect(published.body).toBe(body);

      // Draft should be deleted after publish (keep_copy defaults to false)
      const getResp = await apiGet(page, `/posts/drafts/${draftId}`);
      expect(getResp.status()).toBe(404);
      draftId = undefined; // no cleanup needed
    } finally {
      if (draftId) await deleteDraft(page, draftId);
    }
  });

  test("76.7 publish draft with keep_copy=true preserves draft", async () => {
    test.setTimeout(60_000);
    const suffix = Date.now();
    const body = `Keep copy ${suffix}`;
    let draftId: string | undefined;

    try {
      const createResp = await apiPost(page, "/posts/drafts", { body });
      expect(createResp.status()).toBe(200);
      const created = await createResp.json();
      draftId = created.draft_id;

      const publishResp = await apiPost(page, `/posts/drafts/${draftId}/publish`, {
        keep_copy: true,
      });
      expect(publishResp.status()).toBe(200);
      const published = await publishResp.json();
      expect(published.post_id).toBeTruthy();
      expect(published.body).toBe(body);

      // Draft should still exist
      const getResp = await apiGet(page, `/posts/drafts/${draftId}`);
      expect(getResp.status()).toBe(200);
      const draft = await getResp.json();
      expect(draft.draft_id).toBe(draftId);
      expect(draft.body).toBe(body);
    } finally {
      if (draftId) await deleteDraft(page, draftId);
    }
  });

  test("76.8 list drafts pagination", async () => {
    test.setTimeout(60_000);
    const suffix = Date.now();
    const draftIds: string[] = [];

    try {
      // Create 3 drafts
      for (let i = 0; i < 3; i++) {
        const resp = await apiPost(page, "/posts/drafts", {
          body: `Pagination draft ${i} ${suffix}`,
        });
        expect(resp.status()).toBe(200);
        const data = await resp.json();
        draftIds.push(data.draft_id);
      }

      // List with limit=2
      const listResp = await apiGet(page, "/posts/drafts", { limit: "2" });
      expect(listResp.status()).toBe(200);
      const listData = await listResp.json();

      expect(listData.items.length).toBe(2);
      expect(listData.next_cursor).toBeTruthy();
    } finally {
      for (const id of draftIds) {
        await deleteDraft(page, id);
      }
    }
  });

  test("76.9 update with stale expected_updated_at fails", async () => {
    test.setTimeout(60_000);
    const suffix = Date.now();
    const body = `Conflict draft ${suffix}`;
    let draftId: string | undefined;

    try {
      const createResp = await apiPost(page, "/posts/drafts", { body });
      expect(createResp.status()).toBe(200);
      const created = await createResp.json();
      draftId = created.draft_id;
      const staleUpdatedAt = created.updated_at;

      // First update succeeds and changes updated_at
      const firstPatch = await apiPatch(page, `/posts/drafts/${draftId}`, {
        body: `First update ${suffix}`,
      });
      expect(firstPatch.status()).toBe(200);

      // Second update with stale expected_updated_at should fail with 409
      const stalePatch = await apiPatch(page, `/posts/drafts/${draftId}`, {
        body: `Stale update ${suffix}`,
        expected_updated_at: staleUpdatedAt,
      });
      expect(stalePatch.status()).toBe(409);
    } finally {
      if (draftId) await deleteDraft(page, draftId);
    }
  });

  test("76.10 delete non-existent draft returns 404", async () => {
    test.setTimeout(60_000);
    const fakeDraftId = `draft_ffffffffffffffffffffffffffffffff`;

    const resp = await apiDelete(page, `/posts/drafts/${fakeDraftId}`);
    expect(resp.status()).toBe(404);
  });
});
