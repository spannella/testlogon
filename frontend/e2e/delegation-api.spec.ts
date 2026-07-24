/**
 * E2E tests for the Delegation API (DELEGATE-005).
 *
 * Sections:
 *   503 — Delegation API key CRUD (cookie auth)        (4 tests)
 *   504 — Programmatic key auth + scope enforcement    (5 tests)
 *   505 — Usage tracking & rate-limit headers          (3 tests)
 *
 * Model: Alice is the CREATOR, Bob is her active DELEGATE. Bob issues
 * delegation API keys scoped to Alice. Programmatic calls use the issued
 * `dak_<id>.<secret>` key in an Authorization: Bearer header — these requests
 * carry no session cookie, so they bypass CSRF (the global `request` fixture
 * is used, not `page.request`).
 */

import { test, expect, type Page, type APIRequestContext } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<Record<string, unknown>>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
    // admin setup keys by short name (alice/bob); alias by user_sub so email-id lookups resolve
    for (const _k of Object.keys(_sessions)) { const _s = _sessions[_k]; if (_s && _s.user_sub && !_sessions[_s.user_sub]) _sessions[_s.user_sub] = _s; }
  }
  return _sessions!;
}

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies as never);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

function csrf(userId: string): Record<string, string> {
  return { "x-csrf-token": getSessions()[userId].csrf_token };
}

async function apiPost(page: Page, userId: string, path: string, body: object) {
  return page.request.post(`${BASE}${path}`, { data: body, headers: csrf(userId) });
}
async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}
async function apiDelete(page: Page, userId: string, path: string) {
  return page.request.delete(`${BASE}${path}`, { headers: csrf(userId) });
}

// Programmatic call helper: Bearer key, no session cookies (CSRF bypassed).
function keyAuth(req: APIRequestContext, key: string) {
  return {
    get: (path: string) =>
      req.get(`${BASE}${path}`, { headers: { Authorization: `Bearer ${key}` } }),
    post: (path: string, body: object) =>
      req.post(`${BASE}${path}`, {
        data: body,
        headers: { Authorization: `Bearer ${key}` },
      }),
  };
}

// Ensure Bob is an active delegate of Alice with full permissions.
async function ensureDelegate(page: Page) {
  // Settings: auto-accept so the relationship is active immediately.
  await page.request.put(`${BASE}/ui/delegates/settings`, {
    headers: csrf(ALICE_ID),
    data: {
      require_acceptance: false,
      max_delegates: 10,
      delegate_tag_enabled: true,
      delegate_tag_format: "[via @{delegate_name}]",
    },
  });
  // Add Bob (idempotent — ignore 409 if already present).
  await apiPost(page, ALICE_ID, "/ui/delegates", {
    delegate_id: BOB_ID,
    permissions: [
      "chat_read",
      "chat_respond",
      "feed_read",
      "feed_post",
    ],
    label: "Bob - API delegate",
  });
}

// ─── Section 503: Delegation API key CRUD ────────────────────────────────────

test.describe("503 — Delegation API key CRUD", () => {
  let bobPage: Page;
  let alicePage: Page;
  let createdKeyId = "";

  test.beforeAll(async ({ browser }) => {
    alicePage = await (await browser.newContext()).newPage();
    bobPage = await (await browser.newContext()).newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);
    await ensureDelegate(alicePage);
  });

  test.afterAll(async () => {
    await alicePage.context().close();
    await bobPage.context().close();
  });

  test("503.1 Bob issues a delegation API key scoped to Alice", async () => {
    const resp = await apiPost(bobPage, BOB_ID, "/ui/delegation-api/keys", {
      label: "CRUD key",
      creator_id: ALICE_ID,
      permissions: ["chat_read", "chat_respond"],
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.key_id).toBeTruthy();
    expect(data.key_secret).toMatch(/^dak_/);
    expect(data.status).toBe("active");
    expect(data.creator_id).toBe(ALICE_ID);
    expect(data.permissions).toContain("chat_read");
    createdKeyId = data.key_id;
  });

  test("503.2 Bob lists his delegation API keys (secret not returned)", async () => {
    const resp = await apiGet(bobPage, "/ui/delegation-api/keys");
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    const k = data.find((x: any) => x.key_id === createdKeyId);
    expect(k).toBeTruthy();
    expect(k.prefix).toMatch(/^dak_/);
    expect(k.key_secret == null).toBeTruthy();
  });

  test("503.3 Alice sees the key scoped to her account", async () => {
    const resp = await apiGet(alicePage, "/ui/delegation-api/creator-keys");
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.some((x: any) => x.key_id === createdKeyId)).toBeTruthy();
  });

  test("503.4 Alice revokes the delegation key", async () => {
    const resp = await apiDelete(
      alicePage,
      ALICE_ID,
      `/ui/delegation-api/creator-keys/${createdKeyId}`,
    );
    expect(resp.status()).toBe(200);
    const list = await apiGet(bobPage, "/ui/delegation-api/keys");
    const data = await list.json();
    expect(data.some((x: any) => x.key_id === createdKeyId)).toBeFalsy();
  });
});

// ─── Section 504: Programmatic auth + scope enforcement ──────────────────────

test.describe("504 — Programmatic key auth & scope enforcement", () => {
  let bobPage: Page;
  let fullKey = "";
  let readOnlyKey = "";

  test.beforeAll(async ({ browser }) => {
    const alicePage = await (await browser.newContext()).newPage();
    bobPage = await (await browser.newContext()).newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);
    await ensureDelegate(alicePage);

    const r1 = await apiPost(bobPage, BOB_ID, "/ui/delegation-api/keys", {
      label: "full chat key",
      creator_id: ALICE_ID,
      permissions: ["chat_read", "chat_respond"],
    });
    fullKey = (await r1.json()).key_secret;

    const r2 = await apiPost(bobPage, BOB_ID, "/ui/delegation-api/keys", {
      label: "feed read-only key",
      creator_id: ALICE_ID,
      permissions: ["feed_read"],
    });
    readOnlyKey = (await r2.json()).key_secret;

    await alicePage.context().close();
  });

  test.afterAll(async () => {
    await bobPage.context().close();
  });

  test("504.1 scope endpoint returns available actions", async ({ request }) => {
    const resp = await keyAuth(request, fullKey).get("/ui/delegation-api/v1/scope");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.creator_id).toBe(ALICE_ID);
    expect(data.permissions).toContain("chat_read");
    expect(data.available_actions.length).toBeGreaterThan(0);
  });

  test("504.2 authenticated chat_read call succeeds", async ({ request }) => {
    const resp = await keyAuth(request, fullKey).get(
      "/ui/delegation-api/v1/conversations",
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.conversations)).toBeTruthy();
  });

  test("504.3 missing/invalid key returns 401", async ({ request }) => {
    const resp = await request.get(`${BASE}/ui/delegation-api/v1/scope`, {
      headers: { Authorization: "Bearer dak_deadbeef.nope" },
    });
    expect(resp.status()).toBe(401);
  });

  test("504.4 key without chat_read is denied (403)", async ({ request }) => {
    const resp = await keyAuth(request, readOnlyKey).get(
      "/ui/delegation-api/v1/conversations",
    );
    expect(resp.status()).toBe(403);
  });

  test("504.5 key without chat_respond cannot send a message (403)", async ({
    request,
  }) => {
    const resp = await keyAuth(request, readOnlyKey).post(
      "/ui/delegation-api/v1/conversations/conv_does_not_matter/messages",
      { text: "hi" },
    );
    expect(resp.status()).toBe(403);
  });
});

// ─── Section 505: Usage tracking & rate-limit headers ────────────────────────

test.describe("505 — Usage tracking & rate-limit headers", () => {
  let bobPage: Page;
  let key = "";
  let keyId = "";

  test.beforeAll(async ({ browser }) => {
    const alicePage = await (await browser.newContext()).newPage();
    bobPage = await (await browser.newContext()).newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);
    await ensureDelegate(alicePage);

    const r = await apiPost(bobPage, BOB_ID, "/ui/delegation-api/keys", {
      label: "usage key",
      creator_id: ALICE_ID,
      permissions: ["chat_read"],
    });
    const j = await r.json();
    key = j.key_secret;
    keyId = j.key_id;
    await alicePage.context().close();
  });

  test.afterAll(async () => {
    await bobPage.context().close();
  });

  test("505.1 responses include X-RateLimit-* headers", async ({ request }) => {
    const resp = await keyAuth(request, key).get("/ui/delegation-api/v1/scope");
    expect(resp.status()).toBe(200);
    const headers = resp.headers();
    expect(headers["x-ratelimit-limit"]).toBeTruthy();
    expect(headers["x-ratelimit-remaining"]).toBeDefined();
    expect(headers["x-ratelimit-reset"]).toBeTruthy();
  });

  test("505.2 usage counter increments per call", async ({ request }) => {
    const before = await keyAuth(request, key).get("/ui/delegation-api/v1/scope");
    const beforeCalls = (await before.json()).total_calls as number;

    await keyAuth(request, key).get("/ui/delegation-api/v1/conversations");
    await keyAuth(request, key).get("/ui/delegation-api/v1/conversations");

    const after = await keyAuth(request, key).get("/ui/delegation-api/v1/scope");
    const afterCalls = (await after.json()).total_calls as number;
    expect(afterCalls).toBeGreaterThan(beforeCalls);
  });

  test("505.3 owner can fetch key scope via management endpoint", async () => {
    const resp = await apiGet(bobPage, `/ui/delegation-api/keys/${keyId}/scope`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.key_id).toBe(keyId);
    expect(data.permissions).toContain("chat_read");
    expect(data.total_calls).toBeGreaterThanOrEqual(0);
  });
});
