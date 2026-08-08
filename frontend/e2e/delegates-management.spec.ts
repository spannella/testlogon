/**
 * E2E tests for Delegate Management & Permissions (DELEGATE-001).
 *
 * Sections:
 *   487 — Delegate CRUD API          (5 tests)
 *   488 — Invite Flow API            (4 tests)
 *   489 — Permission Presets & Settings API (4 tests)
 *   490 — Audit Log API              (3 tests)
 *
 * Auth: Alice, Bob, Charlie sessions (from e2e_admin_session_setup.py).
 *
 * Uses cookie-based auth with CSRF headers on all mutating requests.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions, resolveIdentityId } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = resolveIdentityId("e2e_alice@test.local");
const BOB_ID = resolveIdentityId("e2e_bob@test.local");
const CHARLIE_ID = resolveIdentityId("e2e_charlie@test.local");

// ─── Session bootstrap ────────────────────────────────────────────────────────

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
    // admin setup keys by short name (alice/bob); alias by user_sub so email-id lookups resolve
    for (const _k of Object.keys(_sessions)) { const _s = _sessions[_k]; if (_s && _s.user_sub && !_sessions[_s.user_sub]) _sessions[_s.user_sub] = _s; }
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

async function apiPost(page: Page, userId: string, path: string, body: object) {
  const session = getSessions()[userId];
  return page.request.post(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

async function apiPut(page: Page, userId: string, path: string, body: object) {
  const session = getSessions()[userId];
  return page.request.put(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiDelete(page: Page, userId: string, path: string) {
  const session = getSessions()[userId];
  return page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── Cleanup helper ──────────────────────────────────────────────────────────

async function cleanupDelegates(page: Page, creatorId: string) {
  const resp = await apiGet(page, "/ui/delegates");
  if (resp.ok()) {
    const delegates = await resp.json();
    for (const d of delegates) {
      await apiDelete(page, creatorId, `/ui/delegates/${d.delegate_id}`);
    }
  }
}

// ─── Section 487: Delegate CRUD API ──────────────────────────────────────────

test.describe("487 — Delegate CRUD API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Reset settings to require_acceptance=true
    await apiPut(alicePage, ALICE_ID, "/ui/delegates/settings", {
      require_acceptance: true,
      max_delegates: 10,
      delegate_tag_enabled: true,
      delegate_tag_format: "[via @{delegate_name}]",
    });

    // Cleanup any existing delegates
    await cleanupDelegates(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await cleanupDelegates(alicePage, ALICE_ID);
    await alicePage.context().close();
  });

  test("487.1 Alice adds Bob as a delegate with chat_agent preset", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/delegates", {
      delegate_id: BOB_ID,
      permissions: ["chat_read", "chat_respond"],
      preset: "chat_agent",
      label: "Bob - Chat Agent",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.delegate_id).toBe(BOB_ID);
    expect(data.permissions).toContain("chat_read");
    expect(data.permissions).toContain("chat_respond");
    expect(data.status).toBe("pending");
  });

  test("487.2 Alice lists her delegates", async () => {
    const resp = await apiGet(alicePage, "/ui/delegates");
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.length).toBeGreaterThanOrEqual(1);
    const bob = data.find((d: any) => d.delegate_id === BOB_ID);
    expect(bob).toBeTruthy();
    expect(bob.permissions).toContain("chat_read");
  });

  test("487.3 Alice updates Bob's permissions to full_manager", async () => {
    const allPerms = [
      "broadcast_control",
      "broadcast_moderate",
      "chat_read",
      "chat_respond",
      "feed_moderate",
      "feed_post",
      "feed_read",
    ];
    const resp = await apiPut(alicePage, ALICE_ID, `/ui/delegates/${BOB_ID}/permissions`, {
      permissions: allPerms,
      preset: "full_manager",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.permissions.length).toBe(7);
  });

  test("487.4 Alice revokes Bob's delegate access", async () => {
    const resp = await apiDelete(alicePage, ALICE_ID, `/ui/delegates/${BOB_ID}`);
    expect(resp.ok()).toBeTruthy();

    const listResp = await apiGet(alicePage, "/ui/delegates");
    const data = await listResp.json();
    const bob = data.find((d: any) => d.delegate_id === BOB_ID);
    expect(bob).toBeFalsy();
  });

  test("487.5 Adding self as delegate returns 400", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/delegates", {
      delegate_id: ALICE_ID,
      permissions: ["chat_read"],
    });
    expect(resp.status()).toBe(400);
  });
});

// ─── Section 488: Invite Flow API ────────────────────────────────────────────

test.describe("488 — Invite Flow API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let charliePage: Page;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    const charlieCtx = await browser.newContext();
    charliePage = await charlieCtx.newPage();
    await injectAuth(charliePage, CHARLIE_ID);

    // Reset settings
    await apiPut(alicePage, ALICE_ID, "/ui/delegates/settings", {
      require_acceptance: true,
      max_delegates: 10,
      delegate_tag_enabled: true,
      delegate_tag_format: "[via @{delegate_name}]",
    });

    // Cleanup
    await cleanupDelegates(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await cleanupDelegates(alicePage, ALICE_ID);
    await alicePage.context().close();
    await bobPage.context().close();
    await charliePage.context().close();
  });

  test("488.1 Bob receives pending delegation invite", async () => {
    // Alice adds Bob
    const addResp = await apiPost(alicePage, ALICE_ID, "/ui/delegates", {
      delegate_id: BOB_ID,
      permissions: ["chat_read", "chat_respond"],
      preset: "chat_agent",
    });
    expect(addResp.ok()).toBeTruthy();

    // Bob lists invites
    const resp = await apiGet(bobPage, "/ui/delegates/invites");
    expect(resp.ok()).toBeTruthy();
    const invites = await resp.json();
    const aliceInvite = invites.find((i: any) => i.creator_id === ALICE_ID);
    expect(aliceInvite).toBeTruthy();
    expect(aliceInvite.status).toBe("pending");
  });

  test("488.2 Bob accepts delegation invite", async () => {
    const resp = await apiPost(bobPage, BOB_ID, `/ui/delegates/invites/${ALICE_ID}/respond`, {
      accept: true,
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.status).toBe("active");
  });

  test("488.3 Bob appears in Alice's active delegates", async () => {
    const resp = await apiGet(alicePage, "/ui/delegates");
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    const bob = data.find((d: any) => d.delegate_id === BOB_ID);
    expect(bob).toBeTruthy();
    expect(bob.status).toBe("active");
  });

  test("488.4 Charlie declines delegation invite", async () => {
    // Alice adds Charlie
    const addResp = await apiPost(alicePage, ALICE_ID, "/ui/delegates", {
      delegate_id: CHARLIE_ID,
      permissions: ["feed_read"],
    });
    expect(addResp.ok()).toBeTruthy();

    // Charlie declines
    const resp = await apiPost(charliePage, CHARLIE_ID, `/ui/delegates/invites/${ALICE_ID}/respond`, {
      accept: false,
    });
    expect(resp.ok()).toBeTruthy();

    // Charlie's invites should be empty
    const invResp = await apiGet(charliePage, "/ui/delegates/invites");
    const invites = await invResp.json();
    const aliceInvite = invites.find((i: any) => i.creator_id === ALICE_ID);
    expect(aliceInvite).toBeFalsy();

    // Alice's delegate list should not have Charlie
    const listResp = await apiGet(alicePage, "/ui/delegates");
    const delegates = await listResp.json();
    const charlie = delegates.find((d: any) => d.delegate_id === CHARLIE_ID);
    expect(charlie).toBeFalsy();
  });
});

// ─── Section 489: Permission Presets & Settings API ──────────────────────────

test.describe("489 — Permission Presets & Settings API", () => {
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    // Reset settings
    await apiPut(alicePage, ALICE_ID, "/ui/delegates/settings", {
      require_acceptance: true,
      max_delegates: 10,
      delegate_tag_enabled: true,
      delegate_tag_format: "[via @{delegate_name}]",
    });

    // Cleanup
    await cleanupDelegates(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    // Reset settings
    await apiPut(alicePage, ALICE_ID, "/ui/delegates/settings", {
      require_acceptance: true,
      max_delegates: 10,
      delegate_tag_enabled: true,
      delegate_tag_format: "[via @{delegate_name}]",
    });
    await cleanupDelegates(alicePage, ALICE_ID);
    await alicePage.context().close();
    await bobPage.context().close();
  });

  test("489.1 List available presets", async () => {
    const resp = await apiGet(alicePage, "/ui/delegates/presets");
    expect(resp.ok()).toBeTruthy();
    const presets = await resp.json();
    expect(presets.length).toBe(6);
    const keys = presets.map((p: any) => p.key);
    expect(keys).toContain("full_manager");
    expect(keys).toContain("chat_agent");
    expect(keys).toContain("content_manager");
    expect(keys).toContain("broadcast_moderator");
    expect(keys).toContain("broadcast_manager");
    expect(keys).toContain("read_only");
  });

  test("489.2 Update creator delegation settings", async () => {
    const putResp = await apiPut(alicePage, ALICE_ID, "/ui/delegates/settings", {
      require_acceptance: false,
      max_delegates: 5,
      delegate_tag_enabled: true,
      delegate_tag_format: "[via @{delegate_name}]",
    });
    expect(putResp.ok()).toBeTruthy();

    const getResp = await apiGet(alicePage, "/ui/delegates/settings");
    const settings = await getResp.json();
    expect(settings.require_acceptance).toBe(false);
    expect(settings.max_delegates).toBe(5);
  });

  test("489.3 Delegate limit enforced", async () => {
    // Set max_delegates=1
    await apiPut(alicePage, ALICE_ID, "/ui/delegates/settings", {
      require_acceptance: false,
      max_delegates: 1,
      delegate_tag_enabled: true,
      delegate_tag_format: "[via @{delegate_name}]",
    });

    // Add first delegate
    const resp1 = await apiPost(alicePage, ALICE_ID, "/ui/delegates", {
      delegate_id: BOB_ID,
      permissions: ["chat_read"],
    });
    expect(resp1.ok()).toBeTruthy();

    // Try to add second — should fail
    const resp2 = await apiPost(alicePage, ALICE_ID, "/ui/delegates", {
      delegate_id: CHARLIE_ID,
      permissions: ["chat_read"],
    });
    expect(resp2.status()).toBe(400);

    // Cleanup
    await apiDelete(alicePage, ALICE_ID, `/ui/delegates/${BOB_ID}`);
  });

  test("489.4 Managed creators list shows Alice", async () => {
    // Set require_acceptance=false for instant activation
    await apiPut(alicePage, ALICE_ID, "/ui/delegates/settings", {
      require_acceptance: false,
      max_delegates: 10,
      delegate_tag_enabled: true,
      delegate_tag_format: "[via @{delegate_name}]",
    });

    // Add Bob as delegate
    const addResp = await apiPost(alicePage, ALICE_ID, "/ui/delegates", {
      delegate_id: BOB_ID,
      permissions: ["chat_read", "chat_respond"],
    });
    expect(addResp.ok()).toBeTruthy();

    // Bob checks managed creators
    const resp = await apiGet(bobPage, "/ui/delegates/managed");
    expect(resp.ok()).toBeTruthy();
    const managed = await resp.json();
    const alice = managed.find((c: any) => c.creator_id === ALICE_ID);
    expect(alice).toBeTruthy();
    expect(alice.permissions).toContain("chat_read");

    // Cleanup
    await apiDelete(alicePage, ALICE_ID, `/ui/delegates/${BOB_ID}`);
  });
});

// ─── Section 490: Audit Log API ──────────────────────────────────────────────

test.describe("490 — Audit Log API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Reset settings
    await apiPut(alicePage, ALICE_ID, "/ui/delegates/settings", {
      require_acceptance: false,
      max_delegates: 10,
      delegate_tag_enabled: true,
      delegate_tag_format: "[via @{delegate_name}]",
    });

    // Cleanup
    await cleanupDelegates(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await cleanupDelegates(alicePage, ALICE_ID);
    await alicePage.context().close();
  });

  test("490.1 Audit log records delegate_invited event", async () => {
    // Add Bob as delegate
    const addResp = await apiPost(alicePage, ALICE_ID, "/ui/delegates", {
      delegate_id: BOB_ID,
      permissions: ["chat_read"],
    });
    expect(addResp.ok()).toBeTruthy();

    const auditResp = await apiGet(alicePage, "/ui/delegates/audit");
    expect(auditResp.ok()).toBeTruthy();
    const audit = await auditResp.json();
    const invited = audit.find(
      (e: any) => e.action === "delegate_invited" && e.target_id === BOB_ID,
    );
    expect(invited).toBeTruthy();
  });

  test("490.2 Audit log records permission update", async () => {
    const resp = await apiPut(alicePage, ALICE_ID, `/ui/delegates/${BOB_ID}/permissions`, {
      permissions: ["chat_read", "chat_respond", "feed_read"],
    });
    expect(resp.ok()).toBeTruthy();

    const auditResp = await apiGet(alicePage, "/ui/delegates/audit");
    const audit = await auditResp.json();
    const updated = audit.find(
      (e: any) => e.action === "permissions_updated" && e.target_id === BOB_ID,
    );
    expect(updated).toBeTruthy();
    expect(updated.details.new_permissions).toContain("feed_read");
  });

  test("490.3 Audit log records delegate_revoked event", async () => {
    const resp = await apiDelete(alicePage, ALICE_ID, `/ui/delegates/${BOB_ID}`);
    expect(resp.ok()).toBeTruthy();

    const auditResp = await apiGet(alicePage, "/ui/delegates/audit");
    const audit = await auditResp.json();
    const revoked = audit.find(
      (e: any) => e.action === "delegate_revoked" && e.target_id === BOB_ID,
    );
    expect(revoked).toBeTruthy();
  });
});

// ─── Section 491: /delegates route (GAP-0156) ────────────────────────────────
//
// Regression for GAP-0156: DelegatesPage existed on disk but had no <Route> in
// App.tsx, so navigating to /delegates fell through to the catch-all 404.
// These tests fail before the route addition and pass after.

test.describe("491 — /delegates route (GAP-0156)", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.context().close();
  });

  test("491.1 /delegates renders DelegatesPage (not a 404 fallback)", async () => {
    await alicePage.goto(`${BASE}/delegates`, { waitUntil: "domcontentloaded" });

    // Positive: DelegatesPage renders its <h1>Delegates</h1> heading.
    await expect(
      alicePage.getByRole("heading", { name: "Delegates", exact: true }),
    ).toBeVisible({ timeout: 8000 });

    // Negative: the not-found state must NOT be visible.
    await expect(alicePage.getByText(/not found/i)).not.toBeVisible();
  });

  test("491.2 DelegatesPage lazy chunk loads without error", async () => {
    const chunkErrors: string[] = [];
    alicePage.on("pageerror", (err) => {
      if (/loading chunk/i.test(err.message)) chunkErrors.push(err.message);
    });

    await alicePage.goto(`${BASE}/delegates`, { waitUntil: "domcontentloaded" });
    await expect(
      alicePage.getByRole("heading", { name: "Delegates", exact: true }),
    ).toBeVisible({ timeout: 8000 });

    expect(chunkErrors).toHaveLength(0);
  });
});
