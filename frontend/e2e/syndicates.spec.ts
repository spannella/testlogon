/**
 * E2E tests for Syndicate Creation & Membership Management (SYND-001)
 *
 * Section 423: Syndicate Creation API (4 tests)
 * Section 424: Invite & Join Request API (5 tests)
 * Section 425: Admin Transfer & Member Removal API (4 tests)
 * Section 426: Leave & Auto-Dissolution API (5 tests)
 *
 * Auth: Uses admin session cookies (role-bearing JWT) via e2e_admin_session_setup.py.
 * All POST requests include x-csrf-token header.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ─────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";
const CHARLIE_ID = "e2e_charlie@test.local";

const TS = Date.now();

// ─── Session bootstrap ─────────────────────────────────────────────────────────

interface SessionData {
  user_sub:     string;
  session_id:   string;
  csrf_token:   string;
  access_token: string;
  cookies: Array<{
    name:     string;
    value:    string;
    domain:   string;
    path:     string;
    httpOnly: boolean;
    secure:   boolean;
    sameSite: "Lax" | "Strict" | "None";
    expires:  number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

// ─── Identity page factory ─────────────────────────────────────────────────────

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const sess = sessions[identity];
  if (!sess) throw new Error(`No session for identity "${identity}"`);
  const page = await browser.newPage();
  await page.context().addCookies(sess.cookies);
  return page;
}

// ─── Request helpers ───────────────────────────────────────────────────────────

async function apiPost(page: Page, identity: string, path: string, body: object = {}) {
  const sessions = getSessions();
  return page.request.post(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": sessions[identity].csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

// ─── Shared state ──────────────────────────────────────────────────────────────

let alicePage: Page;
let bobPage: Page;
let charliePage: Page;

// Syndicate IDs created during tests
let syndicateId: string;
let dissolveSyndicateId: string;
let autoPromoteSyndicateId: string;

// ─── Section 423: Syndicate Creation API ───────────────────────────────────────

test.describe("423 — Syndicate Creation API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    bobPage = await newIdentityPage(browser, "bob");
    charliePage = await newIdentityPage(browser, "charlie_admin");
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
    await charliePage?.close();
  });

  test("423.1 Alice creates a syndicate", async () => {
    const resp = await apiPost(alicePage, "alice", "/ui/syndicates", {
      name: `Test Syndicate ${TS}`,
      description: "A test syndicate for E2E",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.syndicate_id).toBeTruthy();
    expect(data.admin_user_id).toBe(ALICE_ID);
    expect(data.member_count).toBe(1);
    expect(data.status).toBe("active");
    syndicateId = data.syndicate_id;
  });

  test("423.2 Syndicate appears in user's list", async () => {
    const resp = await apiGet(alicePage, "/ui/syndicates");
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    const found = data.find((s: any) => s.syndicate_id === syndicateId);
    expect(found).toBeTruthy();
    expect(found.role).toBe("admin");
  });

  test("423.3 Syndicate detail includes creator as admin member", async () => {
    const resp = await apiGet(alicePage, `/ui/syndicates/${syndicateId}`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.members.length).toBe(1);
    expect(data.members[0].role).toBe("admin");
    expect(data.members[0].user_id).toBe(ALICE_ID);
  });

  test("423.4 Name validation rejects empty name", async () => {
    const resp = await apiPost(alicePage, "alice", "/ui/syndicates", {
      name: "",
    });
    expect(resp.status()).toBe(422);
  });
});

// ─── Section 424: Invite & Join Request API ────────────────────────────────────

test.describe("424 — Invite & Join Request API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    bobPage = await newIdentityPage(browser, "bob");
    charliePage = await newIdentityPage(browser, "charlie_admin");
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
    await charliePage?.close();
  });

  test("424.1 Admin invites Bob to syndicate", async () => {
    const resp = await apiPost(alicePage, "alice", `/ui/syndicates/${syndicateId}/invite`, {
      user_id: BOB_ID,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.status).toBe("pending");
    expect(data.user_id).toBe(BOB_ID);
  });

  test("424.2 Bob sees pending invite", async () => {
    const resp = await apiGet(bobPage, "/ui/syndicates/invites");
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    const found = data.find((i: any) => i.syndicate_id === syndicateId);
    expect(found).toBeTruthy();
    expect(found.status).toBe("pending");
  });

  test("424.3 Bob accepts invite and becomes member", async () => {
    const resp = await apiPost(bobPage, "bob", `/ui/syndicates/${syndicateId}/invite/respond`, {
      accept: true,
    });
    expect(resp.ok()).toBe(true);

    // Verify Bob is in members
    const membersResp = await apiGet(alicePage, `/ui/syndicates/${syndicateId}/members`);
    const members = await membersResp.json();
    const bob = members.find((m: any) => m.user_id === BOB_ID);
    expect(bob).toBeTruthy();
    expect(bob.role).toBe("member");

    // Verify member_count is 2
    const detailResp = await apiGet(alicePage, `/ui/syndicates/${syndicateId}`);
    const detail = await detailResp.json();
    expect(detail.member_count).toBe(2);
  });

  test("424.4 Charlie requests to join", async () => {
    const resp = await apiPost(charliePage, "charlie_admin", `/ui/syndicates/${syndicateId}/request`, {
      message: "I want to join!",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.status).toBe("pending");
  });

  test("424.5 Admin approves Charlie's request", async () => {
    const resp = await apiPost(alicePage, "alice", `/ui/syndicates/${syndicateId}/request/${CHARLIE_ID}/approve`);
    expect(resp.ok()).toBe(true);

    // Verify Charlie is in members
    const membersResp = await apiGet(alicePage, `/ui/syndicates/${syndicateId}/members`);
    const members = await membersResp.json();
    const charlie = members.find((m: any) => m.user_id === CHARLIE_ID);
    expect(charlie).toBeTruthy();

    // Verify member_count is 3
    const detailResp = await apiGet(alicePage, `/ui/syndicates/${syndicateId}`);
    const detail = await detailResp.json();
    expect(detail.member_count).toBe(3);
  });
});

// ─── Section 425: Admin Transfer & Member Removal API ──────────────────────────

test.describe("425 — Admin Transfer & Member Removal API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    bobPage = await newIdentityPage(browser, "bob");
    charliePage = await newIdentityPage(browser, "charlie_admin");
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
    await charliePage?.close();
  });

  test("425.1 Admin transfers role to Bob", async () => {
    const resp = await apiPost(alicePage, "alice", `/ui/syndicates/${syndicateId}/transfer-admin`, {
      new_admin_user_id: BOB_ID,
    });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.admin_user_id).toBe(BOB_ID);
  });

  test("425.2 Old admin (Alice) is now regular member", async () => {
    const membersResp = await apiGet(bobPage, `/ui/syndicates/${syndicateId}/members`);
    const members = await membersResp.json();
    const alice = members.find((m: any) => m.user_id === ALICE_ID);
    expect(alice).toBeTruthy();
    expect(alice.role).toBe("member");
  });

  test("425.3 New admin (Bob) removes Charlie", async () => {
    const resp = await apiPost(bobPage, "bob", `/ui/syndicates/${syndicateId}/remove/${CHARLIE_ID}`);
    expect(resp.ok()).toBe(true);

    // Verify Charlie is gone
    const membersResp = await apiGet(bobPage, `/ui/syndicates/${syndicateId}/members`);
    const members = await membersResp.json();
    const charlie = members.find((m: any) => m.user_id === CHARLIE_ID);
    expect(charlie).toBeFalsy();

    // Verify member_count is 2
    const detailResp = await apiGet(bobPage, `/ui/syndicates/${syndicateId}`);
    const detail = await detailResp.json();
    expect(detail.member_count).toBe(2);
  });

  test("425.4 Non-admin cannot remove members", async () => {
    // Alice is now a regular member, so she should get 403
    const resp = await apiPost(alicePage, "alice", `/ui/syndicates/${syndicateId}/remove/${BOB_ID}`);
    expect(resp.status()).toBe(403);
  });
});

// ─── Section 426: Leave & Auto-Dissolution API ────────────────────────────────

test.describe("426 — Leave & Auto-Dissolution API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    bobPage = await newIdentityPage(browser, "bob");
    charliePage = await newIdentityPage(browser, "charlie_admin");
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
    await charliePage?.close();
  });

  test("426.1 Alice leaves syndicate", async () => {
    // Alice is a member of the main syndicate (Bob is admin)
    const resp = await apiPost(alicePage, "alice", `/ui/syndicates/${syndicateId}/leave`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.dissolved).toBe(false);

    // Verify Alice is no longer in members
    const membersResp = await apiGet(bobPage, `/ui/syndicates/${syndicateId}/members`);
    const members = await membersResp.json();
    const alice = members.find((m: any) => m.user_id === ALICE_ID);
    expect(alice).toBeFalsy();
  });

  test("426.2 Admin leaves, next oldest member promoted", async () => {
    // Create a fresh syndicate with Alice, add Bob and Charlie
    const createResp = await apiPost(alicePage, "alice", "/ui/syndicates", {
      name: `Auto-Promote Test ${TS}`,
      description: "Test auto-promotion",
    });
    const created = await createResp.json();
    autoPromoteSyndicateId = created.syndicate_id;

    // Invite Bob
    await apiPost(alicePage, "alice", `/ui/syndicates/${autoPromoteSyndicateId}/invite`, {
      user_id: BOB_ID,
    });
    await apiPost(bobPage, "bob", `/ui/syndicates/${autoPromoteSyndicateId}/invite/respond`, {
      accept: true,
    });

    // Invite Charlie
    await apiPost(alicePage, "alice", `/ui/syndicates/${autoPromoteSyndicateId}/invite`, {
      user_id: CHARLIE_ID,
    });
    await apiPost(charliePage, "charlie_admin", `/ui/syndicates/${autoPromoteSyndicateId}/invite/respond`, {
      accept: true,
    });

    // Alice (admin) leaves
    const leaveResp = await apiPost(alicePage, "alice", `/ui/syndicates/${autoPromoteSyndicateId}/leave`);
    expect(leaveResp.ok()).toBe(true);
    const leaveData = await leaveResp.json();
    expect(leaveData.dissolved).toBe(false);

    // Verify Bob (next oldest) is now admin
    const detailResp = await apiGet(bobPage, `/ui/syndicates/${autoPromoteSyndicateId}`);
    const detail = await detailResp.json();
    expect(detail.admin_user_id).toBe(BOB_ID);
  });

  test("426.3 Reject request returns proper status", async () => {
    // Create a syndicate, have Charlie request, then reject
    const createResp = await apiPost(alicePage, "alice", "/ui/syndicates", {
      name: `Reject Test ${TS}`,
    });
    const created = await createResp.json();
    const sid = created.syndicate_id;

    // Charlie requests
    await apiPost(charliePage, "charlie_admin", `/ui/syndicates/${sid}/request`, {
      message: "Please add me",
    });

    // Alice rejects
    const rejectResp = await apiPost(alicePage, "alice", `/ui/syndicates/${sid}/request/${CHARLIE_ID}/reject`);
    expect(rejectResp.ok()).toBe(true);

    // Verify requests list is empty now
    const reqResp = await apiGet(alicePage, `/ui/syndicates/${sid}/requests`);
    const requests = await reqResp.json();
    expect(requests.length).toBe(0);

    // Clean up: Alice leaves (dissolves)
    await apiPost(alicePage, "alice", `/ui/syndicates/${sid}/leave`);
  });

  test("426.4 Last member leaves, syndicate dissolved", async () => {
    // Create a syndicate, then admin leaves immediately
    const createResp = await apiPost(alicePage, "alice", "/ui/syndicates", {
      name: `Dissolve Test ${TS}`,
    });
    const created = await createResp.json();
    dissolveSyndicateId = created.syndicate_id;

    const leaveResp = await apiPost(alicePage, "alice", `/ui/syndicates/${dissolveSyndicateId}/leave`);
    expect(leaveResp.ok()).toBe(true);
    const data = await leaveResp.json();
    expect(data.dissolved).toBe(true);

    // Verify syndicate is archived
    const detailResp = await apiGet(alicePage, `/ui/syndicates/${dissolveSyndicateId}`);
    const detail = await detailResp.json();
    expect(detail.status).toBe("archived");
  });

  test("426.5 Audit log records all membership events", async () => {
    // Check audit log on the main syndicate (Bob is admin)
    const resp = await apiGet(bobPage, `/ui/syndicates/${syndicateId}/audit`);
    expect(resp.ok()).toBe(true);
    const auditEntries = await resp.json();
    expect(auditEntries.length).toBeGreaterThan(0);

    const actions = auditEntries.map((e: any) => e.action);
    // Should have at least: syndicate_created, invite_sent, member_joined
    expect(actions).toContain("syndicate_created");
    expect(actions).toContain("invite_sent");
    expect(actions).toContain("member_joined");
  });
});
