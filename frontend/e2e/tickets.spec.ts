/**
 * E2E tests for the Ticket Management system.
 *
 * Sections:
 *   52 — Ticket CRUD (create / list / get) — API
 *   53 — Admin ticket operations — API
 *   54 — Ticket messaging + auto-reopen — API
 *   55 — Ticket Spaces CRUD + members — API
 *   56 — Space ticket lifecycle — API
 *   57 — TicketsPage UI
 *
 * Auth: uses e2e_admin_session_setup.py (all identities)
 *
 * Identities:
 *   root          – root.admin@testdev.local  – role=root (admin API + assignee target)
 *   alice         – e2e_alice@test.local      – role=user (space owner for sec 55–56)
 *   bob           – e2e_bob@test.local        – role=user (customer / space editor)
 *   charlie_admin – e2e_charlie@test.local    – role=admin (non-member access control)
 *
 * Key: _is_assignable_admin() checks the DB. Only root is admin/root in DB.
 * Charlie has role=user in DB (set by ensure_auth_user in setup script).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE       = "http://localhost:3000";
const ROOT_SUB   = "root.admin@testdev.local";
const BOB_ID     = "e2e_bob@test.local";
const ALICE_ID   = "e2e_alice@test.local";
const CHARLIE_ID = "e2e_charlie@test.local";
const TS         = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface AdminSessionData {
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

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    _adminSessions = loadSessions();
  }
  return _adminSessions!;
}

// ─── Page factory ─────────────────────────────────────────────────────────────

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

// ─── Auth inject for UI tests ─────────────────────────────────────────────────

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

// ─── API helpers ──────────────────────────────────────────────────────────────

/** Authenticated POST using a pre-cookie'd page + CSRF token. */
async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

/** Authenticated GET using a pre-cookie'd page (CSRF not required for GET). */
async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

/** Authenticated DELETE using a pre-cookie'd page + CSRF token. */
async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getAdminSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

// ─── Module-level shared state (sections 55 → 56) ────────────────────────────

let sec55SpaceId   = "";
let sec55AlicePage: Page | undefined;
let sec55BobPage:  Page | undefined;

// ─────────────────────────────────────────────────────────────────────────────
// Section 52 — Ticket CRUD (create / list / get) — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 52: Ticket CRUD — create / list / get (API)", () => {
  let bobPage:   Page;
  let alicePage: Page;
  let rootPage:  Page;
  let ticketId:  string;
  const SUBJECT = `E2E ticket ${TS}`;
  const DESC    = `Test desc ${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getAdminSessions(); // warm up / ensure DDB records exist
    bobPage   = await newIdentityPage(browser, "bob");
    alicePage = await newIdentityPage(browser, "alice");
    rootPage  = await newIdentityPage(browser, "root");
    const resp = await apiPost(bobPage, "bob", "tickets", { subject: SUBJECT, description: DESC });
    if (!resp.ok()) throw new Error(`create ticket failed: ${await resp.text()}`);
    const data = await resp.json() as { ticket: { ticket_id: string } };
    ticketId = data.ticket.ticket_id;
  });

  test("52.1 Create ticket → 200, status open, has ticket_id", async () => {
    expect(ticketId).toBeTruthy();
    const resp = await apiGet(bobPage, `tickets/${ticketId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { ticket: Record<string, unknown> };
    expect(data.ticket.status).toBe("open");
    expect(typeof data.ticket.ticket_id).toBe("string");
    expect(Array.isArray(data.ticket.messages)).toBe(true);
  });

  test("52.2 Response shape — owner_sub, version, created_at, updated_at", async () => {
    const resp = await apiGet(bobPage, `tickets/${ticketId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { ticket: Record<string, unknown> };
    expect(data.ticket.owner_sub).toBe(BOB_ID);
    expect(typeof data.ticket.version).toBe("number");
    expect(typeof data.ticket.created_at).toBe("number");
    expect(typeof data.ticket.updated_at).toBe("number");
  });

  test("52.3 Bob lists own tickets — includes new ticket", async () => {
    const resp = await apiGet(bobPage, "tickets");
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { items: Array<{ ticket_id: string }> };
    expect(Array.isArray(data.items)).toBe(true);
    const found = data.items.find((t) => t.ticket_id === ticketId);
    expect(found).toBeTruthy();
  });

  test("52.4 Status filter (admin) — open includes ticket, done does not", async () => {
    // Admin filter by status works via the status GSI
    const openResp = await apiGet(rootPage, "tickets", { status: "open" });
    expect(openResp.status()).toBe(200);
    const openData = await openResp.json() as { items: Array<{ ticket_id: string }> };
    expect(openData.items.find((t) => t.ticket_id === ticketId)).toBeTruthy();

    const doneResp = await apiGet(rootPage, "tickets", { status: "done" });
    expect(doneResp.status()).toBe(200);
    const doneData = await doneResp.json() as { items: Array<{ ticket_id: string }> };
    expect(doneData.items.find((t) => t.ticket_id === ticketId)).toBeFalsy();
  });

  test("52.5 Get ticket by ID → 200, ticket_id matches", async () => {
    const resp = await apiGet(bobPage, `tickets/${ticketId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { ticket: { ticket_id: string } };
    expect(data.ticket.ticket_id).toBe(ticketId);
  });

  test("52.6 Non-owner GET → 403", async () => {
    const resp = await apiGet(alicePage, `tickets/${ticketId}`);
    expect(resp.status()).toBe(403);
  });

  test("52.7 Subject too short → 422 validation error", async () => {
    const resp = await apiPost(bobPage, "bob", "tickets", { subject: "ab", description: "valid" });
    expect(resp.status()).toBe(422);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 53 — Admin ticket operations (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 53: Admin ticket operations (API)", () => {
  let rootPage: Page;
  let bobPage:  Page;
  let ticketId: string;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    bobPage  = await newIdentityPage(browser, "bob");
    const resp = await apiPost(bobPage, "bob", "tickets", {
      subject:     `Admin ops ticket ${TS}`,
      description: "admin ops test",
    });
    if (!resp.ok()) throw new Error(`create ticket failed: ${await resp.text()}`);
    const data = await resp.json() as { ticket: { ticket_id: string } };
    ticketId = data.ticket.ticket_id;
  });

  test("53.1 Admin summary → 200 with by_status, unassigned_count, total_count", async () => {
    const resp = await apiGet(rootPage, "tickets/admin/summary");
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { summary: Record<string, unknown> };
    expect(data.summary.by_status).toBeDefined();
    expect(typeof data.summary.unassigned_count).toBe("number");
    expect(typeof data.summary.total_count).toBe("number");
  });

  test("53.2 Non-admin summary → 403", async () => {
    const resp = await apiGet(bobPage, "tickets/admin/summary");
    expect(resp.status()).toBe(403);
  });

  test("53.3 Admin lists all open tickets — includes Bob's ticket", async () => {
    const resp = await apiGet(rootPage, "tickets", { status: "open" });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { items: Array<{ ticket_id: string }> };
    expect(data.items.find((t) => t.ticket_id === ticketId)).toBeTruthy();
  });

  test("53.4 Admin filter by owner_sub — includes Bob's ticket", async () => {
    const resp = await apiGet(rootPage, "tickets", { owner_sub: BOB_ID });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { items: Array<{ ticket_id: string }> };
    expect(data.items.find((t) => t.ticket_id === ticketId)).toBeTruthy();
  });

  test("53.5 Admin assigns ticket to root → 200, assigned_admin_sub set", async () => {
    const resp = await apiPost(rootPage, "root", `tickets/${ticketId}/assign`, {
      assignee_admin_sub: ROOT_SUB,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { ticket: Record<string, unknown> };
    expect(data.ticket.assigned_admin_sub).toBe(ROOT_SUB);
  });

  test("53.6 Non-admin cannot assign → 403", async () => {
    const resp = await apiPost(bobPage, "bob", `tickets/${ticketId}/assign`, {
      assignee_admin_sub: ROOT_SUB,
    });
    expect(resp.status()).toBe(403);
  });

  test("53.7 Admin sets status to done → 200, status=done", async () => {
    const resp = await apiPost(rootPage, "root", `tickets/${ticketId}/status`, { status: "done" });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { ticket: { status: string } };
    expect(data.ticket.status).toBe("done");
  });

  test("53.8 Non-admin cannot set status → 403", async () => {
    const resp = await apiPost(bobPage, "bob", `tickets/${ticketId}/status`, { status: "open" });
    expect(resp.status()).toBe(403);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 54 — Ticket messaging + auto-reopen (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 54: Ticket messaging + auto-reopen (API)", () => {
  let rootPage:  Page;
  let bobPage:   Page;
  let alicePage: Page;
  let ticketId:  string;
  const BOB_REPLY   = `Bob reply ${TS}`;
  const ADMIN_REPLY = `Admin reply ${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage  = await newIdentityPage(browser, "root");
    bobPage   = await newIdentityPage(browser, "bob");
    alicePage = await newIdentityPage(browser, "alice");
    // Bob creates fresh ticket
    const resp = await apiPost(bobPage, "bob", "tickets", {
      subject:     `Messaging ticket ${TS}`,
      description: "messaging test",
    });
    if (!resp.ok()) throw new Error(`create ticket failed: ${await resp.text()}`);
    const data = await resp.json() as { ticket: { ticket_id: string } };
    ticketId = data.ticket.ticket_id;
    // Root assigns it (enables admin reply path)
    const assignResp = await apiPost(rootPage, "root", `tickets/${ticketId}/assign`, {
      assignee_admin_sub: ROOT_SUB,
    });
    if (!assignResp.ok()) throw new Error(`assign failed: ${await assignResp.text()}`);
  });

  test("54.1 User replies → 200, message appears in messages[]", async () => {
    const resp = await apiPost(bobPage, "bob", `tickets/${ticketId}/messages`, { body: BOB_REPLY });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { ticket: { messages: Array<{ body: string }> } };
    expect(Array.isArray(data.ticket.messages)).toBe(true);
    expect(data.ticket.messages.find((m) => m.body === BOB_REPLY)).toBeTruthy();
  });

  test("54.2 Reply body and sender_role=user confirmed via GET", async () => {
    const resp = await apiGet(bobPage, `tickets/${ticketId}`);
    expect(resp.status()).toBe(200);
    type Msg = { body: string; sender_role: string };
    const data = await resp.json() as { ticket: { messages: Msg[] } };
    const msg = data.ticket.messages.find((m) => m.body === BOB_REPLY);
    expect(msg).toBeTruthy();
    expect(msg!.sender_role).toBe("user");
  });

  test("54.3 Admin reply has sender_role=admin", async () => {
    const resp = await apiPost(rootPage, "root", `tickets/${ticketId}/messages`, { body: ADMIN_REPLY });
    expect(resp.status()).toBe(200);
    type Msg = { body: string; sender_role: string };
    const data = await resp.json() as { ticket: { messages: Msg[] } };
    const msg = data.ticket.messages.find((m) => m.body === ADMIN_REPLY);
    expect(msg).toBeTruthy();
    expect(msg!.sender_role).toBe("admin");
  });

  test("54.4 Empty body → 422 validation error", async () => {
    const resp = await apiPost(bobPage, "bob", `tickets/${ticketId}/messages`, { body: "" });
    expect(resp.status()).toBe(422);
  });

  test("54.5 Non-owner reply → 403", async () => {
    const resp = await apiPost(alicePage, "alice", `tickets/${ticketId}/messages`, {
      body: "Alice sneaks in",
    });
    expect(resp.status()).toBe(403);
  });

  test("54.6 Reply to done ticket auto-reopens it to open", async () => {
    // Current status after 54.3: waiting_on_user (admin replied)
    // waiting_on_user → done is an allowed transition
    const doneResp = await apiPost(rootPage, "root", `tickets/${ticketId}/status`, { status: "done" });
    expect(doneResp.status()).toBe(200);
    const doneData = await doneResp.json() as { ticket: { status: string } };
    expect(doneData.ticket.status).toBe("done");

    // Bob replies to done ticket → auto-reopens (user reply on done ticket → "open")
    const replyResp = await apiPost(bobPage, "bob", `tickets/${ticketId}/messages`, {
      body: `Reopen reply ${TS}`,
    });
    expect(replyResp.status()).toBe(200);
    const replyData = await replyResp.json() as { ticket: { status: string } };
    expect(replyData.ticket.status).toBe("open");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 55 — Ticket Spaces CRUD + members (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 55: Ticket Spaces CRUD + members (API)", () => {
  let alicePage:   Page;
  let bobPage:     Page;
  let charliePage: Page;
  const SPACE_NAME = `E2E Space ${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage   = await newIdentityPage(browser, "alice");
    bobPage     = await newIdentityPage(browser, "bob");
    charliePage = await newIdentityPage(browser, "charlie_admin");

    // Alice creates the space
    const resp = await apiPost(alicePage, "alice", "ticket-spaces", {
      name:       SPACE_NAME,
      visibility: "private",
    });
    if (!resp.ok()) throw new Error(`create space failed: ${await resp.text()}`);
    const data = await resp.json() as { space: { space_id: string } };
    sec55SpaceId   = data.space.space_id;
    sec55AlicePage = alicePage;
    sec55BobPage   = bobPage;

    // Add Bob as editor
    const bobResp = await apiPost(alicePage, "alice", `ticket-spaces/${sec55SpaceId}/members`, {
      member_sub: BOB_ID,
      role:       "editor",
    });
    if (!bobResp.ok()) throw new Error(`add Bob failed: ${await bobResp.text()}`);

    // Add root as viewer (will be removed in 55.9)
    const rootResp = await apiPost(alicePage, "alice", `ticket-spaces/${sec55SpaceId}/members`, {
      member_sub: ROOT_SUB,
      role:       "viewer",
    });
    if (!rootResp.ok()) throw new Error(`add root failed: ${await rootResp.text()}`);

    void charliePage; // suppress unused warning until 55.7
  });

  test("55.1 Create space → 200, owner_sub=alice, visibility=private", async () => {
    const resp = await apiGet(alicePage, `ticket-spaces/${sec55SpaceId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { space: Record<string, unknown> };
    expect(data.space.owner_sub).toBe(ALICE_ID);
    expect(data.space.visibility).toBe("private");
  });

  test("55.2 Owner listed as member with role=owner", async () => {
    const resp = await apiGet(alicePage, `ticket-spaces/${sec55SpaceId}`);
    type Member = { member_sub: string; role: string };
    const data = await resp.json() as { space: { members: Member[] } };
    const alice = data.space.members.find((m) => m.member_sub === ALICE_ID);
    expect(alice).toBeTruthy();
    expect(alice!.role).toBe("owner");
  });

  test("55.3 List spaces for Alice → includes new space", async () => {
    const resp = await apiGet(alicePage, "ticket-spaces");
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { items: Array<{ space_id: string }> };
    expect(data.items.find((s) => s.space_id === sec55SpaceId)).toBeTruthy();
  });

  test("55.4 Get space by ID → 200, space_id matches", async () => {
    const resp = await apiGet(alicePage, `ticket-spaces/${sec55SpaceId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { space: { space_id: string } };
    expect(data.space.space_id).toBe(sec55SpaceId);
  });

  test("55.5 Bob added as editor — members include Bob with role=editor", async () => {
    const resp = await apiGet(alicePage, `ticket-spaces/${sec55SpaceId}`);
    type Member = { member_sub: string; role: string };
    const data = await resp.json() as { space: { members: Member[] } };
    const bob = data.space.members.find((m) => m.member_sub === BOB_ID);
    expect(bob).toBeTruthy();
    expect(bob!.role).toBe("editor");
  });

  test("55.6 Root added as viewer — members include root with role=viewer", async () => {
    const resp = await apiGet(alicePage, `ticket-spaces/${sec55SpaceId}`);
    type Member = { member_sub: string; role: string };
    const data = await resp.json() as { space: { members: Member[] } };
    const root = data.space.members.find((m) => m.member_sub === ROOT_SUB);
    expect(root).toBeTruthy();
    expect(root!.role).toBe("viewer");
  });

  test("55.7 Non-member access → 403", async () => {
    // Charlie is not a member of this space
    const resp = await apiGet(charliePage, `ticket-spaces/${sec55SpaceId}`);
    expect(resp.status()).toBe(403);
  });

  test("55.8 Cannot remove space owner → 400 with cannot_remove_space_owner", async () => {
    const resp = await apiDelete(
      alicePage, "alice",
      `ticket-spaces/${sec55SpaceId}/members/${ALICE_ID}`,
    );
    expect(resp.status()).toBe(400);
    const data = await resp.json() as { detail: { error: { code: string } } };
    expect(data.detail.error.code).toBe("cannot_remove_space_owner");
  });

  test("55.9 Owner removes root (viewer) → 200, root no longer in members", async () => {
    const resp = await apiDelete(
      alicePage, "alice",
      `ticket-spaces/${sec55SpaceId}/members/${ROOT_SUB}`,
    );
    expect(resp.status()).toBe(200);
    type Member = { member_sub: string };
    const data = await resp.json() as { space: { members: Member[] } };
    expect(data.space.members.find((m) => m.member_sub === ROOT_SUB)).toBeFalsy();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 56 — Space ticket lifecycle (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 56: Space ticket lifecycle (API)", () => {
  let spaceTicketId = "";

  test.beforeAll(async () => {
    if (!sec55SpaceId || !sec55BobPage) {
      throw new Error("sec55SpaceId not set — section 55 beforeAll must run first");
    }
    // Bob (editor) creates a space ticket
    const resp = await apiPost(sec55BobPage, "bob", `ticket-spaces/${sec55SpaceId}/tickets`, {
      subject:     `Space ticket ${TS}`,
      description: "space ticket test",
    });
    if (!resp.ok()) throw new Error(`create space ticket failed: ${await resp.text()}`);
    const data = await resp.json() as { ticket: { ticket_id: string } };
    spaceTicketId = data.ticket.ticket_id;
  });

  test("56.1 Editor creates space ticket → 200, status=open, space_id set", async () => {
    const resp = await apiGet(sec55BobPage!, `ticket-spaces/${sec55SpaceId}/tickets/${spaceTicketId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { ticket: Record<string, unknown> };
    expect(data.ticket.status).toBe("open");
    expect(data.ticket.space_id).toBe(sec55SpaceId);
  });

  test("56.2 List space tickets → includes the new ticket", async () => {
    const resp = await apiGet(sec55BobPage!, `ticket-spaces/${sec55SpaceId}/tickets`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { items: Array<{ ticket_id: string }> };
    expect(data.items.find((t) => t.ticket_id === spaceTicketId)).toBeTruthy();
  });

  test("56.3 Get space ticket by ID → 200, shape check", async () => {
    const resp = await apiGet(sec55AlicePage!, `ticket-spaces/${sec55SpaceId}/tickets/${spaceTicketId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { ticket: Record<string, unknown> };
    expect(data.ticket.ticket_id).toBe(spaceTicketId);
    expect(data.ticket.subject).toBeTruthy();
    expect(Array.isArray(data.ticket.messages)).toBe(true);
  });

  test("56.4 Editor replies → 200, message in messages[]", async () => {
    const REPLY = `Space reply ${TS}`;
    const resp = await apiPost(
      sec55BobPage!, "bob",
      `ticket-spaces/${sec55SpaceId}/tickets/${spaceTicketId}/messages`,
      { body: REPLY },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { ticket: { messages: Array<{ body: string }> } };
    expect(data.ticket.messages.find((m) => m.body === REPLY)).toBeTruthy();
  });

  test("56.5 Owner assigns ticket to editor (Bob) → 200, assigned_to_sub=BOB_ID", async () => {
    // After 55.9 root is no longer a member. Remaining: Alice (owner), Bob (editor).
    const resp = await apiPost(
      sec55AlicePage!, "alice",
      `ticket-spaces/${sec55SpaceId}/tickets/${spaceTicketId}/assign`,
      { assignee_sub: BOB_ID },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { ticket: { assigned_to_sub: string } };
    expect(data.ticket.assigned_to_sub).toBe(BOB_ID);
  });

  test("56.6 Assigning to non-member → 400 with invalid_space_assignee", async () => {
    // Charlie is not a member of this space
    const resp = await apiPost(
      sec55AlicePage!, "alice",
      `ticket-spaces/${sec55SpaceId}/tickets/${spaceTicketId}/assign`,
      { assignee_sub: CHARLIE_ID },
    );
    expect(resp.status()).toBe(400);
    const data = await resp.json() as { detail: { error: { code: string } } };
    expect(data.detail.error.code).toBe("invalid_space_assignee");
  });

  test("56.7 Editor sets status to done → 200, status=done", async () => {
    const resp = await apiPost(
      sec55BobPage!, "bob",
      `ticket-spaces/${sec55SpaceId}/tickets/${spaceTicketId}/status`,
      { status: "done" },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { ticket: { status: string } };
    expect(data.ticket.status).toBe("done");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 57 — TicketsPage UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 57: TicketsPage UI", () => {
  let bobPage: Page;
  const UI_SUBJECT = `UI ticket ${TS}`;
  const UI_DESC    = `UI desc ${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    bobPage = await browser.newPage();
    await injectAuth(bobPage, "bob");
    await bobPage.goto(`${BASE}/tickets`, { waitUntil: "load" });
  });

  test("57.1 Page loads at /tickets with h1 Support Tickets", async () => {
    await expect(
      bobPage.locator("h1").filter({ hasText: /support tickets/i }),
    ).toBeVisible({ timeout: 8000 });
  });

  test("57.2 Open a ticket card with Subject/Description inputs and Create ticket button", async () => {
    await expect(bobPage.getByText("Open a ticket")).toBeVisible({ timeout: 5000 });
    await expect(bobPage.locator("#ticket-subject")).toBeVisible({ timeout: 5000 });
    await expect(bobPage.locator("#ticket-description")).toBeVisible({ timeout: 5000 });
    await expect(
      bobPage.getByRole("button", { name: "Create ticket" }),
    ).toBeVisible({ timeout: 5000 });
  });

  test("57.3 Create ticket via UI → toast Ticket created", async () => {
    test.setTimeout(20_000);
    await bobPage.locator("#ticket-subject").fill(UI_SUBJECT);
    await bobPage.locator("#ticket-description").fill(UI_DESC);
    const [postResp] = await Promise.all([
      bobPage.waitForResponse((r) =>
        r.url().includes("/tickets") &&
        r.request().method() === "POST" &&
        !r.url().includes("/messages"),
      ),
      bobPage.getByRole("button", { name: "Create ticket" }).click(),
    ]);
    expect(postResp.status()).toBe(200);
    await expect(bobPage.getByText("Ticket created", { exact: true })).toBeVisible({ timeout: 8000 });
  });

  test("57.4 New ticket appears in My tickets list", async () => {
    test.setTimeout(30_000);
    // Ensure we have a valid page on /tickets (session may have been lost)
    await injectAuth(bobPage, "bob");
    await bobPage.goto(`${BASE}/tickets`, { waitUntil: "load" });
    // Create a ticket via API to ensure it exists regardless of prior test state
    const marker = `UI check ${Date.now()}`;
    await apiPost(bobPage, "bob", "tickets", { subject: marker, description: "verify list" });
    // Click Refresh
    await bobPage.getByRole("button", { name: "Refresh" }).click();
    await bobPage.waitForTimeout(1500);
    // Paginate if needed
    for (let i = 0; i < 5; i++) {
      const visible = await bobPage.getByText(marker).first().isVisible().catch(() => false);
      if (visible) break;
      const nextBtn = bobPage.getByRole("button", { name: "Next page" });
      if (!(await nextBtn.isEnabled().catch(() => false))) break;
      await nextBtn.click();
      await bobPage.waitForTimeout(500);
    }
    await expect(bobPage.getByText(marker).first()).toBeVisible({ timeout: 8000 });
  });

  test("57.5 Ticket detail panel shows reply textarea and Send reply button", async () => {
    // After create, the ticket is auto-selected via useEffect
    await expect(
      bobPage.getByPlaceholder("Reply to ticket..."),
    ).toBeVisible({ timeout: 8000 });
    await expect(
      bobPage.getByRole("button", { name: "Send reply" }),
    ).toBeVisible({ timeout: 5000 });
  });
});
