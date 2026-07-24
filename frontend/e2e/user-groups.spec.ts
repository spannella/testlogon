/**
 * E2E tests for User Groups (GROUP-001).
 *
 * Sections:
 *   447 — Group CRUD API (4 tests)
 *   448 — Membership Lifecycle API (5 tests)
 *   449 — Role Management & Succession API (4 tests)
 *   450 — Groups UI (3 tests)
 *   451 — Edge Cases & Negative Tests (5 tests)
 *   452 — Invitation Flow (3 tests)
 *
 * Auth: Uses e2e_admin_session_setup.py for root/alice/bob/charlie sessions.
 * All POST/PATCH/DELETE requests include x-csrf-token header.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";
const ROOT_ID  = "root.admin@testdev.local";
const TS       = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

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

function csrfHeaders(userId: string) {
  return { "x-csrf-token": getSessions()[userId].csrf_token };
}

async function apiPost(page: Page, userId: string, path: string, data?: any) {
  return page.request.post(`${API}${path}`, {
    headers: csrfHeaders(userId),
    data,
  });
}

async function apiPatch(page: Page, userId: string, path: string, data?: any) {
  return page.request.patch(`${API}${path}`, {
    headers: csrfHeaders(userId),
    data,
  });
}

async function apiDelete(page: Page, userId: string, path: string) {
  return page.request.delete(`${API}${path}`, {
    headers: csrfHeaders(userId),
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

// ─── Shared state ─────────────────────────────────────────────────────────────

const GROUP_NAME         = `E2E Group ${TS}`;
const PRIVATE_GROUP_NAME = `E2E Private ${TS}`;
let groupId              = "";
let privateGroupId       = "";
// For succession test, a separate group
const SUCCESSION_GROUP   = `E2E Succ ${TS}`;
let succGroupId          = "";
// For invitation flow
const INVITE_GROUP       = `E2E Invite ${TS}`;
let inviteGroupId        = "";
// For dissolve test
const DISSOLVE_GROUP     = `E2E Dissolve ${TS}`;
let dissolveGroupId      = "";

// ─── Tests ────────────────────────────────────────────────────────────────────

test.describe("user-groups", () => {
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  // ── Section 447: Group CRUD API ────────────────────────────────────

  test.describe("447 — Group CRUD API", () => {
    test("447.1 Create a public group", async () => {
      const resp = await apiPost(alicePage, ALICE_ID, "/ui/groups", {
        name: GROUP_NAME,
        description: "A test group for E2E",
        visibility: "public",
        topic: "testing",
      });
      expect(resp.status()).toBe(201);
      const body = await resp.json();
      expect(body.group_id).toBeTruthy();
      expect(body.visibility).toBe("public");
      expect(body.admin_user_id).toBe(ALICE_ID);
      expect(body.my_role).toBe("admin");
      expect(body.member_count).toBe(1);
      groupId = body.group_id;
    });

    test("447.2 Get group details", async () => {
      const resp = await apiGet(alicePage, `/ui/groups/${groupId}`);
      expect(resp.status()).toBe(200);
      const body = await resp.json();
      expect(body.name).toBe(GROUP_NAME);
      expect(body.member_count).toBe(1);
      expect(body.my_role).toBe("admin");
    });

    test("447.3 Update group settings", async () => {
      const resp = await apiPatch(alicePage, ALICE_ID, `/ui/groups/${groupId}`, {
        description: "Updated description",
      });
      expect(resp.status()).toBe(200);
      const body = await resp.json();
      expect(body.description).toBe("Updated description");
    });

    test("447.4 Create private group", async () => {
      const resp = await apiPost(alicePage, ALICE_ID, "/ui/groups", {
        name: PRIVATE_GROUP_NAME,
        description: "Private group",
        visibility: "private",
      });
      expect(resp.status()).toBe(201);
      const body = await resp.json();
      expect(body.visibility).toBe("private");
      privateGroupId = body.group_id;
    });
  });

  // ── Section 448: Membership Lifecycle API ──────────────────────────

  test.describe("448 — Membership Lifecycle API", () => {
    test("448.1 Bob joins public group", async () => {
      const resp = await apiPost(bobPage, BOB_ID, `/ui/groups/${groupId}/join`);
      expect(resp.status()).toBe(200);
      const body = await resp.json();
      expect(body.status).toBe("active");
      expect(body.role).toBe("member");
    });

    test("448.2 List members includes Bob", async () => {
      const resp = await apiGet(alicePage, `/ui/groups/${groupId}/members`);
      expect(resp.status()).toBe(200);
      const body = await resp.json();
      const bob = body.members.find((m: any) => m.user_id === BOB_ID);
      expect(bob).toBeTruthy();
      expect(bob.role).toBe("member");
    });

    test("448.3 Bob requests to join private group", async () => {
      const resp = await apiPost(bobPage, BOB_ID, `/ui/groups/${privateGroupId}/join`);
      expect(resp.status()).toBe(200);
      const body = await resp.json();
      expect(body.status).toBe("pending_approval");
    });

    test("448.4 Alice approves join request", async () => {
      const resp = await apiPost(
        alicePage,
        ALICE_ID,
        `/ui/groups/${privateGroupId}/requests/${BOB_ID}/review`,
        { approved: true },
      );
      expect(resp.status()).toBe(200);
      const body = await resp.json();
      expect(body.status).toBe("active");
    });

    test("448.5 Bob leaves group", async () => {
      const resp = await apiPost(bobPage, BOB_ID, `/ui/groups/${privateGroupId}/leave`);
      expect(resp.status()).toBe(200);
      const body = await resp.json();
      expect(body.ok).toBe(true);
    });
  });

  // ── Section 449: Role Management & Succession API ──────────────────

  test.describe("449 — Role Management & Succession API", () => {
    test.beforeAll(async () => {
      // Create a fresh group for succession tests
      const resp = await apiPost(alicePage, ALICE_ID, "/ui/groups", {
        name: SUCCESSION_GROUP,
        visibility: "public",
      });
      const body = await resp.json();
      succGroupId = body.group_id;

      // Bob joins
      await apiPost(bobPage, BOB_ID, `/ui/groups/${succGroupId}/join`);
    });

    test("449.1 Alice promotes Bob to moderator", async () => {
      const resp = await apiPatch(
        alicePage,
        ALICE_ID,
        `/ui/groups/${succGroupId}/members/${BOB_ID}/role`,
        { role: "moderator" },
      );
      expect(resp.status()).toBe(200);
      const body = await resp.json();
      expect(body.role).toBe("moderator");
    });

    test("449.2 Moderator cannot remove admin", async () => {
      const resp = await apiDelete(
        bobPage,
        BOB_ID,
        `/ui/groups/${succGroupId}/members/${ALICE_ID}`,
      );
      expect(resp.status()).toBe(403);
    });

    test("449.3 Admin can remove moderator", async () => {
      // First, add a third member (root) so group doesn't dissolve
      const rootPage = await alicePage.context().browser()!.newPage();
      await injectAuth(rootPage, ROOT_ID);
      await apiPost(rootPage, ROOT_ID, `/ui/groups/${succGroupId}/join`);

      // Alice removes Bob
      const resp = await apiDelete(
        alicePage,
        ALICE_ID,
        `/ui/groups/${succGroupId}/members/${BOB_ID}`,
      );
      expect(resp.status()).toBe(200);
      await rootPage.close();
    });

    test("449.4 Admin succession on leave", async () => {
      // Re-add Bob as member
      await apiPost(bobPage, BOB_ID, `/ui/groups/${succGroupId}/join`);

      // Alice leaves - succession should happen
      const resp = await apiPost(alicePage, ALICE_ID, `/ui/groups/${succGroupId}/leave`);
      expect(resp.status()).toBe(200);

      // Verify admin changed
      const getResp = await apiGet(bobPage, `/ui/groups/${succGroupId}`);
      const body = await getResp.json();
      expect(body.admin_user_id).not.toBe(ALICE_ID);
    });
  });

  // ── Section 450: Groups UI ─────────────────────────────────────────

  test.describe("450 — Groups UI", () => {
    // Self-seed a dedicated public group that Alice administers. This block must
    // not rely on the module-level `GROUP_NAME`/`groupId` from section 447 —
    // Playwright restarts the worker on a prior failure (and on retry of these
    // very tests), which resets module state and regenerates the TS-derived
    // GROUP_NAME, leaving `groupId` empty (settings route `/groups//settings`)
    // and pointing GROUP_NAME at a group that was never created.
    let uiGroupName = "";
    let uiGroupId = "";
    test.beforeAll(async () => {
      uiGroupName = `E2E UI Group ${TS}`;
      const resp = await apiPost(alicePage, ALICE_ID, "/ui/groups", {
        name: uiGroupName,
        description: "A test group for E2E UI",
        visibility: "public",
        topic: "testing",
      });
      uiGroupId = (await resp.json()).group_id;
    });

    test("450.1 Groups list shows user's groups", async () => {
      await alicePage.goto(`${BASE}/groups`, { waitUntil: "domcontentloaded" });
      await expect(
        alicePage.locator("[data-testid='groups-list-page']"),
      ).toBeVisible();
      // Alice should see the public group she created
      await expect(alicePage.getByText(uiGroupName)).toBeVisible({ timeout: 10_000 });
    });

    test("450.2 Discover tab shows public groups", async () => {
      await alicePage.goto(`${BASE}/groups`, { waitUntil: "domcontentloaded" });
      await alicePage.getByRole("tab", { name: "Discover" }).click();
      // Search for the seeded group so it isn't paginated off by accumulated
      // test data, then assert it appears in the discover results.
      await alicePage.getByPlaceholder("Search groups...").fill(uiGroupName);
      await expect(
        alicePage.getByText(uiGroupName),
      ).toBeVisible({ timeout: 10_000 });
    });

    test("450.3 Settings page allows admin edits", async () => {
      await alicePage.goto(`${BASE}/groups/${uiGroupId}/settings`, {
        waitUntil: "domcontentloaded",
      });
      await expect(
        alicePage.locator("[data-testid='group-settings-page']"),
      ).toBeVisible({ timeout: 10_000 });
      const descInput = alicePage.locator("#settings-description");
      // The settings form is driven by react-hook-form `values:` bound to the
      // group query, so it RE-SETS the field every time the group query data
      // changes. Under a shard run that query is slow and/or refetches in the
      // background (the `["groups"]` cache is invalidated by other specs'
      // mutations), which would wipe out our typed text and submit the stale
      // original description. Wait for the form to be hydrated with the loaded
      // group data first, then fill and immediately submit, and confirm the
      // value stuck right before saving.
      await expect(descInput).toHaveValue("A test group for E2E UI", { timeout: 10_000 });
      await descInput.fill(`UI updated desc ${TS}`);
      await expect(descInput).toHaveValue(`UI updated desc ${TS}`);
      // Capture the PATCH so we don't read the API back before the write lands.
      const savePromise = alicePage.waitForResponse(
        (r) =>
          r.url().includes(`/ui/groups/${uiGroupId}`) &&
          r.request().method() === "PATCH",
        { timeout: 10_000 },
      );
      await alicePage.getByRole("button", { name: /Save Changes/i }).click();
      const saveResp = await savePromise;
      expect(saveResp.ok()).toBe(true);
      // Verify via API
      const resp = await apiGet(alicePage, `/ui/groups/${uiGroupId}`);
      const body = await resp.json();
      expect(body.description).toBe(`UI updated desc ${TS}`);
    });
  });

  // ── Section 451: Edge Cases & Negative Tests ───────────────────────

  test.describe("451 — Edge Cases & Negative Tests", () => {
    // Self-seed a dedicated public group with Bob as a member. This block must
    // not rely on the module-level `groupId` from section 447/448 — Playwright
    // restarts the worker on a prior failure (e.g. the 450 UI tests), which
    // resets module state and would leave `groupId` empty (404 instead of 409).
    let edgeGroupId = "";
    test.beforeAll(async () => {
      const resp = await apiPost(alicePage, ALICE_ID, "/ui/groups", {
        name: `E2E Edge ${TS}`,
        visibility: "public",
      });
      edgeGroupId = (await resp.json()).group_id;
      await apiPost(bobPage, BOB_ID, `/ui/groups/${edgeGroupId}/join`);
    });

    test("451.1 Duplicate join returns 409", async () => {
      // Bob is already in the group from this block's beforeAll
      const resp = await apiPost(bobPage, BOB_ID, `/ui/groups/${edgeGroupId}/join`);
      expect(resp.status()).toBe(409);
    });

    test("451.2 Non-admin cannot update group", async () => {
      const resp = await apiPatch(bobPage, BOB_ID, `/ui/groups/${edgeGroupId}`, {
        name: "Hacked Name",
      });
      expect(resp.status()).toBe(403);
    });

    test("451.3 Non-member cannot view members of private group", async () => {
      // Create a fresh private group by Alice
      const createResp = await apiPost(alicePage, ALICE_ID, "/ui/groups", {
        name: `Private Check ${TS}`,
        visibility: "private",
      });
      const pg = await createResp.json();

      // Bob (non-member) tries to view members
      const resp = await apiGet(bobPage, `/ui/groups/${pg.group_id}/members`);
      expect(resp.status()).toBe(403);
    });

    test("451.4 Dissolved group returns 410", async () => {
      // Create and dissolve a group
      const createResp = await apiPost(alicePage, ALICE_ID, "/ui/groups", {
        name: DISSOLVE_GROUP,
        visibility: "public",
      });
      const dg = await createResp.json();
      dissolveGroupId = dg.group_id;

      await apiDelete(alicePage, ALICE_ID, `/ui/groups/${dissolveGroupId}`);

      // Try to GET the dissolved group
      const resp = await apiGet(alicePage, `/ui/groups/${dissolveGroupId}`);
      expect(resp.status()).toBe(410);
    });

    test("451.5 Name too short returns 422", async () => {
      const resp = await apiPost(alicePage, ALICE_ID, "/ui/groups", {
        name: "Ab",
        visibility: "public",
      });
      expect(resp.status()).toBe(422);
    });
  });

  // ── Section 452: Invitation Flow ───────────────────────────────────

  test.describe("452 — Invitation Flow", () => {
    test.beforeAll(async () => {
      // Create a group for invitation tests
      const resp = await apiPost(alicePage, ALICE_ID, "/ui/groups", {
        name: INVITE_GROUP,
        visibility: "private",
      });
      const body = await resp.json();
      inviteGroupId = body.group_id;
    });

    test("452.1 Admin invites user", async () => {
      const resp = await apiPost(
        alicePage,
        ALICE_ID,
        `/ui/groups/${inviteGroupId}/invite`,
        { user_id: BOB_ID },
      );
      expect(resp.status()).toBe(200);
      const body = await resp.json();
      expect(body.status).toBe("invited");
    });

    test("452.2 Invited user accepts", async () => {
      const resp = await apiPost(
        bobPage,
        BOB_ID,
        `/ui/groups/${inviteGroupId}/invites/${BOB_ID}/respond`,
        { accept: true },
      );
      expect(resp.status()).toBe(200);
      const body = await resp.json();
      expect(body.status).toBe("active");

      // Verify Bob is now a member
      const membersResp = await apiGet(alicePage, `/ui/groups/${inviteGroupId}/members`);
      const members = await membersResp.json();
      const bob = members.members.find((m: any) => m.user_id === BOB_ID);
      expect(bob).toBeTruthy();
      expect(bob.status).toBe("active");
    });

    test("452.3 Invited user declines", async () => {
      // Invite Root
      await apiPost(
        alicePage,
        ALICE_ID,
        `/ui/groups/${inviteGroupId}/invite`,
        { user_id: ROOT_ID },
      );

      // Root declines
      const rootPage = await alicePage.context().browser()!.newPage();
      await injectAuth(rootPage, ROOT_ID);
      const resp = await apiPost(
        rootPage,
        ROOT_ID,
        `/ui/groups/${inviteGroupId}/invites/${ROOT_ID}/respond`,
        { accept: false },
      );
      expect(resp.status()).toBe(200);
      const body = await resp.json();
      expect(body.status).toBe("declined");

      // Verify Root is NOT in the members list
      const membersResp = await apiGet(alicePage, `/ui/groups/${inviteGroupId}/members`);
      const members = await membersResp.json();
      const root = members.members.find((m: any) => m.user_id === ROOT_ID);
      expect(root).toBeFalsy();

      await rootPage.close();
    });
  });
});
