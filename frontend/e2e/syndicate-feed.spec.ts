/**
 * E2E tests for Syndicate Page & Newsfeed (SYND-005)
 *
 * Section 439: Syndicate Profile API (6 tests)
 * Section 440: Syndicate Feed Post API (7 tests)
 * Section 441: Visibility Filtering API (5 tests)
 * Section 442: Syndicate Profile UI (4 tests)
 *
 * Auth: admin session cookies (role-bearing JWT) via e2e_admin_session_setup.py.
 * Non-GET requests include the x-csrf-token header.
 *
 * Endpoints under the distinct prefix /ui/syndicates/feed.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const CHARLIE_ID = "e2e_charlie@test.local";

const TS = Date.now();

interface SessionData {
  user_sub: string;
  csrf_token: string;
  cookies: Array<Record<string, unknown>>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sess = getSessions()[identity];
  if (!sess) throw new Error(`No session for identity "${identity}"`);
  const page = await browser.newPage();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await page.context().addCookies(sess.cookies as any);
  // Seed the auth store so the React app treats the user as authenticated.
  // Without this, ProtectedRoute redirects to /login and protected pages
  // (e.g. the syndicate profile) never mount, so their testids never render.
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, sess.user_sub);
  return page;
}

async function apiPost(page: Page, identity: string, path: string, body: object = {}) {
  return page.request.post(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": getSessions()[identity].csrf_token },
  });
}

async function apiPut(page: Page, identity: string, path: string, body: object = {}) {
  return page.request.put(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": getSessions()[identity].csrf_token },
  });
}

async function apiDelete(page: Page, identity: string, path: string) {
  return page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": getSessions()[identity].csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

// Shared pages + syndicate.
let alicePage: Page; // owner/admin
let bobPage: Page; // member
let charliePage: Page; // member (non-author, non-admin)
let syndicateId: string;

async function makeMember(adminPage: Page, sid: string, memberIdentity: string, memberId: string) {
  // Admin invites; invitee accepts.
  await apiPost(adminPage, "alice", `/ui/syndicates/${sid}/invite`, { user_id: memberId });
  const memberPage = memberIdentity === "bob" ? bobPage : charliePage;
  await apiPost(memberPage, memberIdentity, `/ui/syndicates/${sid}/invite/respond`, { accept: true });
}

// Shared pages and the base syndicate are created ONCE for the whole file and
// torn down ONCE at the very end. Previously these lived in block 439's
// beforeAll/afterAll, so block 439's afterAll closed the shared pages while
// blocks 440/441/442 still needed them -> "Target page, context or browser has
// been closed" (and `undefined` after a worker reset on retry).
test.beforeAll(async ({ browser }) => {
  alicePage = await newIdentityPage(browser, "alice");
  bobPage = await newIdentityPage(browser, "bob");
  charliePage = await newIdentityPage(browser, "charlie_admin");

  const resp = await apiPost(alicePage, "alice", "/ui/syndicates", {
    name: `Feed Syndicate ${TS}`,
    description: "Syndicate for feed E2E",
  });
  const data = await resp.json();
  syndicateId = data.syndicate_id;

  // Bob and Charlie join as members.
  await makeMember(alicePage, syndicateId, "bob", BOB_ID);
  await makeMember(alicePage, syndicateId, "charlie_admin", CHARLIE_ID);
});

test.afterAll(async () => {
  await alicePage?.close();
  await bobPage?.close();
  await charliePage?.close();
});

test.describe("439 — Syndicate Profile API", () => {
  test("439.1 GET profile returns metadata and members", async () => {
    const resp = await apiGet(alicePage, `/ui/syndicates/feed/${syndicateId}/profile`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.name).toBe(`Feed Syndicate ${TS}`);
    expect(Array.isArray(data.members)).toBe(true);
    expect(data.members.length).toBeGreaterThanOrEqual(3);
    expect(typeof data.post_count).toBe("number");
  });

  test("439.2 Admin updates profile with tags and description", async () => {
    const resp = await apiPut(alicePage, "alice", `/ui/syndicates/feed/${syndicateId}/profile`, {
      description: "Updated description",
      tags: ["gaming", "tutorials"],
      website_url: "https://example.com",
    });
    expect(resp.ok()).toBe(true);
    const after = await (await apiGet(alicePage, `/ui/syndicates/feed/${syndicateId}/profile`)).json();
    expect(after.description).toBe("Updated description");
    expect(after.tags).toEqual(["gaming", "tutorials"]);
    expect(after.website_url).toBe("https://example.com");
  });

  test("439.3 Non-admin cannot update profile", async () => {
    const resp = await apiPut(bobPage, "bob", `/ui/syndicates/feed/${syndicateId}/profile`, {
      description: "hacked",
    });
    expect(resp.status()).toBe(403);
  });

  test("439.4 Profile includes bundle_plans array", async () => {
    const data = await (await apiGet(alicePage, `/ui/syndicates/feed/${syndicateId}/profile`)).json();
    expect(Array.isArray(data.bundle_plans)).toBe(true);
  });

  test("439.5 Profile shows is_member=true for members", async () => {
    const data = await (await apiGet(bobPage, `/ui/syndicates/feed/${syndicateId}/profile`)).json();
    expect(data.is_member).toBe(true);
  });

  test("439.6 404 for non-existent syndicate", async () => {
    const resp = await apiGet(alicePage, `/ui/syndicates/feed/synd_doesnotexist/profile`);
    expect(resp.status()).toBe(404);
  });
});

test.describe("440 — Syndicate Feed Post API", () => {
  let publicPostId = "";
  let membersPostId = "";
  let rootPage: Page; // non-member

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("440.1 Member creates public post", async () => {
    const resp = await apiPost(bobPage, "bob", `/ui/syndicates/feed/${syndicateId}`, {
      text: `Public post ${TS}`,
      visibility: "public",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.visibility).toBe("public");
    publicPostId = data.post_id;

    const feed = await (await apiGet(bobPage, `/ui/syndicates/feed/${syndicateId}`)).json();
    expect(feed.posts.find((p: any) => p.post_id === publicPostId)).toBeTruthy();
  });

  test("440.2 Member creates members-only post", async () => {
    const resp = await apiPost(alicePage, "alice", `/ui/syndicates/feed/${syndicateId}`, {
      text: `Members post ${TS}`,
      visibility: "members_only",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.visibility).toBe("members_only");
    membersPostId = data.post_id;
  });

  test("440.3 Non-member cannot post", async () => {
    // Root is not a member of this syndicate.
    const r = await apiPost(rootPage, "root", `/ui/syndicates/feed/${syndicateId}`, { text: "nope" });
    expect([403, 404]).toContain(r.status());
  });

  test("440.4 Author can delete own post", async () => {
    const resp = await apiDelete(bobPage, "bob", `/ui/syndicates/feed/${syndicateId}/${publicPostId}`);
    expect(resp.ok()).toBe(true);
    const feed = await (await apiGet(bobPage, `/ui/syndicates/feed/${syndicateId}`)).json();
    expect(feed.posts.find((p: any) => p.post_id === publicPostId)).toBeFalsy();
  });

  test("440.5 Admin can delete any member's post", async () => {
    // Bob creates a post; Alice (admin) deletes it.
    const created = await (
      await apiPost(bobPage, "bob", `/ui/syndicates/feed/${syndicateId}`, { text: `Bob mod ${TS}` })
    ).json();
    const resp = await apiDelete(alicePage, "alice", `/ui/syndicates/feed/${syndicateId}/${created.post_id}`);
    expect(resp.ok()).toBe(true);
  });

  test("440.6 Non-author non-admin cannot delete", async () => {
    // Charlie (member, not author, not admin) tries to delete Alice's members-only post.
    const resp = await apiDelete(charliePage, "charlie_admin", `/ui/syndicates/feed/${syndicateId}/${membersPostId}`);
    expect(resp.status()).toBe(403);
  });

  test("440.7 Post text validation enforced", async () => {
    const empty = await apiPost(alicePage, "alice", `/ui/syndicates/feed/${syndicateId}`, { text: "" });
    expect(empty.status()).toBe(422);
    const tooLong = await apiPost(alicePage, "alice", `/ui/syndicates/feed/${syndicateId}`, {
      text: "x".repeat(5001),
    });
    expect(tooLong.status()).toBe(422);
  });
});

test.describe("441 — Visibility Filtering API", () => {
  let visSyndicateId = "";
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root"); // non-member viewer
    const data = await (
      await apiPost(alicePage, "alice", "/ui/syndicates", {
        name: `Vis Syndicate ${TS}`,
        description: "visibility test",
      })
    ).json();
    visSyndicateId = data.syndicate_id;
    // One public + one members-only post by Alice.
    await apiPost(alicePage, "alice", `/ui/syndicates/feed/${visSyndicateId}`, {
      text: `vis public ${TS}`,
      visibility: "public",
    });
    await apiPost(alicePage, "alice", `/ui/syndicates/feed/${visSyndicateId}`, {
      text: `vis members ${TS}`,
      visibility: "members_only",
    });
  });

  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("441.1 Member sees all posts", async () => {
    const data = await (await apiGet(alicePage, `/ui/syndicates/feed/${visSyndicateId}`)).json();
    expect(data.is_member).toBe(true);
    const vis = data.posts.map((p: any) => p.visibility);
    expect(vis).toContain("public");
    expect(vis).toContain("members_only");
  });

  test("441.2 Non-member sees only public posts", async () => {
    const data = await (await apiGet(rootPage, `/ui/syndicates/feed/${visSyndicateId}`)).json();
    expect(data.is_member).toBe(false);
    expect(data.posts.every((p: any) => p.visibility === "public")).toBe(true);
    expect(data.posts.length).toBe(1);
  });

  test("441.3 Members-only text hidden from non-members", async () => {
    const data = await (await apiGet(rootPage, `/ui/syndicates/feed/${visSyndicateId}`)).json();
    expect(data.posts.find((p: any) => p.text.includes("vis members"))).toBeFalsy();
  });

  test("441.4 Empty feed returns empty array", async () => {
    const empty = await (
      await apiPost(alicePage, "alice", "/ui/syndicates", { name: `Empty ${TS}`, description: "" })
    ).json();
    const data = await (await apiGet(alicePage, `/ui/syndicates/feed/${empty.syndicate_id}`)).json();
    expect(data.posts).toEqual([]);
    expect(data.next_cursor).toBeNull();
  });

  test("441.5 Non-member visible count matches response length", async () => {
    const data = await (await apiGet(rootPage, `/ui/syndicates/feed/${visSyndicateId}`)).json();
    expect(data.posts.length).toBe(data.posts.filter((p: any) => p.visibility === "public").length);
  });
});

test.describe("442 — Syndicate Profile UI", () => {
  let uiSyndicateId = "";

  test.beforeAll(async () => {
    const data = await (
      await apiPost(alicePage, "alice", "/ui/syndicates", {
        name: `UI Syndicate ${TS}`,
        description: "ui test syndicate",
      })
    ).json();
    uiSyndicateId = data.syndicate_id;
    await apiPost(alicePage, "alice", `/ui/syndicates/feed/${uiSyndicateId}`, {
      text: `ui members post ${TS}`,
      visibility: "members_only",
    });
  });

  test("442.1 Profile page renders syndicate name", async () => {
    await alicePage.goto(`${BASE}/syndicates/${uiSyndicateId}`);
    await expect(alicePage.getByTestId("syndicate-name")).toContainText(`UI Syndicate ${TS}`);
  });

  test("442.2 Members tab shows member list", async () => {
    await alicePage.goto(`${BASE}/syndicates/${uiSyndicateId}`);
    await alicePage.getByTestId("syndicate-tab-members").click();
    await expect(alicePage.getByTestId("syndicate-member-card").first()).toBeVisible();
  });

  test("442.3 Composer visible for members, hidden for non-members", async () => {
    await alicePage.goto(`${BASE}/syndicates/${uiSyndicateId}`);
    await expect(alicePage.getByTestId("syndicate-post-composer")).toBeVisible();

    // Root is not a member -> sees join banner, no composer.
    const rootPage = await newIdentityPage(alicePage.context().browser()!, "root");
    await rootPage.goto(`${BASE}/syndicates/${uiSyndicateId}`);
    await expect(rootPage.getByTestId("syndicate-join-banner")).toBeVisible();
    await expect(rootPage.getByTestId("syndicate-post-composer")).toHaveCount(0);
    await rootPage.close();
  });

  test("442.4 Members-only badge visible on restricted posts", async () => {
    await alicePage.goto(`${BASE}/syndicates/${uiSyndicateId}`);
    await expect(alicePage.getByTestId("syndicate-members-only-badge").first()).toBeVisible();
  });
});
