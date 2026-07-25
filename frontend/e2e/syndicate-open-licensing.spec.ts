/**
 * E2E tests for Syndicate Open Licensing (LICENSE-005)
 *
 * Section 479: Enable/Disable Open Licensing API (4 tests)
 * Section 480: Content Registration & Auto-License API (4 tests)
 * Section 481: Membership Lifecycle & Auto-Licensing API (4 tests)
 * Section 482: Content Exemption API (4 tests)
 *
 * Auth: admin session cookies (role-bearing JWT) via e2e_admin_session_setup.py.
 * All non-GET requests include x-csrf-token header.
 *
 * Alice = syndicate owner/admin; Bob, Charlie = members.
 * Auto-licenses use license_mode=syndicate_auto in the issued_licenses table.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions, resolveIdentityId } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const ALICE_ID = resolveIdentityId("e2e_alice@test.local");
const BOB_ID = resolveIdentityId("e2e_bob@test.local");
const CHARLIE_ID = resolveIdentityId("e2e_charlie@test.local");

const TS = Date.now();

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
  }
  return _sessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const sess = sessions[identity];
  if (!sess) throw new Error(`No session for identity "${identity}"`);
  const page = await browser.newPage();
  await page.context().addCookies(sess.cookies);
  return page;
}

function csrf(identity: string) {
  return { "x-csrf-token": getSessions()[identity].csrf_token };
}

async function apiPost(page: Page, identity: string, path: string, body: object = {}) {
  return page.request.post(`${BASE}${path}`, { data: body, headers: csrf(identity) });
}
async function apiPatch(page: Page, identity: string, path: string, body: object = {}) {
  return page.request.patch(`${BASE}${path}`, { data: body, headers: csrf(identity) });
}
async function apiDelete(page: Page, identity: string, path: string) {
  return page.request.delete(`${BASE}${path}`, { headers: csrf(identity) });
}
async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

let alicePage: Page;
let bobPage: Page;
let charliePage: Page;

const OL = (id: string) => `/ui/syndicates/open-licensing/${id}`;
const DEFAULT_TERMS = {
  profit_share_pct: 5,
  fixed_cost_cents: 0,
  revenue_share_pct: 3,
  currency: "usd",
};

async function createSyndicateWithBob(): Promise<string> {
  const createResp = await apiPost(alicePage, "alice", "/ui/syndicates", {
    name: `OpenLic Synd ${TS}-${Math.random().toString(36).slice(2, 7)}`,
    description: "open licensing e2e",
  });
  expect(createResp.status()).toBe(201);
  const sid = (await createResp.json()).syndicate_id as string;

  const inviteResp = await apiPost(alicePage, "alice", `/ui/syndicates/${sid}/invite`, {
    user_id: BOB_ID,
  });
  expect(inviteResp.ok()).toBeTruthy();
  const acceptResp = await apiPost(bobPage, "bob", `/ui/syndicates/${sid}/invite/respond`, {
    accept: true,
  });
  expect(acceptResp.ok()).toBeTruthy();
  return sid;
}

async function heldLicenses(page: Page): Promise<any[]> {
  const resp = await apiGet(page, "/ui/licenses/held");
  expect(resp.ok()).toBeTruthy();
  return (await resp.json()).items as any[];
}

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

// ---------------------------------------------------------------------------
test.describe("Section 479: Enable/Disable Open Licensing API", () => {
  let sid = "";
  test.beforeAll(async () => {
    sid = await createSyndicateWithBob();
  });

  test("479.1 Admin enables open licensing with terms", async () => {
    const resp = await apiPost(alicePage, "alice", `${OL(sid)}/enable`, { terms: DEFAULT_TERMS });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.open_licensing_enabled).toBe(true);
    expect(body.open_licensing_terms.profit_share_pct).toBe(5);
    expect(body.open_licensing_terms.revenue_share_pct).toBe(3);
  });

  test("479.2 Non-admin cannot enable open licensing", async () => {
    const resp = await apiPost(bobPage, "bob", `${OL(sid)}/enable`, { terms: DEFAULT_TERMS });
    expect(resp.status()).toBe(403);
  });

  test("479.3 Admin updates terms", async () => {
    const resp = await apiPatch(alicePage, "alice", `${OL(sid)}/terms`, {
      terms: { ...DEFAULT_TERMS, profit_share_pct: 10 },
    });
    expect(resp.status()).toBe(200);
    const getResp = await apiGet(alicePage, OL(sid));
    const cfg = await getResp.json();
    expect(cfg.open_licensing_terms.profit_share_pct).toBe(10);
  });

  test("479.4 Admin disables open licensing", async () => {
    const resp = await apiPost(alicePage, "alice", `${OL(sid)}/disable`);
    expect(resp.status()).toBe(200);
    const cfg = await (await apiGet(alicePage, OL(sid))).json();
    expect(cfg.open_licensing_enabled).toBe(false);
  });
});

// ---------------------------------------------------------------------------
test.describe("Section 480: Content Registration & Auto-License API", () => {
  let sid = "";
  const contentId = `vid_${TS}_480`;
  test.beforeAll(async () => {
    sid = await createSyndicateWithBob();
    await apiPost(alicePage, "alice", `${OL(sid)}/enable`, { terms: DEFAULT_TERMS });
  });

  test("480.1 Alice registers content under syndicate", async () => {
    const resp = await apiPost(alicePage, "alice", `${OL(sid)}/register`, {
      content_id: contentId,
      content_type: "video",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    // member_count = 2 (Alice + Bob) -> 1 auto-license (to Bob)
    expect(body.licenses_created).toBe(1);
  });

  test("480.2 Bob sees auto-license in held licenses", async () => {
    const held = await heldLicenses(bobPage);
    const lic = held.find(
      (l) => l.content_id === contentId && l.license_mode === "syndicate_auto",
    );
    expect(lic).toBeTruthy();
    expect(lic.licensor_id).toBe(ALICE_ID);
    expect(lic.status).toBe("active");
  });

  test("480.3 Syndicate content list includes registered content", async () => {
    const resp = await apiGet(alicePage, `${OL(sid)}/content`);
    expect(resp.ok()).toBeTruthy();
    const items = (await resp.json()).items as any[];
    expect(items.some((c) => c.content_id === contentId)).toBe(true);
  });

  test("480.4 Registration fails when open licensing is disabled", async () => {
    await apiPost(alicePage, "alice", `${OL(sid)}/disable`);
    const resp = await apiPost(alicePage, "alice", `${OL(sid)}/register`, {
      content_id: `vid_${TS}_480b`,
      content_type: "video",
    });
    expect(resp.status()).toBe(400);
  });
});

// ---------------------------------------------------------------------------
test.describe("Section 481: Membership Lifecycle & Auto-Licensing API", () => {
  let sid = "";
  const aliceContent = `vid_${TS}_481a`;
  const bobContent = `vid_${TS}_481b`;
  const lateContent = `vid_${TS}_481late`;

  test.beforeAll(async () => {
    sid = await createSyndicateWithBob();
    await apiPost(alicePage, "alice", `${OL(sid)}/enable`, { terms: DEFAULT_TERMS });
    await apiPost(alicePage, "alice", `${OL(sid)}/register`, {
      content_id: aliceContent,
      content_type: "video",
    });
    await apiPost(bobPage, "bob", `${OL(sid)}/register`, {
      content_id: bobContent,
      content_type: "video",
    });
  });

  test("481.1 New member receives auto-licenses for existing content", async () => {
    // Charlie joins -> on_member_joined auto-licenses existing content to him.
    const inviteResp = await apiPost(alicePage, "alice", `/ui/syndicates/${sid}/invite`, {
      user_id: CHARLIE_ID,
    });
    expect(inviteResp.ok()).toBeTruthy();
    const acceptResp = await apiPost(
      charliePage,
      "charlie_admin",
      `/ui/syndicates/${sid}/invite/respond`,
      { accept: true },
    );
    expect(acceptResp.ok()).toBeTruthy();

    const held = await heldLicenses(charliePage);
    const fromAlice = held.find(
      (l) => l.content_id === aliceContent && l.license_mode === "syndicate_auto",
    );
    const fromBob = held.find(
      (l) => l.content_id === bobContent && l.license_mode === "syndicate_auto",
    );
    expect(fromAlice).toBeTruthy();
    expect(fromBob).toBeTruthy();
  });

  test("481.2 Leaving member retains existing licenses", async () => {
    const leaveResp = await apiPost(bobPage, "bob", `/ui/syndicates/${sid}/leave`);
    expect(leaveResp.ok()).toBeTruthy();
    const held = await heldLicenses(bobPage);
    const lic = held.find(
      (l) => l.content_id === aliceContent && l.license_mode === "syndicate_auto",
    );
    expect(lic).toBeTruthy();
    expect(lic.status).toBe("active");
  });

  test("481.3 Content by departed member remains licensed to others", async () => {
    // Charlie still holds an active auto-license for Bob's content after Bob left.
    const held = await heldLicenses(charliePage);
    const lic = held.find(
      (l) => l.content_id === bobContent && l.license_mode === "syndicate_auto",
    );
    expect(lic).toBeTruthy();
    expect(lic.status).toBe("active");
  });

  test("481.4 No new auto-licenses for departed member's future content", async () => {
    // Alice registers new content after Bob left -> Bob gets NO new auto-license,
    // but Charlie (still a member) does.
    const resp = await apiPost(alicePage, "alice", `${OL(sid)}/register`, {
      content_id: lateContent,
      content_type: "video",
    });
    expect(resp.status()).toBe(200);

    const bobHeld = await heldLicenses(bobPage);
    expect(bobHeld.some((l) => l.content_id === lateContent)).toBe(false);

    const charlieHeld = await heldLicenses(charliePage);
    expect(charlieHeld.some((l) => l.content_id === lateContent)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
test.describe("Section 482: Content Exemption API", () => {
  let sid = "";
  const contentId = `vid_${TS}_482`;

  test.beforeAll(async () => {
    sid = await createSyndicateWithBob();
    await apiPost(alicePage, "alice", `${OL(sid)}/enable`, { terms: DEFAULT_TERMS });
    await apiPost(alicePage, "alice", `${OL(sid)}/register`, {
      content_id: contentId,
      content_type: "video",
    });
  });

  test("482.1 Creator exempts content from auto-licensing", async () => {
    const resp = await apiPost(alicePage, "alice", `${OL(sid)}/exempt/${contentId}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.exempt).toBe(true);
    expect(body.revoked_count).toBeGreaterThanOrEqual(1);
  });

  test("482.2 Exempted content's auto-licenses are revoked", async () => {
    const held = await heldLicenses(bobPage);
    const lic = held.find(
      (l) => l.content_id === contentId && l.license_mode === "syndicate_auto",
    );
    // Either absent or revoked (not active).
    expect(lic === undefined || lic.status === "revoked").toBe(true);
  });

  test("482.3 Non-owner cannot exempt content", async () => {
    const resp = await apiPost(bobPage, "bob", `${OL(sid)}/exempt/${contentId}`);
    expect(resp.status()).toBe(403);
  });

  test("482.4 Remove exemption re-creates auto-licenses", async () => {
    const resp = await apiDelete(alicePage, "alice", `${OL(sid)}/exempt/${contentId}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.exempt).toBe(false);
    expect(body.licenses_created).toBeGreaterThanOrEqual(1);

    const held = await heldLicenses(bobPage);
    const active = held.find(
      (l) =>
        l.content_id === contentId &&
        l.license_mode === "syndicate_auto" &&
        l.status === "active",
    );
    expect(active).toBeTruthy();
  });
});
