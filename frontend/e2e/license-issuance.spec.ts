/**
 * E2E tests for Content License Issuance (LICENSE-002).
 *
 * Sections:
 *   467 -- Per-User License Issuance API (4 tests)
 *   468 -- Blanket License Issuance API  (4 tests)
 *   469 -- License Check & Terms API     (4 tests)
 *   470 -- License Revocation API        (4 tests)
 *
 * Auth: Alice, Bob, Charlie session cookies (from e2e_admin_session_setup.py).
 *       Keys: "alice", "bob", "charlie_admin"
 *
 * Total: 16 tests
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const TS = Date.now();

// Identity keys matching e2e_admin_session_setup.py
const ALICE_KEY = "alice";
const BOB_KEY = "bob";
const CHARLIE_KEY = "charlie_admin";

// Email-based user subs
const ALICE_SUB = "e2e_alice@test.local";
const BOB_SUB = "e2e_bob@test.local";

// Unique content IDs per run
const PER_USER_CONTENT = `pu_content_${TS}`;
const BLANKET_CONTENT = `bl_content_${TS}`;
const UNLICENSED_CONTENT = `un_content_${TS}`;

// ─── Session bootstrap ───────────────────────────────────────────────────────

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

// ─── Auth + request helpers ──────────────────────────────────────────────────

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

async function apiPost(page: Page, identity: string, path: string, body: Record<string, unknown>) {
  const session = getSessions()[identity];
  return page.request.post(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
    data: body,
  });
}

async function apiPatch(page: Page, identity: string, path: string, body: Record<string, unknown>) {
  const session = getSessions()[identity];
  return page.request.patch(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
    data: body,
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

// ─── Shared state ─────────────────────────────────────────────────────────────

let perUserLicenseId = "";
let blanketLicenseId = "";

// ─── Section 467: Per-User License Issuance API ──────────────────────────────

test.describe("467 -- Per-User License Issuance API", () => {
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_KEY);
    bobPage = await newIdentityPage(browser, BOB_KEY);
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("467.1 Alice issues a per-user license to Bob for her video", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/licenses/issued", {
      content_id: PER_USER_CONTENT,
      content_type: "video",
      license_mode: "per_user",
      licensee_id: BOB_SUB,
      profit_share_pct: 15,
      fixed_cost_cents: 500,
      revenue_share_pct: 5,
      title: `Test Video ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.issued_license_id).toBeTruthy();
    expect(data.license_mode).toBe("per_user");
    expect(data.licensee_id).toBe(BOB_SUB);
    expect(data.status).toBe("active");
    expect(data.profit_share_pct).toBe(15);
    expect(data.fixed_cost_cents).toBe(500);
    expect(data.revenue_share_pct).toBe(5);
    perUserLicenseId = data.issued_license_id;
  });

  test("467.2 License appears in Alice's issued list", async () => {
    const resp = await apiGet(alicePage, "/ui/licenses/issued");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.items.find(
      (i: { issued_license_id: string }) => i.issued_license_id === perUserLicenseId,
    );
    expect(found).toBeTruthy();
    expect(found.license_mode).toBe("per_user");
  });

  test("467.3 Bob sees the license in his held list", async () => {
    const resp = await apiGet(bobPage, "/ui/licenses/held");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.items.find(
      (i: { issued_license_id: string }) => i.issued_license_id === perUserLicenseId,
    );
    expect(found).toBeTruthy();
    expect(found.terms_snapshot).toBeTruthy();
    expect(Number(found.terms_snapshot.profit_share_pct)).toBe(15);
    expect(Number(found.terms_snapshot.fixed_cost_cents)).toBe(500);
  });

  test("467.4 Per-user license without licensee_id fails", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/licenses/issued", {
      content_id: "some_content",
      content_type: "video",
      license_mode: "per_user",
      // No licensee_id
      profit_share_pct: 10,
    });
    expect(resp.status()).toBe(400);
  });
});

// ─── Section 468: Blanket License Issuance API ───────────────────────────────

test.describe("468 -- Blanket License Issuance API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_KEY);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("468.1 Alice issues a blanket license on a video clip", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/licenses/issued", {
      content_id: BLANKET_CONTENT,
      content_type: "video",
      license_mode: "blanket",
      profit_share_pct: 10,
      fixed_cost_cents: 0,
      revenue_share_pct: 5,
      title: `Blanket Video ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.issued_license_id).toBeTruthy();
    expect(data.license_mode).toBe("blanket");
    expect(data.licensee_id).toBeFalsy();
    expect(data.status).toBe("active");
    blanketLicenseId = data.issued_license_id;
  });

  test("468.2 Blanket-licensed content appears in library", async () => {
    const resp = await apiGet(alicePage, "/ui/licenses/library");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.items.find(
      (i: { content_id: string }) => i.content_id === BLANKET_CONTENT,
    );
    expect(found).toBeTruthy();
    expect(found.profit_share_pct).toBe(10);
  });

  test("468.3 Library is filterable by content type", async () => {
    const resp = await apiGet(alicePage, "/ui/licenses/library?content_type=video");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    for (const item of data.items) {
      expect(item.content_type).toBe("video");
    }
    const found = data.items.find(
      (i: { content_id: string }) => i.content_id === BLANKET_CONTENT,
    );
    expect(found).toBeTruthy();
  });

  test("468.4 Library is browsable by licensor", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/licenses/library/creator/${encodeURIComponent(ALICE_SUB)}`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.items.find(
      (i: { content_id: string }) => i.content_id === BLANKET_CONTENT,
    );
    expect(found).toBeTruthy();
    expect(found.licensor_id).toBe(ALICE_SUB);
  });
});

// ─── Section 469: License Check & Terms API ──────────────────────────────────

test.describe("469 -- License Check & Terms API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let charliePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_KEY);
    bobPage = await newIdentityPage(browser, BOB_KEY);
    charliePage = await newIdentityPage(browser, CHARLIE_KEY);
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
    await charliePage.close();
  });

  test("469.1 Bob checks license for content with per-user license", async () => {
    const resp = await apiGet(
      bobPage,
      `/ui/licenses/content/${PER_USER_CONTENT}/check`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.has_license).toBe(true);
    expect(data.license_mode).toBe("per_user");
    expect(data.terms).toBeTruthy();
    expect(data.terms.profit_share_pct).toBe(15);
  });

  test("469.2 Charlie checks license for blanket-licensed content", async () => {
    const resp = await apiGet(
      charliePage,
      `/ui/licenses/content/${BLANKET_CONTENT}/check`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.has_license).toBe(true);
    expect(data.license_mode).toBe("blanket");
  });

  test("469.3 Bob checks unlicensed content", async () => {
    const resp = await apiGet(
      bobPage,
      `/ui/licenses/content/${UNLICENSED_CONTENT}/check`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.has_license).toBe(false);
  });

  test("469.4 Alice updates blanket license terms", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_KEY,
      `/ui/licenses/issued/${blanketLicenseId}?content_id=${encodeURIComponent(BLANKET_CONTENT)}`,
      { profit_share_pct: 20 },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.profit_share_pct).toBe(20);
  });
});

// ─── Section 470: License Revocation API ─────────────────────────────────────

test.describe("470 -- License Revocation API", () => {
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_KEY);
    bobPage = await newIdentityPage(browser, BOB_KEY);
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("470.1 Alice revokes Bob's per-user license", async () => {
    const resp = await apiPost(
      alicePage,
      ALICE_KEY,
      `/ui/licenses/issued/${perUserLicenseId}/revoke?content_id=${encodeURIComponent(PER_USER_CONTENT)}`,
      { reason: "Terms violated" },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("revoked");
  });

  test("470.2 Bob no longer sees revoked license as active", async () => {
    const resp = await apiGet(bobPage, "/ui/licenses/held");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.items.find(
      (i: { issued_license_id: string }) => i.issued_license_id === perUserLicenseId,
    );
    expect(found).toBeTruthy();
    expect(found.status).toBe("revoked");
  });

  test("470.3 Alice revokes blanket license", async () => {
    const resp = await apiPost(
      alicePage,
      ALICE_KEY,
      `/ui/licenses/issued/${blanketLicenseId}/revoke?content_id=${encodeURIComponent(BLANKET_CONTENT)}`,
      { reason: "No longer available" },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("revoked");

    // Verify removed from library
    const libResp = await apiGet(alicePage, "/ui/licenses/library");
    expect(libResp.status()).toBe(200);
    const libData = await libResp.json();
    const found = libData.items.find(
      (i: { content_id: string }) => i.content_id === BLANKET_CONTENT,
    );
    expect(found).toBeFalsy();
  });

  test("470.4 Non-licensor cannot revoke", async () => {
    // First create a new license for Bob to try to revoke
    const issueResp = await apiPost(alicePage, ALICE_KEY, "/ui/licenses/issued", {
      content_id: `no_revoke_${TS}`,
      content_type: "music",
      license_mode: "blanket",
      profit_share_pct: 5,
      title: "No Revoke Test",
    });
    expect(issueResp.status()).toBe(200);
    const issued = await issueResp.json();

    // Bob tries to revoke Alice's license
    const resp = await apiPost(
      bobPage,
      BOB_KEY,
      `/ui/licenses/issued/${issued.issued_license_id}/revoke?content_id=${encodeURIComponent(`no_revoke_${TS}`)}`,
      { reason: "I want to" },
    );
    expect(resp.status()).toBe(403);
  });
});
