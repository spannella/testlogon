/**
 * E2E tests for ENTERPRISE-003 Organization / Team Workspaces.
 *
 * Sections:
 *   92  — Org CRUD API                  (6 tests)
 *   93  — Member management API          (7 tests)
 *   94  — Org file space API             (4 tests)
 *   95  — Org calendar API               (4 tests)
 *   96  — Org billing API                (5 tests)
 *   97  — Orgs UI page                   (4 tests)
 *   98  — Cross-org isolation            (3 tests)
 *
 * Auth:
 *   Alice — e2e_alice@test.local  (creates orgs, owner)
 *   Bob   — e2e_bob@test.local    (invited member)
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
import { usingCpp, cppResetUserOrgs } from "./helpers/cpp-seed";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ALICE_ID = "alice";
const BOB_ID   = "bob";
const TS       = Date.now();

// ── Session bootstrap ────────────────────────────────────────────────────────

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

// ── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate(
    (uid: string) => {
      const state = { userId: uid, accessToken: null, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    session.user_sub,
  );
}

function csrfFor(identity: string): string {
  return getSessions()[identity].csrf_token;
}

async function apiGet(page: Page, identity: string, path: string) {
  return page.request.get(`${BASE}${path}`, {
    headers: { "x-csrf-token": csrfFor(identity) },
  });
}

async function apiPost(page: Page, identity: string, path: string, body: object) {
  return page.request.post(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": csrfFor(identity) },
  });
}

async function apiPatch(page: Page, identity: string, path: string, body: object) {
  return page.request.patch(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": csrfFor(identity) },
  });
}

async function apiDelete(page: Page, identity: string, path: string) {
  return page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": csrfFor(identity) },
  });
}

// ── Multipart file upload helper ─────────────────────────────────────────────

async function apiUploadFile(
  page: Page,
  identity: string,
  orgId: string,
  filename: string,
  content: string,
) {
  return page.request.post(`${BASE}/ui/orgs/${orgId}/files/upload`, {
    headers: { "x-csrf-token": csrfFor(identity) },
    multipart: {
      file: {
        name: filename,
        mimeType: "text/plain",
        buffer: Buffer.from(content, "utf-8"),
      },
    },
  });
}

// Under cpp, orgs persist in moto across runs and the spec never deletes the
// orgs it creates, so Alice/Bob eventually cross ORG_MAX_PER_USER and every
// section's beforeAll create_org 409s. Reap each fixture's owned orgs once up
// front so each run starts under the cap. No-op on the Python path.
test.beforeAll(() => {
  if (!usingCpp()) return;
  const sessions = loadSessions();
  for (const id of [ALICE_ID, BOB_ID]) {
    const sub = sessions[id]?.user_sub;
    if (sub) cppResetUserOrgs(sub);
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 92 — Org CRUD API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("92 — Org CRUD API", () => {
  let alicePage: Page;
  let orgId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("92.1 Alice creates an organization", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/orgs", {
      name: `E2E Org ${TS}`,
      description: "Created by E2E test",
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.org_id).toBeTruthy();
    expect(body.name).toBe(`E2E Org ${TS}`);
    expect(body.owner_user_sub).toBe(getSessions()[ALICE_ID].user_sub);
    expect(body.status).toBe("active");
    expect(body.member_count).toBe(1);
    orgId = body.org_id;
  });

  test("92.2 Alice lists her organizations", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, "/ui/orgs");
    expect(resp.status()).toBe(200);
    const orgs = await resp.json();
    const found = orgs.find((o: any) => o.org_id === orgId);
    expect(found).toBeTruthy();
    expect(found.name).toBe(`E2E Org ${TS}`);
    expect(found.org_role).toBe("owner");
  });

  test("92.3 Alice gets the organization by ID", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, `/ui/orgs/${orgId}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.org_id).toBe(orgId);
    expect(body.slug).toBeTruthy();
  });

  test("92.4 Alice updates the organization name", async () => {
    const resp = await apiPatch(alicePage, ALICE_ID, `/ui/orgs/${orgId}`, {
      name: `E2E Org Updated ${TS}`,
      description: "Updated desc",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.name).toBe(`E2E Org Updated ${TS}`);
  });

  test("92.5 Non-member cannot access the org", async () => {
    // Bob is not a member yet
    const bobPage = await alicePage.context().browser()!.newPage();
    await injectAuth(bobPage, BOB_ID);
    const resp = await apiGet(bobPage, BOB_ID, `/ui/orgs/${orgId}`);
    expect(resp.status()).toBe(403);
    await bobPage.close();
  });

  test("92.6 Alice archives the organization", async () => {
    // Create a throwaway org to archive
    const createResp = await apiPost(alicePage, ALICE_ID, "/ui/orgs", {
      name: `Archive Test ${TS}`,
    });
    expect(createResp.status()).toBe(201);
    const archiveOrgId = (await createResp.json()).org_id;

    const resp = await apiDelete(alicePage, ALICE_ID, `/ui/orgs/${archiveOrgId}`);
    expect(resp.status()).toBe(204);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 93 — Member management API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("93 — Member management API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let orgId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);

    // Create org for this section
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/orgs", {
      name: `Members Test Org ${TS}`,
    });
    expect(resp.status()).toBe(201);
    orgId = (await resp.json()).org_id;
  });
  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("93.1 Alice lists members (only herself)", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, `/ui/orgs/${orgId}/members`);
    expect(resp.status()).toBe(200);
    const members = await resp.json();
    expect(members.length).toBeGreaterThanOrEqual(1);
    const alice = members.find((m: any) => m.user_sub === getSessions()[ALICE_ID].user_sub);
    expect(alice).toBeTruthy();
    expect(alice.org_role).toBe("owner");
  });

  test("93.2 Alice invites and Bob accepts", async () => {
    const bobSub = getSessions()[BOB_ID].user_sub;
    const invResp = await apiPost(alicePage, ALICE_ID, `/ui/orgs/${orgId}/members/invite`, {
      email: bobSub,
      org_role: "member",
    });
    expect(invResp.status()).toBe(201);
    const inv = await invResp.json();
    expect(inv.invite_id).toBeTruthy();
    expect(inv.token).toBeTruthy();
    expect(inv.org_role).toBe("member");

    // Bob accepts the invite
    const accResp = await apiPost(bobPage, BOB_ID, `/ui/orgs/invites/${inv.invite_id}/accept`, {
      token: inv.token,
    });
    expect(accResp.status()).toBe(200);
    const body = await accResp.json();
    expect(body.org_role).toBe("member");
    expect(body.status).toBe("active");
  });

  test("93.3 Bob can now see the org", async () => {
    const resp = await apiGet(bobPage, BOB_ID, `/ui/orgs/${orgId}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.name).toBe(`Members Test Org ${TS}`);
  });

  test("93.4 Alice changes Bob's role to admin", async () => {
    const bobSub = getSessions()[BOB_ID].user_sub;
    // Ensure Bob is a member (may need re-invite if retried)
    const membersResp = await apiGet(alicePage, ALICE_ID, `/ui/orgs/${orgId}/members`);
    const members = await membersResp.json();
    const bobMember = members.find((m: any) => m.user_sub === bobSub);
    if (!bobMember) {
      // Re-invite and accept Bob (retry scenario)
      const invResp = await apiPost(alicePage, ALICE_ID, `/ui/orgs/${orgId}/members/invite`, {
        email: bobSub,
        org_role: "member",
      });
      const inv = await invResp.json();
      await apiPost(bobPage, BOB_ID, `/ui/orgs/invites/${inv.invite_id}/accept`, {
        token: inv.token,
      });
    }

    const resp = await apiPatch(alicePage, ALICE_ID, `/ui/orgs/${orgId}/members/${bobSub}/role`, {
      org_role: "admin",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.org_role).toBe("admin");
  });

  test("93.5 Duplicate invite returns 409", async () => {
    const bobSub = getSessions()[BOB_ID].user_sub;
    // Ensure Bob is a member first
    const membersResp = await apiGet(alicePage, ALICE_ID, `/ui/orgs/${orgId}/members`);
    const members = await membersResp.json();
    const bobMember = members.find((m: any) => m.user_sub === bobSub);
    if (!bobMember) {
      const invResp = await apiPost(alicePage, ALICE_ID, `/ui/orgs/${orgId}/members/invite`, {
        email: bobSub,
        org_role: "member",
      });
      const inv = await invResp.json();
      await apiPost(bobPage, BOB_ID, `/ui/orgs/invites/${inv.invite_id}/accept`, {
        token: inv.token,
      });
    }

    const resp = await apiPost(alicePage, ALICE_ID, `/ui/orgs/${orgId}/members/invite`, {
      email: bobSub,
      org_role: "member",
    });
    expect(resp.status()).toBe(409);
  });

  test("93.6 Alice removes Bob from the org", async () => {
    const bobSub = getSessions()[BOB_ID].user_sub;
    // Ensure Bob is a member first
    const membersResp = await apiGet(alicePage, ALICE_ID, `/ui/orgs/${orgId}/members`);
    const members = await membersResp.json();
    const bobMember = members.find((m: any) => m.user_sub === bobSub);
    if (!bobMember) {
      const invResp = await apiPost(alicePage, ALICE_ID, `/ui/orgs/${orgId}/members/invite`, {
        email: bobSub,
        org_role: "member",
      });
      const inv = await invResp.json();
      await apiPost(bobPage, BOB_ID, `/ui/orgs/invites/${inv.invite_id}/accept`, {
        token: inv.token,
      });
    }

    const resp = await apiDelete(alicePage, ALICE_ID, `/ui/orgs/${orgId}/members/${bobSub}`);
    expect(resp.status()).toBe(204);

    // Verify Bob can no longer access the org
    const checkResp = await apiGet(bobPage, BOB_ID, `/ui/orgs/${orgId}`);
    expect(checkResp.status()).toBe(403);
  });

  test("93.7 Owner cannot be removed", async () => {
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    const resp = await apiDelete(alicePage, ALICE_ID, `/ui/orgs/${orgId}/members/${aliceSub}`);
    // Remove member endpoint returns 409 for owner
    expect(resp.status()).toBe(409);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 94 — Org file space API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("94 — Org file space API", () => {
  let alicePage: Page;
  let orgId: string;
  let nodeId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Create org for files testing
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/orgs", {
      name: `Files Test Org ${TS}`,
    });
    expect(resp.status()).toBe(201);
    orgId = (await resp.json()).org_id;
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("94.1 Upload a file to org space", async () => {
    const resp = await apiUploadFile(
      alicePage,
      ALICE_ID,
      orgId,
      `org_test_${TS}.txt`,
      `Hello from org file test ${TS}`,
    );
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.node_id).toBeTruthy();
    expect(body.name).toBe(`org_test_${TS}.txt`);
    expect(body.uploaded_by).toBe(getSessions()[ALICE_ID].user_sub);
    nodeId = body.node_id;
  });

  test("94.2 List files in org space", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, `/ui/orgs/${orgId}/files`);
    expect(resp.status()).toBe(200);
    const files = await resp.json();
    const found = files.find((f: any) => f.node_id === nodeId);
    expect(found).toBeTruthy();
    expect(found.name).toBe(`org_test_${TS}.txt`);
  });

  test("94.3 Download a file from org space", async () => {
    const resp = await alicePage.request.get(
      `${BASE}/ui/orgs/${orgId}/files/${nodeId}/download`,
      { headers: { "x-csrf-token": csrfFor(ALICE_ID) } },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.text();
    expect(body).toContain(`Hello from org file test ${TS}`);
  });

  test("94.4 Delete a file from org space", async () => {
    const resp = await apiDelete(alicePage, ALICE_ID, `/ui/orgs/${orgId}/files/${nodeId}`);
    expect(resp.status()).toBe(204);

    // Verify deleted file no longer appears in listing
    const listResp = await apiGet(alicePage, ALICE_ID, `/ui/orgs/${orgId}/files`);
    const files = await listResp.json();
    const found = files.find((f: any) => f.node_id === nodeId);
    expect(found).toBeFalsy();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 95 — Org calendar API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("95 — Org calendar API", () => {
  let alicePage: Page;
  let orgId: string;
  let eventId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);

    const resp = await apiPost(alicePage, ALICE_ID, "/ui/orgs", {
      name: `Calendar Test Org ${TS}`,
    });
    expect(resp.status()).toBe(201);
    orgId = (await resp.json()).org_id;
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("95.1 Create an org event", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/orgs/${orgId}/calendar/events`, {
      title: `Team Standup ${TS}`,
      start_time: "2026-06-01T09:00:00Z",
      end_time: "2026-06-01T09:30:00Z",
      description: "Daily standup",
      all_day: false,
      attendees: [],
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.event_id).toBeTruthy();
    expect(body.title).toBe(`Team Standup ${TS}`);
    expect(body.org_id).toBe(orgId);
    eventId = body.event_id;
  });

  test("95.2 List org events", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, `/ui/orgs/${orgId}/calendar/events`);
    expect(resp.status()).toBe(200);
    const events = await resp.json();
    const found = events.find((e: any) => e.event_id === eventId);
    expect(found).toBeTruthy();
    expect(found.title).toBe(`Team Standup ${TS}`);
  });

  test("95.3 Update an org event", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/orgs/${orgId}/calendar/events/${eventId}`,
      { title: `Updated Standup ${TS}` },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.title).toBe(`Updated Standup ${TS}`);
  });

  test("95.4 Delete an org event", async () => {
    const resp = await apiDelete(
      alicePage,
      ALICE_ID,
      `/ui/orgs/${orgId}/calendar/events/${eventId}`,
    );
    expect(resp.status()).toBe(204);

    // Verify it's gone
    const listResp = await apiGet(alicePage, ALICE_ID, `/ui/orgs/${orgId}/calendar/events`);
    const events = await listResp.json();
    const found = events.find((e: any) => e.event_id === eventId);
    expect(found).toBeFalsy();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 96 — Org billing API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("96 — Org billing API", () => {
  let alicePage: Page;
  let orgId: string;
  let pmId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);

    const resp = await apiPost(alicePage, ALICE_ID, "/ui/orgs", {
      name: `Billing Test Org ${TS}`,
    });
    expect(resp.status()).toBe(201);
    orgId = (await resp.json()).org_id;
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("96.1 Add a payment method to org", async () => {
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/orgs/${orgId}/billing/payment-methods`,
      { provider: "stripe", type: "card", last4: "1234", brand: "visa" },
    );
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.payment_method_id).toBeTruthy();
    expect(body.last4).toBe("1234");
    pmId = body.payment_method_id;
  });

  test("96.2 List org payment methods", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, `/ui/orgs/${orgId}/billing/payment-methods`);
    expect(resp.status()).toBe(200);
    const pms = await resp.json();
    expect(pms.length).toBeGreaterThanOrEqual(1);
    const found = pms.find((p: any) => p.payment_method_id === pmId);
    expect(found).toBeTruthy();
  });

  test("96.3 Set default payment method", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/orgs/${orgId}/billing/set-default`, {
      payment_method_id: pmId,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
  });

  test("96.4 Get billing history (empty)", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, `/ui/orgs/${orgId}/billing/history`);
    expect(resp.status()).toBe(200);
    const history = await resp.json();
    expect(Array.isArray(history)).toBe(true);
  });

  test("96.5 Remove a payment method", async () => {
    const resp = await apiDelete(
      alicePage,
      ALICE_ID,
      `/ui/orgs/${orgId}/billing/payment-methods/${pmId}`,
    );
    expect(resp.status()).toBe(204);

    // Verify it's gone
    const listResp = await apiGet(alicePage, ALICE_ID, `/ui/orgs/${orgId}/billing/payment-methods`);
    const pms = await listResp.json();
    const found = pms.find((p: any) => p.payment_method_id === pmId);
    expect(found).toBeFalsy();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 97 — Orgs UI page
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("97 — Orgs UI page", () => {
  let alicePage: Page;
  let uiOrgId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("97.1 OrgsPage loads and shows heading", async () => {
    await alicePage.goto(`${BASE}/orgs`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByRole("heading", { name: "Organizations" })).toBeVisible({ timeout: 10_000 });
  });

  test("97.2 Create organization via UI dialog", async () => {
    // Ensure we're on the orgs page
    await alicePage.goto(`${BASE}/orgs`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByRole("heading", { name: "Organizations" })).toBeVisible();

    // Click create button
    await alicePage.getByRole("button", { name: /Create Organization/i }).click();
    await expect(alicePage.getByRole("heading", { name: "Create Organization" })).toBeVisible();

    // Fill form
    await alicePage.getByLabel("Name").fill(`UI Org ${TS}`);
    await alicePage.getByLabel("Description").fill("Created via UI test");

    // Submit and capture the API response
    const [createResp] = await Promise.all([
      alicePage.waitForResponse((r) => r.url().includes("/ui/orgs") && r.request().method() === "POST"),
      alicePage.getByRole("button", { name: "Create" }).click(),
    ]);
    expect(createResp.status()).toBe(201);
    const body = await createResp.json();
    uiOrgId = body.org_id;
  });

  test("97.3 New org appears in the list", async () => {
    // Ensure we're on the orgs page
    await alicePage.goto(`${BASE}/orgs`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByText(`UI Org ${TS}`)).toBeVisible();
  });

  test("97.4 Navigate to org dashboard", async () => {
    // Ensure we're on the orgs page first
    if (!uiOrgId) {
      // If retry, create the org via API
      const resp = await apiPost(alicePage, ALICE_ID, "/ui/orgs", {
        name: `UI Org ${TS}`,
        description: "Created via UI test (retry)",
      });
      if (resp.status() === 201) {
        uiOrgId = (await resp.json()).org_id;
      }
    }
    await alicePage.goto(`${BASE}/orgs`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByText(`UI Org ${TS}`)).toBeVisible();

    // Click on the org card
    await alicePage.getByText(`UI Org ${TS}`).first().click();
    await alicePage.waitForURL(`**/orgs/**`);

    // Check the dashboard tabs exist
    await expect(alicePage.getByRole("tab", { name: "Overview" })).toBeVisible();
    await expect(alicePage.getByRole("tab", { name: "Members" })).toBeVisible();
    await expect(alicePage.getByRole("tab", { name: "Files" })).toBeVisible();
    await expect(alicePage.getByRole("tab", { name: "Calendar" })).toBeVisible();
    await expect(alicePage.getByRole("tab", { name: "Billing" })).toBeVisible();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 98 — Cross-org isolation
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("98 — Cross-org isolation", () => {
  let alicePage: Page;
  let bobPage: Page;
  let aliceOrgId: string;
  let bobOrgId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);

    // Alice creates her org
    const aResp = await apiPost(alicePage, ALICE_ID, "/ui/orgs", {
      name: `Alice Isolation Org ${TS}`,
    });
    expect(aResp.status()).toBe(201);
    aliceOrgId = (await aResp.json()).org_id;

    // Bob creates his org
    const bResp = await apiPost(bobPage, BOB_ID, "/ui/orgs", {
      name: `Bob Isolation Org ${TS}`,
    });
    expect(bResp.status()).toBe(201);
    bobOrgId = (await bResp.json()).org_id;

    // Upload a file to Alice's org
    await apiUploadFile(alicePage, ALICE_ID, aliceOrgId, `alice_secret_${TS}.txt`, "Alice secret data");
  });
  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("98.1 Bob cannot access Alice's org", async () => {
    const resp = await apiGet(bobPage, BOB_ID, `/ui/orgs/${aliceOrgId}`);
    expect(resp.status()).toBe(403);
  });

  test("98.2 Bob cannot list Alice's org files", async () => {
    const resp = await apiGet(bobPage, BOB_ID, `/ui/orgs/${aliceOrgId}/files`);
    expect(resp.status()).toBe(403);
  });

  test("98.3 Bob cannot access Alice's org events", async () => {
    const resp = await apiGet(bobPage, BOB_ID, `/ui/orgs/${aliceOrgId}/calendar/events`);
    expect(resp.status()).toBe(403);
  });
});
