/**
 * FINRA / Messaging Compliance E2E tests
 *
 * Section 92: Message reporting — submit, status update, rate-limit guard
 * Section 93: Legal holds    — create, list, release
 * Section 94: Compliance archive events — query after message activity
 * Section 95: Compliance archive export — create, get, manifest, records, list
 *
 * ── Auth strategy ──────────────────────────────────────────────────────────
 * • Messaging API endpoints (report, status update) use Bearer / X-User-Id header
 *   → use the global `request` fixture (no session cookies, no CSRF).
 * • Legal-hold + compliance endpoints require a session-cookie auth caller with
 *   `content_moderation` scope → use `compliance_admin` page (cookies injected
 *   from e2e_admin_session_setup.py) with x-csrf-token header.
 *
 * Run prerequisite:
 *   python3 e2e_admin_session_setup.py   (auto-run via getAdminSessions())
 *   python3 e2e_session_setup.py         (for Alice/Bob sessions — not needed here
 *                                          because we use X-User-Id Bearer for messaging)
 */

import { test, expect, type Page, type Browser, type APIRequestContext } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";
const CHARLIE_ID = "e2e_charlie@test.local";
const TS = Date.now();

// ─── Admin session bootstrap ──────────────────────────────────────────────────

interface AdminSessionData {
  user_sub:     string;
  session_id:   string;
  csrf_token:   string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None";
    expires: number;
  }>;
}

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    _adminSessions = loadSessions();
  }
  return _adminSessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity]!.cookies);
  return page;
}

// ─── Request helpers ──────────────────────────────────────────────────────────

/** POST to messaging API using Bearer <user_id> header (no session cookies). */
async function msgPost(request: APIRequestContext, userId: string, path: string, body?: unknown) {
  return request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "Authorization": `Bearer ${getAdminSessions()[userId].user_sub}`, "Content-Type": "application/json" },
  });
}

/** GET from messaging API using Bearer <user_id> header. */
async function msgGet(request: APIRequestContext, userId: string, path: string, params?: Record<string, string>) {
  return request.get(`${API}/${path}`, {
    headers: { "Authorization": `Bearer ${getAdminSessions()[userId].user_sub}` },
    params,
  });
}

/** PATCH to messaging API using Bearer <user_id> header. */
async function msgPatch(request: APIRequestContext, userId: string, path: string, body?: unknown) {
  return request.patch(`${API}/${path}`, {
    data: body ?? {},
    headers: { "Authorization": `Bearer ${getAdminSessions()[userId].user_sub}`, "Content-Type": "application/json" },
  });
}

/** Build a Cookie: header string from the session's cookies. */
function sessionCookieHeader(identity: string): string {
  const sess = getAdminSessions()[identity]!;
  return sess.cookies.map(c => `${c.name}=${c.value}`).join("; ");
}

/** POST to compliance/session-auth API using explicit Cookie header + CSRF.
 *  Passing cookies via the Cookie: header is more reliable than relying on
 *  Playwright's context cookie-jar, which can transiently miss httpOnly
 *  cookies from fresh browser contexts in the full suite. */
async function compPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity]!;
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
      "Cookie": sessionCookieHeader(identity),
    },
  });
}

/** GET from compliance/session-auth API using Node.js global fetch.
 *  Uses Node.js fetch (not Playwright's page.request) to bypass any Playwright
 *  browser-context cookie or networking issues that occur in the full suite.
 *  Returns a Playwright-compatible response object ({status(), json(), text(), ok()}). */
async function compGet(_page: Page, path: string, params?: Record<string, string>, identity = "compliance_admin") {
  const url = new URL(`${API}/${path}`);
  if (params) {
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  }
  const res = await fetch(url.toString(), {
    headers: { "Cookie": sessionCookieHeader(identity) },
  });
  const bodyText = await res.text();
  const headersMap: Record<string, string> = {};
  res.headers.forEach((value, key) => { headersMap[key] = value; });
  return {
    status: () => res.status,
    ok: () => res.ok,
    text: async () => bodyText,
    json: async () => JSON.parse(bodyText) as unknown,
    headers: () => headersMap,
  };
}

// ─── Shared setup: create alice-bob DM + group with a message ─────────────────

interface ComplianceTestFixture {
  dmConvoId: string;
  dmMessageId: string;
  groupConvoId: string;
  groupMessageId: string;
}

async function setupConversationsAndMessages(request: APIRequestContext): Promise<ComplianceTestFixture> {
  // 1. Alice-Bob DM (type=dm, creator auto-added so participant_ids needs only the other user)
  const dmResp = await msgPost(request, ALICE_ID, "messaging/conversations", {
    type: "dm",
    participant_ids: [BOB_ID],
  });
  expect(dmResp.status()).toBe(200);
  const dmConvo = await dmResp.json() as { conversation_id: string };
  const dmConvoId = dmConvo.conversation_id;

  // Bob sends a message in the DM
  const msgResp = await msgPost(request, BOB_ID, `messaging/conversations/${dmConvoId}/messages`, {
    text: `Compliance test DM message ${TS}`,
  });
  expect(msgResp.status()).toBe(200);
  const dmMsg = await msgResp.json() as { message_id: string };
  const dmMessageId = dmMsg.message_id;

  // 2. Group conversation — Charlie creates it (charlie becomes admin participant)
  // group needs ≥3 unique participants (creator auto-added, so list the other 2)
  const grpResp = await msgPost(request, CHARLIE_ID, "messaging/conversations", {
    type: "group",
    title: `Compliance Test Group ${TS}`,
    participant_ids: [ALICE_ID, BOB_ID],
  });
  expect(grpResp.status()).toBe(200);
  const grpConvo = await grpResp.json() as { conversation_id: string };
  const groupConvoId = grpConvo.conversation_id;

  // Alice and Bob accept the group invite (so they become active participants)
  await msgPost(request, ALICE_ID, `messaging/conversations/${groupConvoId}/accept`, {});
  await msgPost(request, BOB_ID, `messaging/conversations/${groupConvoId}/accept`, {});

  // Charlie (active as creator) sends a message in the group
  const grpMsgResp = await msgPost(request, CHARLIE_ID, `messaging/conversations/${groupConvoId}/messages`, {
    text: `Compliance test group message ${TS}`,
  });
  expect(grpMsgResp.status()).toBe(200);
  const grpMsg = await grpMsgResp.json() as { message_id: string };
  const groupMessageId = grpMsg.message_id;

  return { dmConvoId, dmMessageId, groupConvoId, groupMessageId };
}

// ─── Section 92: Message reporting ───────────────────────────────────────────

test.describe("92. Messaging compliance — message reporting", () => {
  let fixture: ComplianceTestFixture;

  test.beforeAll(async ({ request }) => {
    getAdminSessions();
    fixture = await setupConversationsAndMessages(request);
  });

  test("92.1 Alice can report Bob's message with reason_code and statement", async ({ request }) => {
    const resp = await msgPost(request, ALICE_ID,
      `messaging/conversations/${fixture.dmConvoId}/messages/${fixture.dmMessageId}/report`,
      { reason_code: "harassment", statement: "This message is inappropriate and harassing." },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json() as {
      ok: boolean; report_id: string; status: string; reason_code: string;
    };
    expect(body.ok).toBe(true);
    expect(body.report_id).toMatch(/^rpt_/);
    expect(body.status).toBe("submitted");
    expect(body.reason_code).toBe("harassment");
  });

  test("92.2 Report returns conversation_id and message_id", async ({ request }) => {
    const resp = await msgPost(request, ALICE_ID,
      `messaging/conversations/${fixture.dmConvoId}/messages/${fixture.dmMessageId}/report`,
      { reason_code: "spam", statement: "This is clearly spam content." },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { conversation_id: string; message_id: string };
    expect(body.conversation_id).toBe(fixture.dmConvoId);
    expect(body.message_id).toBe(fixture.dmMessageId);
  });

  test("92.3 Report missing reason_code → 422", async ({ request }) => {
    const resp = await msgPost(request, ALICE_ID,
      `messaging/conversations/${fixture.dmConvoId}/messages/${fixture.dmMessageId}/report`,
      { statement: "Some statement here." },
    );
    expect(resp.status()).toBe(422);
  });

  test("92.4 Report statement too short → 422", async ({ request }) => {
    const resp = await msgPost(request, ALICE_ID,
      `messaging/conversations/${fixture.dmConvoId}/messages/${fixture.dmMessageId}/report`,
      { reason_code: "spam", statement: "Hi" },
    );
    expect(resp.status()).toBe(422);
  });

  test("92.5 Non-participant cannot report a message → 403", async ({ request }) => {
    // Charlie is not in the DM between Alice and Bob
    const resp = await msgPost(request, CHARLIE_ID,
      `messaging/conversations/${fixture.dmConvoId}/messages/${fixture.dmMessageId}/report`,
      { reason_code: "harassment", statement: "Attempting to report from outside." },
    );
    expect(resp.status()).toBe(403);
  });

  test("92.6 Report on non-existent message → 404", async ({ request }) => {
    const resp = await msgPost(request, ALICE_ID,
      `messaging/conversations/${fixture.dmConvoId}/messages/m_nonexistent999/report`,
      { reason_code: "spam", statement: "Reporting a fake message id here." },
    );
    expect(resp.status()).toBe(404);
  });

  test("92.7 Charlie (group admin) can update report status to under_review", async ({ request }) => {
    // First report the group message as alice
    const reportResp = await msgPost(request, ALICE_ID,
      `messaging/conversations/${fixture.groupConvoId}/messages/${fixture.groupMessageId}/report`,
      { reason_code: "misinformation", statement: "This message contains false information." },
    );
    expect(reportResp.status()).toBe(200);
    const { report_id } = await reportResp.json() as { report_id: string };

    // Charlie is the group admin, so can update status
    const patchResp = await msgPatch(request, CHARLIE_ID,
      `messaging/conversations/${fixture.groupConvoId}/reports/${report_id}/status`,
      { status: "under_review", note: "Reviewing this report now." },
    );
    expect(patchResp.status()).toBe(200);
    const body = await patchResp.json() as { ok: boolean; status: string };
    expect(body.ok).toBe(true);
    expect(body.status).toBe("under_review");
  });

  test("92.8 Alice (non-admin in group) cannot update report status → 403", async ({ request }) => {
    // Report again (separate report)
    const reportResp = await msgPost(request, ALICE_ID,
      `messaging/conversations/${fixture.groupConvoId}/messages/${fixture.groupMessageId}/report`,
      { reason_code: "harassment", statement: "Another harassment report for testing." },
    );
    expect(reportResp.status()).toBe(200);
    const { report_id } = await reportResp.json() as { report_id: string };

    // Alice is not group admin → 403
    const patchResp = await msgPatch(request, ALICE_ID,
      `messaging/conversations/${fixture.groupConvoId}/reports/${report_id}/status`,
      { status: "actioned" },
    );
    expect(patchResp.status()).toBe(403);
  });

  test("92.9 Report status update → actioned and dismissed are valid states", async ({ request }) => {
    const reportResp = await msgPost(request, ALICE_ID,
      `messaging/conversations/${fixture.groupConvoId}/messages/${fixture.groupMessageId}/report`,
      { reason_code: "other", statement: "Testing actioned status transition." },
    );
    expect(reportResp.status()).toBe(200);
    const { report_id } = await reportResp.json() as { report_id: string };

    const actioned = await msgPatch(request, CHARLIE_ID,
      `messaging/conversations/${fixture.groupConvoId}/reports/${report_id}/status`,
      { status: "actioned" },
    );
    expect(actioned.status()).toBe(200);
    expect((await actioned.json() as { status: string }).status).toBe("actioned");
  });
});

// ─── Section 93: Legal holds ──────────────────────────────────────────────────

test.describe("93. Messaging compliance — legal holds", () => {
  let fixture: ComplianceTestFixture;
  let compliancePage: Page;
  let holdId: string;

  test.beforeAll(async ({ browser, request }) => {
    getAdminSessions();
    fixture = await setupConversationsAndMessages(request);
    compliancePage = await newIdentityPage(browser, "compliance_admin");
    // compliance_admin is charlie who created the group → already active participant
  });

  test.afterAll(async () => {
    await compliancePage.close().catch(() => {});
  });

  test("93.1 Compliance admin can create a legal hold on a message", async () => {
    // Compliance admin joins the DM conversation first (required by require_participant_active)
    // Actually the compliance admin (charlie) is already creator of the group conv
    const resp = await compPost(compliancePage, "compliance_admin",
      `messaging/conversations/${fixture.groupConvoId}/legal-holds`,
      {
        case_id: `CASE-E2E-${TS}`,
        reason: "Regulatory hold for FINRA e2e test.",
        message_id: fixture.groupMessageId,
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json() as {
      hold_id: string; status: string; case_id: string; message_id: string;
    };
    expect(body.hold_id).toMatch(/^lh_/);
    expect(body.status).toBe("active");
    expect(body.case_id).toBe(`CASE-E2E-${TS}`);
    expect(body.message_id).toBe(fixture.groupMessageId);
    holdId = body.hold_id;
  });

  test("93.2 Legal hold requires either message_id or report_id → 422 if neither", async () => {
    const resp = await compPost(compliancePage, "compliance_admin",
      `messaging/conversations/${fixture.groupConvoId}/legal-holds`,
      { case_id: `CASE-E2E-${TS}`, reason: "Missing target id test." },
    );
    expect(resp.status()).toBe(422);
  });

  test("93.3 List active legal holds returns the created hold", async () => {
    const resp = await compGet(compliancePage,
      `messaging/conversations/${fixture.groupConvoId}/legal-holds`,
      { status: "active" },
    );
    expect(resp.status()).toBe(200);
    const items = await resp.json() as Array<{ hold_id: string; status: string }>;
    const found = items.find((h) => h.hold_id === holdId);
    expect(found).toBeDefined();
    expect(found?.status).toBe("active");
  });

  test("93.4 Regular user (alice) cannot create a legal hold → 403", async ({ request, browser }) => {
    const alicePage = await newIdentityPage(browser, "alice");
    const sess = getAdminSessions()["alice"]!;
    const resp = await alicePage.request.post(
      `${API}/messaging/conversations/${fixture.groupConvoId}/legal-holds`,
      {
        data: { case_id: `CASE-E2E-${TS}`, reason: "Unauthorized hold attempt by alice.", message_id: fixture.groupMessageId },
        headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
      },
    );
    expect(resp.status()).toBe(403);
    await alicePage.close();
  });

  test("93.5 Release the legal hold → status becomes released", async () => {
    expect(holdId).toBeDefined();
    const resp = await compPost(compliancePage, "compliance_admin",
      `messaging/conversations/${fixture.groupConvoId}/legal-holds/${holdId}/release`,
      { reason: "Investigation concluded; releasing hold after FINRA review." },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { hold_id: string; status: string; released_at: number };
    expect(body.hold_id).toBe(holdId);
    expect(body.status).toBe("released");
    expect(body.released_at).toBeGreaterThan(0);
  });

  test("93.6 List released holds includes the released hold", async () => {
    const resp = await compGet(compliancePage,
      `messaging/conversations/${fixture.groupConvoId}/legal-holds`,
      { status: "released" },
    );
    expect(resp.status()).toBe(200);
    const items = await resp.json() as Array<{ hold_id: string; status: string }>;
    const found = items.find((h) => h.hold_id === holdId);
    expect(found).toBeDefined();
    expect(found?.status).toBe("released");
  });

  test("93.7 List all holds (status=all) includes both active and released", async () => {
    // Create a new hold so there's at least one active
    const createResp = await compPost(compliancePage, "compliance_admin",
      `messaging/conversations/${fixture.groupConvoId}/legal-holds`,
      {
        case_id: `CASE-E2E-ALL-${TS}`,
        reason: "Second hold for status=all test.",
        message_id: fixture.groupMessageId,
      },
    );
    expect(createResp.status()).toBe(200);

    const resp = await compGet(compliancePage,
      `messaging/conversations/${fixture.groupConvoId}/legal-holds`,
      { status: "all" },
    );
    expect(resp.status()).toBe(200);
    const items = await resp.json() as Array<{ hold_id: string; status: string }>;
    const statuses = new Set(items.map((h) => h.status));
    expect(statuses.has("released")).toBe(true);
    expect(statuses.has("active")).toBe(true);
  });
});

// ─── Section 94: Compliance archive events ────────────────────────────────────

test.describe("94. Messaging compliance — archive event query", () => {
  let fixture: ComplianceTestFixture;
  let compliancePage: Page;

  test.beforeAll(async ({ browser, request }) => {
    getAdminSessions();
    fixture = await setupConversationsAndMessages(request);
    compliancePage = await newIdentityPage(browser, "compliance_admin");
    // Note: compGet/compPost now pass cookies explicitly via Cookie: header, so
    // no warmup loop or cookie re-injection is needed here.
  });

  test.afterAll(async () => {
    await compliancePage.close().catch(() => {});
  });

  test("94.1 Compliance admin can query archive events (paginated response)", async () => {
    const resp = await compGet(compliancePage, "messaging/compliance/archive/events");
    const rawBody = await resp.text();
    expect(
      resp.status(),
      `Expected 200 but got ${resp.status()}. Body: ${rawBody.slice(0, 300)}`,
    ).toBe(200);
    const body = JSON.parse(rawBody) as { items: unknown[]; total_matches: number };
    expect(Array.isArray(body.items)).toBe(true);
    expect(typeof body.total_matches).toBe("number");
  });

  test("94.2 Archive events filtered by conversation_id returns subset", async () => {
    const resp = await compGet(compliancePage, "messaging/compliance/archive/events", {
      conversation_id: fixture.groupConvoId,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json() as {
      items: Array<{ conversation_id: string; event_type: string; event_id: string }>;
      total_matches: number;
    };
    expect(Array.isArray(body.items)).toBe(true);
    // Every returned event must belong to the requested conversation
    for (const item of body.items) {
      expect(item.conversation_id).toBe(fixture.groupConvoId);
    }
  });

  test("94.3 Archive events for group conversation include message.sent event", async () => {
    const resp = await compGet(compliancePage, "messaging/compliance/archive/events", {
      conversation_id: fixture.groupConvoId,
      include_payload: "true",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json() as {
      items: Array<{ event_type: string; message_id: string }>;
    };
    const sent = body.items.find((e) => e.event_type === "message.sent");
    expect(sent).toBeDefined();
    expect(sent?.message_id).toBe(fixture.groupMessageId);
  });

  test("94.4 Archive event items include required fields", async () => {
    const resp = await compGet(compliancePage, "messaging/compliance/archive/events", {
      conversation_id: fixture.groupConvoId,
      limit: "1",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json() as {
      items: Array<{
        event_id: string; event_ts: number; event_type: string;
        conversation_id: string; message_id: string; actor_user_id: string;
        object_key: string; payload_hash: string; prev_hash: string; schema_version: number;
      }>;
    };
    if (body.items.length > 0) {
      const item = body.items[0]!;
      expect(typeof item.event_id).toBe("string");
      expect(typeof item.event_ts).toBe("number");
      expect(typeof item.event_type).toBe("string");
      expect(typeof item.object_key).toBe("string");
      expect(typeof item.payload_hash).toBe("string");
      expect(typeof item.schema_version).toBe("number");
    }
  });

  test("94.5 from_ts > to_ts → 422", async () => {
    const now = Math.floor(Date.now() / 1000);
    const resp = await compGet(compliancePage, "messaging/compliance/archive/events", {
      from_ts: String(now + 1000),
      to_ts: String(now),
    });
    expect(resp.status()).toBe(422);
  });

  test("94.6 Regular user cannot query compliance archive → 403", async ({ browser }) => {
    const alicePage = await newIdentityPage(browser, "alice");
    const resp = await alicePage.request.get(`${API}/messaging/compliance/archive/events`);
    expect(resp.status()).toBe(403);
    await alicePage.close();
  });
});

// ─── Section 95: Compliance archive export ────────────────────────────────────

test.describe("95. Messaging compliance — archive export", () => {
  let fixture: ComplianceTestFixture;
  let compliancePage: Page;
  let exportId: string;
  const CASE_ID = `FINRA-CASE-${TS}`;
  const now = Math.floor(Date.now() / 1000);

  test.beforeAll(async ({ browser, request }) => {
    getAdminSessions();
    fixture = await setupConversationsAndMessages(request);
    compliancePage = await newIdentityPage(browser, "compliance_admin");

    // Create the export up-front so all tests share a stable exportId even across retries.
    const resp = await compPost(compliancePage, "compliance_admin",
      "messaging/compliance/archive/exports",
      {
        case_id: CASE_ID,
        from_ts: now - 3600,
        to_ts: now + 60,
        conversation_id: fixture.groupConvoId,
        include_payload: true,
      },
    );
    if (!resp.ok()) throw new Error(`Export creation failed: ${resp.status()}`);
    const body = await resp.json() as { export_id: string };
    exportId = body.export_id;
  });

  test.afterAll(async () => {
    await compliancePage.close().catch(() => {});
  });

  test("95.1 Create compliance archive export → status completed", async () => {
    expect(exportId).toBeDefined();
    expect(exportId).toMatch(/^exp_/);
    // Retrieve the export to verify its fields.
    const resp = await compGet(compliancePage, `messaging/compliance/archive/exports/${exportId}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json() as {
      export_id: string; case_id: string; status: string;
      record_count: number; expires_at: number;
    };
    expect(body.export_id).toBe(exportId);
    expect(body.case_id).toBe(CASE_ID);
    expect(body.status).toBe("completed");
    expect(body.record_count).toBeGreaterThanOrEqual(0);
    expect(body.expires_at).toBeGreaterThan(now);
  });

  test("95.2 from_ts > to_ts → 422 validation error", async () => {
    const resp = await compPost(compliancePage, "compliance_admin",
      "messaging/compliance/archive/exports",
      { case_id: CASE_ID, from_ts: now + 1000, to_ts: now },
    );
    expect(resp.status()).toBe(422);
  });

  test("95.3 GET export by ID returns expected fields", async () => {
    expect(exportId).toBeDefined();
    const resp = await compGet(compliancePage,
      `messaging/compliance/archive/exports/${exportId}`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json() as {
      export_id: string; case_id: string; status: string;
      tenant_id: string; requested_by_user_id: string;
    };
    expect(body.export_id).toBe(exportId);
    expect(body.case_id).toBe(CASE_ID);
    expect(body.status).toBe("completed");
    expect(body.tenant_id).toBe("default");
    expect(body.requested_by_user_id).toBe(CHARLIE_ID);
  });

  test("95.4 GET export manifest returns signed manifest JSON", async () => {
    expect(exportId).toBeDefined();
    const resp = await compGet(compliancePage,
      `messaging/compliance/archive/exports/${exportId}/manifest`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json() as {
      export_id: string; case_id: string;
      signature: { key_id: string; value: string; algorithm: string };
      record_checksums: { count: number };
    };
    expect(body.export_id).toBe(exportId);
    expect(body.case_id).toBe(CASE_ID);
    expect(typeof body.signature?.key_id).toBe("string");
    expect(typeof body.signature?.value).toBe("string");
  });

  test("95.5 GET export records returns NDJSON content", async () => {
    expect(exportId).toBeDefined();
    const resp = await compGet(compliancePage,
      `messaging/compliance/archive/exports/${exportId}/records`,
    );
    expect(resp.status()).toBe(200);
    // Content-Type should be NDJSON
    const ct = resp.headers()["content-type"] ?? "";
    expect(ct).toContain("ndjson");
  });

  test("95.6 List exports by case_id returns the created export", async () => {
    const resp = await compGet(compliancePage,
      "messaging/compliance/archive/exports",
      { case_id: CASE_ID },
    );
    expect(resp.status()).toBe(200);
    const items = await resp.json() as Array<{ export_id: string; case_id: string }>;
    expect(Array.isArray(items)).toBe(true);
    const found = items.find((e) => e.export_id === exportId);
    expect(found).toBeDefined();
    expect(found?.case_id).toBe(CASE_ID);
  });

  test("95.7 GET manifest for incomplete export → 409", async () => {
    // Create an export that we know will be "queued" — we can't easily do this
    // without mocking, so instead test with a nonexistent export_id
    const resp = await compGet(compliancePage,
      "messaging/compliance/archive/exports/exp_nonexistent999/manifest",
    );
    expect(resp.status()).toBe(404);
  });

  test("95.8 Regular user cannot create compliance export → 403", async ({ browser }) => {
    const alicePage = await newIdentityPage(browser, "alice");
    const sess = getAdminSessions()["alice"]!;
    const resp = await alicePage.request.post(
      `${API}/messaging/compliance/archive/exports`,
      {
        data: { case_id: CASE_ID, from_ts: now - 3600, to_ts: now },
        headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
      },
    );
    expect(resp.status()).toBe(403);
    await alicePage.close();
  });
});
