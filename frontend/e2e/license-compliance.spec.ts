/**
 * E2E tests for LICENSE-006 — License Compliance & Verification.
 *
 * Section 483: Compliance Check API (4 tests)
 * Section 484: Content Flagging API (4 tests)
 * Section 485: Admin Compliance Management API (5 tests)
 * Section 486: Compliance Scan & Notification API (3 tests)
 *
 * Auth: role-bearing cookies from e2e_admin_session_setup.py. JSON POSTs carry
 * the x-csrf-token header (required by require_ui_session when the ui_session
 * cookie is present). Admin endpoints require admin/root.
 *
 * Deterministic license fixtures are built via the LICENSE-002 issuance API
 * (`/ui/licenses/issued`): a *blanket* license with no/future expiry → the
 * content is compliant; a blanket license with a PAST `expires_at` → the
 * content is `license_expired`. No direct DDB manipulation required.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const ALICE_ID = "e2e_alice@test.local";

interface AdminSessionData {
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

let _sessions: Record<string, AdminSessionData> | null = null;
function getSessions(): Record<string, AdminSessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}/${path}`);
}

/** Issue a blanket license on a content item via LICENSE-002. */
async function issueBlanketLicense(
  page: Page,
  identity: string,
  contentId: string,
  expiresAt?: number,
) {
  const r = await apiPost(page, identity, "ui/licenses/issued", {
    content_id: contentId,
    content_type: "video",
    license_mode: "blanket",
    title: "Compliance fixture",
    expires_at: expiresAt ?? null,
  });
  expect(r.status()).toBe(200);
  return (await r.json()) as Record<string, unknown>;
}

const TS = Date.now();
const NOW = Math.floor(Date.now() / 1000);
// Distinct content ids per run for isolation.
const COMPLIANT_CONTENT = `vid_ok_${TS}`;
const EXPIRED_CONTENT = `vid_exp_${TS}`;
const FLAG_CONTENT = `vid_flag_${TS}`;

// ─── 483. Compliance Check API ──────────────────────────────────────────────

test.describe("483. Compliance Check API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
    // Compliant fixture: active blanket license, no expiry.
    await issueBlanketLicense(alicePage, "alice", COMPLIANT_CONTENT);
    // Expired fixture: blanket license already past expiry.
    await issueBlanketLicense(alicePage, "alice", EXPIRED_CONTENT, NOW - 86400);
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("483.1 Check on content with active license returns compliant", async () => {
    const r = await apiPost(
      alicePage,
      "alice",
      `ui/licenses/compliance/content/${COMPLIANT_CONTENT}/check?content_type=video`,
    );
    expect(r.status()).toBe(200);
    const d = (await r.json()) as { compliance_status: string; issues: unknown[] };
    expect(d.compliance_status).toBe("compliant");
    expect(d.issues.length).toBe(0);
  });

  test("483.2 Check on content with expired license returns license_expired", async () => {
    const r = await apiPost(
      alicePage,
      "alice",
      `ui/licenses/compliance/content/${EXPIRED_CONTENT}/check?content_type=video`,
    );
    expect(r.status()).toBe(200);
    const d = (await r.json()) as {
      compliance_status: string;
      issues: Array<Record<string, unknown>>;
    };
    expect(d.compliance_status).toBe("license_expired");
    expect(d.issues.length).toBeGreaterThan(0);
    expect(d.issues[0].type).toBe("license_expired");
  });

  test("483.3 Creator compliance list shows content items", async () => {
    const r = await apiGet(alicePage, "ui/licenses/compliance/my-content");
    expect(r.status()).toBe(200);
    const d = (await r.json()) as {
      items: Array<{ content_id: string; compliance_status: string }>;
      summary: { total: number };
    };
    const ok = d.items.find((i) => i.content_id === COMPLIANT_CONTENT);
    const exp = d.items.find((i) => i.content_id === EXPIRED_CONTENT);
    expect(ok?.compliance_status).toBe("compliant");
    expect(exp?.compliance_status).toBe("license_expired");
    expect(d.summary.total).toBeGreaterThanOrEqual(2);
  });

  test("483.4 Content compliance refs returns license references", async () => {
    const r = await apiGet(
      alicePage,
      `ui/licenses/compliance/content/${EXPIRED_CONTENT}/refs`,
    );
    expect(r.status()).toBe(200);
    const d = (await r.json()) as { items: Array<Record<string, unknown>> };
    expect(d.items.length).toBeGreaterThan(0);
    expect(d.items[0].license_type).toBe("issued");
    expect(d.items[0].license_status).toBe("expired");
  });
});

// ─── 484. Content Flagging API ──────────────────────────────────────────────

test.describe("484. Content Flagging API", () => {
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
    bobPage = await newIdentityPage(browser, "bob");
    await issueBlanketLicense(alicePage, "alice", FLAG_CONTENT);
    await apiPost(
      alicePage,
      "alice",
      `ui/licenses/compliance/content/${FLAG_CONTENT}/check?content_type=video`,
    );
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("484.1 Viewer flags content for unlicensed music", async () => {
    const r = await apiPost(bobPage, "bob", "ui/licenses/compliance/flag", {
      content_id: FLAG_CONTENT,
      reason: "unlicensed_music",
    });
    expect(r.status()).toBe(200);
    const d = (await r.json()) as Record<string, unknown>;
    expect(d.status).toBe("open");
    expect(d.reason).toBe("unlicensed_music");
    expect(d.reporter_type).toBe("viewer");
  });

  test("484.2 Creator flags content with evidence", async () => {
    const r = await apiPost(bobPage, "bob", "ui/licenses/compliance/flag", {
      content_id: FLAG_CONTENT,
      reason: "copyright_claim",
      evidence: "Uses my track Sunset Drive at 1:30",
      reporter_type: "creator",
    });
    expect(r.status()).toBe(200);
    const d = (await r.json()) as Record<string, unknown>;
    expect(d.evidence).toBe("Uses my track Sunset Drive at 1:30");
    expect(d.reporter_type).toBe("creator");
  });

  test("484.3 Flagging escalates content compliance status to flagged", async () => {
    const r = await apiGet(
      alicePage,
      `ui/licenses/compliance/content/${FLAG_CONTENT}`,
    );
    expect(r.status()).toBe(200);
    const d = (await r.json()) as { compliance_status: string };
    expect(d.compliance_status).toBe("flagged");
  });

  test("484.4 Invalid flag reason is rejected", async () => {
    const r = await apiPost(bobPage, "bob", "ui/licenses/compliance/flag", {
      content_id: FLAG_CONTENT,
      reason: "invalid_reason",
    });
    expect(r.status()).toBe(400);
  });
});

// ─── 485. Admin Compliance Management API ────────────────────────────────────

test.describe("485. Admin Compliance Management API", () => {
  let alicePage: Page;
  let rootPage: Page;
  const ADMIN_CONTENT = `vid_admin_${TS}`;
  let flagId = "";

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
    rootPage = await newIdentityPage(browser, "root");
    // Build an expired-license issue + a flag for the admin queues.
    await issueBlanketLicense(alicePage, "alice", ADMIN_CONTENT, NOW - 86400);
    await apiPost(
      alicePage,
      "alice",
      `ui/licenses/compliance/content/${ADMIN_CONTENT}/check?content_type=video`,
    );
    const fr = await apiPost(alicePage, "alice", "ui/licenses/compliance/flag", {
      content_id: ADMIN_CONTENT,
      reason: "expired_license",
      reporter_type: "creator",
    });
    flagId = ((await fr.json()) as Record<string, string>).flag_id;
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await rootPage?.close();
  });

  test("485.1 Admin sees compliance issues in queue", async () => {
    const r = await apiGet(rootPage, "ui/admin/licenses/compliance/issues");
    expect(r.status()).toBe(200);
    const d = (await r.json()) as { items: Array<{ content_id: string }> };
    expect(d.items.some((i) => i.content_id === ADMIN_CONTENT)).toBe(true);
  });

  test("485.2 Admin sees open flags in flag queue", async () => {
    const r = await apiGet(
      rootPage,
      "ui/admin/licenses/compliance/flags?status=open",
    );
    expect(r.status()).toBe(200);
    const d = (await r.json()) as { items: Array<{ flag_id: string }> };
    expect(d.items.some((f) => f.flag_id === flagId)).toBe(true);
  });

  test("485.3 Admin resolves flag as dismissed", async () => {
    const r = await apiPost(
      rootPage,
      "root",
      `ui/admin/licenses/compliance/flags/${flagId}/resolve`,
      { content_id: ADMIN_CONTENT, resolution: "dismissed", notes: "no merit" },
    );
    expect(r.status()).toBe(200);
    const d = (await r.json()) as { status: string };
    expect(d.status).toBe("dismissed");

    const list = await apiGet(
      alicePage,
      `ui/licenses/compliance/content/${ADMIN_CONTENT}/flags?status=dismissed`,
    );
    const ld = (await list.json()) as { items: Array<{ flag_id: string }> };
    expect(ld.items.some((f) => f.flag_id === flagId)).toBe(true);
  });

  test("485.4 Admin updates content to action_required", async () => {
    const r = await apiPost(
      rootPage,
      "root",
      `ui/admin/licenses/compliance/content/${ADMIN_CONTENT}/status`,
      { new_status: "action_required", notes: "renew the license" },
    );
    expect(r.status()).toBe(200);
    const d = (await r.json()) as { compliance_status: string };
    expect(d.compliance_status).toBe("action_required");

    const detail = await apiGet(
      alicePage,
      `ui/licenses/compliance/content/${ADMIN_CONTENT}`,
    );
    const dd = (await detail.json()) as { compliance_status: string };
    expect(dd.compliance_status).toBe("action_required");
  });

  test("485.5 Non-admin cannot access admin compliance endpoints", async () => {
    const r = await apiGet(alicePage, "ui/admin/licenses/compliance/issues");
    expect(r.status()).toBe(403);
  });
});

// ─── 486. Compliance Scan & Notification API ─────────────────────────────────

test.describe("486. Compliance Scan & Notification API", () => {
  let alicePage: Page;
  let rootPage: Page;
  const SCAN_CONTENT = `vid_scan_${TS}`;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await rootPage?.close();
  });

  test("486.1 Admin triggers compliance scan", async () => {
    const r = await apiPost(rootPage, "root", "ui/admin/licenses/compliance/scan");
    expect(r.status()).toBe(200);
    const d = (await r.json()) as {
      checked: number;
      issues_found: number;
      alerts_sent: number;
    };
    expect(typeof d.checked).toBe("number");
    expect(typeof d.issues_found).toBe("number");
    expect(typeof d.alerts_sent).toBe("number");
  });

  test("486.2 Scan detects a newly expired license", async () => {
    // Content starts compliant (active blanket license, future expiry far out),
    // then we issue a SECOND blanket license already expired and re-scan.
    await issueBlanketLicense(alicePage, "alice", SCAN_CONTENT, NOW + 365 * 86400);
    const first = await apiPost(
      alicePage,
      "alice",
      `ui/licenses/compliance/content/${SCAN_CONTENT}/check?content_type=video`,
    );
    expect(((await first.json()) as { compliance_status: string }).compliance_status).toBe(
      "compliant",
    );

    // Add an expired license to the same content → next scan should flag it.
    await issueBlanketLicense(alicePage, "alice", SCAN_CONTENT, NOW - 86400);
    const scan = await apiPost(rootPage, "root", "ui/admin/licenses/compliance/scan");
    expect(scan.status()).toBe(200);

    const detail = await apiGet(
      alicePage,
      `ui/licenses/compliance/content/${SCAN_CONTENT}`,
    );
    const dd = (await detail.json()) as { compliance_status: string };
    expect(dd.compliance_status).toBe("license_expired");
  });

  test("486.3 Flagging content twice creates two flag records", async () => {
    await apiPost(alicePage, "alice", "ui/licenses/compliance/flag", {
      content_id: SCAN_CONTENT,
      reason: "unlicensed_music",
    });
    await apiPost(alicePage, "alice", "ui/licenses/compliance/flag", {
      content_id: SCAN_CONTENT,
      reason: "unlicensed_video",
    });
    const r = await apiGet(
      alicePage,
      `ui/licenses/compliance/content/${SCAN_CONTENT}/flags`,
    );
    const d = (await r.json()) as { items: unknown[] };
    expect(d.items.length).toBeGreaterThanOrEqual(2);
  });
});
