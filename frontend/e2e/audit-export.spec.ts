/**
 * ENTERPRISE-004 — Audit Log Export E2E tests
 *
 * Uses root session for admin endpoints.
 * Tests: create CSV/NDJSON export, list exports, get export, download export,
 *        non-root 403, date range exceeding max, empty date range,
 *        source filter, action filter.
 */
import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ── Constants ────────────────────────────────────────────────────────────

const API = "http://localhost:8000";
const API_PREFIX = "ui/admin/audit-exports";

// ── Session bootstrap ────────────────────────────────────────────────────

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

let _adminSessions: Record<string, AdminSessionData> | null = null;

function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _adminSessions = JSON.parse(raw);
  }
  return _adminSessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

// ── Request helpers ──────────────────────────────────────────────────────

async function apiPost(
  page: Page,
  identity: string,
  urlPath: string,
  body: Record<string, unknown>,
) {
  const sess = getAdminSessions()[identity];
  const resp = await page.request.post(`${API}/${urlPath}`, {
    data: body,
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
  const status = resp.status();
  let respBody: any = null;
  try { respBody = await resp.json(); } catch { /* noop */ }
  return { status, body: respBody };
}

async function apiGet(page: Page, urlPath: string) {
  const resp = await page.request.get(`${API}/${urlPath}`);
  const status = resp.status();
  let respBody: any = null;
  let text = "";
  try {
    text = await resp.text();
    respBody = JSON.parse(text);
  } catch {
    /* noop - text is available for non-JSON responses */
  }
  return { status, body: respBody, text };
}

// ── Tests ────────────────────────────────────────────────────────────────

const NOW = Math.floor(Date.now() / 1000);
const FROM_DATE = NOW - 30 * 86400;
const TO_DATE = NOW;

test.describe("Audit Log Export", () => {
  let rootPage: Page;
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await alicePage.context().close();
  });

  // -- Section 1: Create CSV export job --

  let csvExportId: string;

  test("1.1 Create CSV export job", async () => {
    const result = await apiPost(rootPage, "root", API_PREFIX, {
      categories: ["auth"],
      format: "csv",
      from_date: FROM_DATE,
      to_date: TO_DATE,
    });
    expect(result.status).toBe(201);
    expect(result.body.export_id).toBeTruthy();
    expect(result.body.status).toBe("completed");
    expect(result.body.categories).toEqual(["auth"]);
    expect(result.body.format).toBe("csv");
    expect(result.body.from_date).toBe(FROM_DATE);
    expect(result.body.to_date).toBe(TO_DATE);
    expect(result.body.created_by).toBeTruthy();
    csvExportId = result.body.export_id;
  });

  // -- Section 2: Create NDJSON export job --

  let ndjsonExportId: string;

  test("2.1 Create NDJSON export job", async () => {
    const result = await apiPost(rootPage, "root", API_PREFIX, {
      categories: ["auth", "admin"],
      format: "ndjson",
      from_date: FROM_DATE,
      to_date: TO_DATE,
    });
    expect(result.status).toBe(201);
    expect(result.body.export_id).toBeTruthy();
    expect(result.body.status).toBe("completed");
    expect(result.body.format).toBe("ndjson");
    expect(result.body.categories).toEqual(["auth", "admin"]);
    ndjsonExportId = result.body.export_id;
  });

  // -- Section 3: List exports shows the created jobs --

  test("3.1 List exports shows created jobs", async () => {
    const result = await apiGet(rootPage, API_PREFIX);
    expect(result.status).toBe(200);
    expect(result.body.exports).toBeDefined();
    expect(Array.isArray(result.body.exports)).toBe(true);

    const ids = result.body.exports.map((e: any) => e.export_id);
    expect(ids).toContain(csvExportId);
    expect(ids).toContain(ndjsonExportId);
  });

  // -- Section 4: Get export status returns complete --

  test("4.1 Get export status returns completed", async () => {
    const result = await apiGet(rootPage, `${API_PREFIX}/${csvExportId}`);
    expect(result.status).toBe(200);
    expect(result.body.export_id).toBe(csvExportId);
    expect(result.body.status).toBe("completed");
    expect(result.body.event_count).toBeGreaterThanOrEqual(0);
    expect(result.body.created_at).toBeGreaterThan(0);
  });

  // -- Section 5: Download export returns content --

  test("5.1 Download CSV export returns content", async () => {
    const result = await apiGet(rootPage, `${API_PREFIX}/${csvExportId}/download`);
    expect(result.status).toBe(200);
    // CSV should have a header row at minimum
    expect(result.text).toContain("event_id");
    expect(result.text).toContain("event_type");
    expect(result.text).toContain("event_action");
  });

  test("5.2 Download NDJSON export returns content", async () => {
    const result = await apiGet(rootPage, `${API_PREFIX}/${ndjsonExportId}/download`);
    expect(result.status).toBe(200);
    // NDJSON content: each line (if any data) should be JSON parseable
    const lines = result.text.trim().split("\n").filter((l: string) => l.trim());
    if (lines.length > 0) {
      const firstLine = JSON.parse(lines[0]);
      expect(firstLine.event_id).toBeDefined();
      expect(firstLine.event_type).toBeDefined();
    }
  });

  // -- Section 6: Non-root user gets 403 --

  test("6.1 Non-root user gets 403 on create", async () => {
    const result = await apiPost(alicePage, "alice", API_PREFIX, {
      categories: ["auth"],
      format: "csv",
      from_date: FROM_DATE,
      to_date: TO_DATE,
    });
    expect(result.status).toBe(403);
  });

  test("6.2 Non-root user gets 403 on list", async () => {
    const result = await apiGet(alicePage, API_PREFIX);
    expect(result.status).toBe(403);
  });

  // -- Section 7: Date range exceeding max returns 400 --

  test("7.1 Date range exceeding max returns 400", async () => {
    const result = await apiPost(rootPage, "root", API_PREFIX, {
      categories: ["auth"],
      format: "csv",
      from_date: FROM_DATE,
      to_date: FROM_DATE + 91 * 86400,
    });
    expect(result.status).toBe(400);
    expect(result.body.detail).toContain("exceeds maximum");
  });

  // -- Section 8: Empty date range returns 400 --

  test("8.1 Empty/zero date range returns 400", async () => {
    const result = await apiPost(rootPage, "root", API_PREFIX, {
      categories: ["auth"],
      format: "csv",
      from_date: 0,
      to_date: 0,
    });
    expect(result.status).toBe(400);
  });

  // -- Section 9: Export with source filter --

  test("9.1 Export with single source filter", async () => {
    const result = await apiPost(rootPage, "root", API_PREFIX, {
      categories: ["billing"],
      format: "ndjson",
      from_date: FROM_DATE,
      to_date: TO_DATE,
    });
    expect(result.status).toBe(201);
    expect(result.body.status).toBe("completed");
    expect(result.body.categories).toEqual(["billing"]);
  });

  // -- Section 10: Export with invalid category returns 400 --

  test("10.1 Export with invalid category returns 400", async () => {
    const result = await apiPost(rootPage, "root", API_PREFIX, {
      categories: ["nonexistent_category"],
      format: "csv",
      from_date: FROM_DATE,
      to_date: TO_DATE,
    });
    expect(result.status).toBe(400);
    expect(result.body.detail).toContain("Unknown categories");
  });
});
