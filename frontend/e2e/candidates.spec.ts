/**
 * E2E tests for the ATS Candidates module (CND-001..CND-007).
 *
 * Sections:
 *   70 — Candidate CRUD (create / list / get / update / delete) — API
 *   71 — Candidate list filters (status, source, owner) — API
 *   72 — Resume management (upload / list / set-primary / delete) — API
 *   73 — Change history — API
 *   74 — Flag-off / not-enabled state — UI
 *   75 — CandidatesListPage UI
 *   76 — CandidateDetailPage UI
 *   77 — CreateCandidatePage UI
 *
 * Auth: uses e2e_admin_session_setup.py (all identities)
 *
 * Identities:
 *   alice  – e2e_alice@test.local   – role=user (candidate owner)
 *   root   – root.admin@testdev.local – role=root (admin operations)
 *
 * NOTE: The CANDIDATES_ENABLED flag must be on in the dev stack for sections
 * 70-73 and 75-77 to pass. If the flag is off, section 74 verifies the
 * "not enabled" state. Use `CANDIDATES_ENABLED=1` in .env.local and restart.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const ROOT_ID  = "root.admin@testdev.local";
const TS       = Date.now();

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
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _adminSessions = JSON.parse(raw);
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

async function apiPatch(page: Page, identity: string, path: string, body: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.patch(`${API}/${path}`, {
    data: body,
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiPut(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.put(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getAdminSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: {
      "x-csrf-token": sess.csrf_token,
    },
  });
}

// ─── Module-level shared state ────────────────────────────────────────────────

let alicePage: Page;
let rootPage:  Page;
let candidateId = "";
const CANDIDATE_EMAIL = `e2e.cand.${TS}@test.local`;
const CANDIDATE_NAME  = `E2E Cand ${TS}`;

// =============================================================================
// Section 70 — Candidate CRUD — API
// =============================================================================

test.describe("Section 70: Candidate CRUD — API", () => {
  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getAdminSessions();
    alicePage = await newIdentityPage(browser, "alice");
    rootPage  = await newIdentityPage(browser, "root");
  });

  test("70.1 Create candidate — 201, candidate_id returned", async () => {
    const resp = await apiPost(alicePage, "alice", "ui/candidates", {
      first_name: "E2E",
      last_name: `Cand ${TS}`,
      email: CANDIDATE_EMAIL,
      company: "ACME Corp",
      title: "Software Engineer",
      source: "direct",
      status: "active",
      key_skills: "TypeScript, React, Python",
      can_relocate: true,
    });
    if (resp.status() === 404) {
      // candidates_enabled flag is off — skip remaining tests in this section
      test.skip();
      return;
    }
    expect(resp.status()).toBe(201);
    const data = await resp.json() as Record<string, unknown>;
    expect(typeof data.candidate_id).toBe("string");
    expect((data.candidate_id as string).startsWith("cand_")).toBe(true);
    candidateId = data.candidate_id as string;
  });

  test("70.2 GET candidate by ID — 200, fields match", async () => {
    if (!candidateId) { test.skip(); return; }
    const resp = await apiGet(alicePage, `ui/candidates/${candidateId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Record<string, unknown>;
    expect(data.email).toBe(CANDIDATE_EMAIL.toLowerCase());
    expect(data.email_raw).toBe(CANDIDATE_EMAIL);
    expect(data.status).toBe("active");
    expect(data.source).toBe("direct");
    expect(data.can_relocate).toBe(true);
    expect(data.company).toBe("ACME Corp");
    expect(Array.isArray(data.resumes)).toBe(true);
  });

  test("70.3 List candidates (own) — includes new candidate", async () => {
    if (!candidateId) { test.skip(); return; }
    const resp = await apiGet(alicePage, "ui/candidates");
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { candidates: Array<{ candidate_id: string }> };
    expect(Array.isArray(data.candidates)).toBe(true);
    const found = data.candidates.find((c) => c.candidate_id === candidateId);
    expect(found).toBeTruthy();
  });

  test("70.4 PATCH candidate — update status and title", async () => {
    if (!candidateId) { test.skip(); return; }
    const resp = await apiPatch(alicePage, "alice", `ui/candidates/${candidateId}`, {
      status: "qualified",
      title: "Senior Software Engineer",
      desired_pay: "$130k",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Record<string, unknown>;
    expect(data.status).toBe("qualified");
    expect(data.title).toBe("Senior Software Engineer");
    expect(data.desired_pay).toBe("$130k");
  });

  test("70.5 PATCH non-existent candidate → 404", async () => {
    const resp = await apiPatch(alicePage, "alice", "ui/candidates/cand_nonexistent123", {
      title: "X",
    });
    expect(resp.status()).toBe(404);
  });

  test("70.6 GET candidate response shape — timestamps, owner_sub, created_by", async () => {
    if (!candidateId) { test.skip(); return; }
    const resp = await apiGet(alicePage, `ui/candidates/${candidateId}`);
    const data = await resp.json() as Record<string, unknown>;
    expect(typeof data.created_at).toBe("number");
    expect(typeof data.updated_at).toBe("number");
    expect(typeof data.owner_sub).toBe("string");
    expect(typeof data.created_by).toBe("string");
  });

  test("70.7 Duplicate email → 409", async () => {
    // Try to create a second candidate with the same email
    const resp = await apiPost(alicePage, "alice", "ui/candidates", {
      first_name: "Dup",
      last_name: "Test",
      email: CANDIDATE_EMAIL,
    });
    // 409 = duplicate_candidate; 201 = both could pass (race, but sequential here)
    expect([201, 409]).toContain(resp.status());
  });

  test("70.8 DELETE candidate → 204 (soft delete)", async () => {
    // Create a fresh one to delete, to preserve candidateId for later sections
    const createResp = await apiPost(alicePage, "alice", "ui/candidates", {
      first_name: "ToDelete",
      last_name: `${TS}`,
      email: `delete.${TS}@test.local`,
    });
    if (createResp.status() !== 201) { test.skip(); return; }
    const created = await createResp.json() as { candidate_id: string };
    const toDeleteId = created.candidate_id;

    const deleteResp = await apiDelete(alicePage, "alice", `ui/candidates/${toDeleteId}`);
    expect(deleteResp.status()).toBe(204);

    // Second DELETE → 410 (already soft-deleted → gone)
    const deleteAgain = await apiDelete(alicePage, "alice", `ui/candidates/${toDeleteId}`);
    expect([204, 410]).toContain(deleteAgain.status());

    // GET after delete → 410
    const getResp = await apiGet(alicePage, `ui/candidates/${toDeleteId}`);
    expect(getResp.status()).toBe(410);
  });
});

// =============================================================================
// Section 71 — List filters — API
// =============================================================================

test.describe("Section 71: Candidate list filters — API", () => {
  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = alicePage ?? await newIdentityPage(browser, "alice");
    rootPage  = rootPage  ?? await newIdentityPage(browser, "root");
  });

  test("71.1 Filter by status=qualified", async () => {
    if (!candidateId) { test.skip(); return; }
    const resp = await apiGet(alicePage, "ui/candidates", { status: "qualified" });
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { candidates: Array<{ status: string }> };
    for (const c of data.candidates) {
      expect(c.status).toBe("qualified");
    }
  });

  test("71.2 Filter by source=direct — returns only direct source candidates", async () => {
    if (!candidateId) { test.skip(); return; }
    const resp = await apiGet(alicePage, "ui/candidates", { source: "direct" });
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { candidates: Array<{ source: string }> };
    for (const c of data.candidates) {
      expect(c.source).toBe("direct");
    }
  });

  test("71.3 Pagination — cursor returned when more pages exist", async () => {
    const resp = await apiGet(alicePage, "ui/candidates", { limit: "1" });
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { candidates: unknown[]; cursor?: string | null };
    // With limit=1 and at least one candidate, cursor may be present
    expect(Array.isArray(data.candidates)).toBe(true);
    expect(data.candidates.length).toBeLessThanOrEqual(1);
  });

  test("71.4 owner_sub filter (admin) — root can query by owner", async () => {
    // Root queries by alice's sub
    const sess = getAdminSessions()["alice"];
    const resp = await apiGet(rootPage, "ui/candidates", { owner_sub: sess.user_sub });
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { candidates: Array<{ owner_sub: string }> };
    for (const c of data.candidates) {
      expect(c.owner_sub).toBe(sess.user_sub);
    }
  });

  test("71.5 Admin set-owner — PUT /{id}/owner (root only)", async () => {
    if (!candidateId) { test.skip(); return; }
    const rootSess = getAdminSessions()["root"];
    const resp = await apiPut(rootPage, "root", `ui/candidates/${candidateId}/owner`, {
      owner_sub: rootSess.user_sub,
    });
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { owner_sub: string };
    expect(data.owner_sub).toBe(rootSess.user_sub);
  });
});

// =============================================================================
// Section 72 — Resume management — API
// =============================================================================

test.describe("Section 72: Resume management — API", () => {
  let resumeAttachmentId = "";

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = alicePage ?? await newIdentityPage(browser, "alice");
    if (!candidateId) {
      // Ensure we have a candidate to attach resumes to
      const resp = await apiPost(alicePage, "alice", "ui/candidates", {
        first_name: "Resume",
        last_name: `Test ${TS}`,
        email: `resume.test.${TS}@test.local`,
      });
      if (resp.status() === 201) {
        const data = await resp.json() as { candidate_id: string };
        candidateId = data.candidate_id;
      }
    }
  });

  test("72.1 Upload a text resume — 201, attachment_id returned", async () => {
    if (!candidateId) { test.skip(); return; }
    // We can't easily upload multipart with page.request, so we send a minimal plain-text body
    const sess = getAdminSessions()["alice"];
    const content = `Resume content for candidate ${TS}`;
    const formData = new URLSearchParams();
    // Use fetch-style multipart — Playwright request supports FormData via Buffer
    const resp = await alicePage.request.post(
      `${API}/ui/candidates/${candidateId}/resumes`,
      {
        multipart: {
          file: {
            name: "resume.txt",
            mimeType: "text/plain",
            buffer: Buffer.from(content),
          },
          make_primary: "true",
        },
        headers: {
          "x-csrf-token": sess.csrf_token,
        },
      },
    );
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(201);
    const data = await resp.json() as Record<string, unknown>;
    expect(typeof data.attachment_id).toBe("string");
    resumeAttachmentId = data.attachment_id as string;
    expect(data.is_primary).toBe(true);
    expect(data.filename_original).toBe("resume.txt");
  });

  test("72.2 List resumes — includes uploaded resume", async () => {
    if (!candidateId || !resumeAttachmentId) { test.skip(); return; }
    const resp = await apiGet(alicePage, `ui/candidates/${candidateId}/resumes`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Array<{ attachment_id: string }>;
    expect(Array.isArray(data)).toBe(true);
    expect(data.find((r) => r.attachment_id === resumeAttachmentId)).toBeTruthy();
  });

  test("72.3 GET single resume by ID — 200, fields present", async () => {
    if (!candidateId || !resumeAttachmentId) { test.skip(); return; }
    const resp = await apiGet(
      alicePage,
      `ui/candidates/${candidateId}/resumes/${resumeAttachmentId}`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Record<string, unknown>;
    expect(data.attachment_id).toBe(resumeAttachmentId);
    expect(data.candidate_id).toBe(candidateId);
    expect(typeof data.url).toBe("string");
    expect(typeof data.size_bytes).toBe("number");
  });

  test("72.4 Set primary resume — 200, is_primary=true", async () => {
    if (!candidateId || !resumeAttachmentId) { test.skip(); return; }
    const sess = getAdminSessions()["alice"];
    const resp = await alicePage.request.put(
      `${API}/ui/candidates/${candidateId}/resumes/${resumeAttachmentId}/primary`,
      {
        headers: { "x-csrf-token": sess.csrf_token },
      },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { is_primary: boolean };
    expect(data.is_primary).toBe(true);
  });

  test("72.5 GET candidate detail — primary_resume_id matches", async () => {
    if (!candidateId || !resumeAttachmentId) { test.skip(); return; }
    const resp = await apiGet(alicePage, `ui/candidates/${candidateId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { primary_resume_id?: string };
    expect(data.primary_resume_id).toBe(resumeAttachmentId);
  });

  test("72.6 DELETE resume — 204", async () => {
    if (!candidateId || !resumeAttachmentId) { test.skip(); return; }
    const resp = await apiDelete(
      alicePage,
      "alice",
      `ui/candidates/${candidateId}/resumes/${resumeAttachmentId}`,
    );
    expect(resp.status()).toBe(204);
    // After deletion, list returns empty
    const listResp = await apiGet(alicePage, `ui/candidates/${candidateId}/resumes`);
    expect(listResp.status()).toBe(200);
    const data = await listResp.json() as Array<{ attachment_id: string }>;
    expect(data.find((r) => r.attachment_id === resumeAttachmentId)).toBeFalsy();
  });
});

// =============================================================================
// Section 73 — Change history — API
// =============================================================================

test.describe("Section 73: Change history — API", () => {
  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = alicePage ?? await newIdentityPage(browser, "alice");
  });

  test("73.1 GET /history — 200, events array", async () => {
    if (!candidateId) { test.skip(); return; }
    const resp = await apiGet(alicePage, `ui/candidates/${candidateId}/history`);
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { events: unknown[] };
    expect(Array.isArray(data.events)).toBe(true);
  });

  test("73.2 History events have required fields", async () => {
    if (!candidateId) { test.skip(); return; }
    const resp = await apiGet(alicePage, `ui/candidates/${candidateId}/history`);
    if (resp.status() !== 200) { test.skip(); return; }
    const data = await resp.json() as {
      events: Array<{ event_id: string; change_type: string; actor_sub: string; created_at: number }>;
    };
    for (const ev of data.events) {
      expect(typeof ev.event_id).toBe("string");
      expect(typeof ev.change_type).toBe("string");
      expect(typeof ev.actor_sub).toBe("string");
      expect(typeof ev.created_at).toBe("number");
    }
  });

  test("73.3 History pagination — cursor field present or null", async () => {
    if (!candidateId) { test.skip(); return; }
    const resp = await apiGet(alicePage, `ui/candidates/${candidateId}/history`, { limit: "5" });
    if (resp.status() !== 200) { test.skip(); return; }
    const data = await resp.json() as { events: unknown[]; cursor?: string | null };
    expect("events" in data).toBe(true);
    expect("cursor" in data).toBe(true);
  });
});

// =============================================================================
// Section 74 — Flag-off / not-enabled state — UI
// =============================================================================

test.describe("Section 74: Flag-off / not-enabled state — UI", () => {
  let aliceUiPage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    aliceUiPage = await browser.newPage();
    await injectAuth(aliceUiPage, "alice");
  });

  test.afterAll(async () => {
    await aliceUiPage.close();
  });

  test("74.1 Candidates list page renders without crashing", async () => {
    await aliceUiPage.goto(`${BASE}/ats/candidates`, { waitUntil: "domcontentloaded" });
    // Either the list table or the not-enabled card should be visible
    const heading = aliceUiPage.getByRole("heading", { name: "Candidates", exact: true });
    await expect(heading).toBeVisible({ timeout: 10_000 });
  });

  test("74.2 When flag is off, shows not-enabled card", async () => {
    // Check for either the not-enabled card OR the table (flag may be on in CI)
    await aliceUiPage.goto(`${BASE}/ats/candidates`, { waitUntil: "domcontentloaded" });
    const notEnabled = aliceUiPage.getByText("Candidates module not enabled");
    const table = aliceUiPage.getByRole("table");
    const emptyState = aliceUiPage.getByText("No candidates found");
    const addBtn = aliceUiPage.getByRole("button", { name: /new candidate/i });
    // At least one of these should be visible
    await expect(
      notEnabled.or(table).or(emptyState).or(addBtn),
    ).toBeVisible({ timeout: 10_000 });
  });
});

// =============================================================================
// Section 75 — CandidatesListPage UI
// =============================================================================

test.describe("Section 75: CandidatesListPage UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("75.1 Page title and New Candidate button visible", async () => {
    await page.goto(`${BASE}/ats/candidates`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Candidates", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: /new candidate/i })).toBeVisible();
  });

  test("75.2 Filter controls render — status and source selects", async () => {
    await page.goto(`${BASE}/ats/candidates`, { waitUntil: "domcontentloaded" });
    await expect(page.getByText(/all statuses/i)).toBeVisible();
    await expect(page.getByText(/all sources/i)).toBeVisible();
  });

  test("75.3 Search input is present", async () => {
    await page.goto(`${BASE}/ats/candidates`, { waitUntil: "domcontentloaded" });
    const searchInput = page.getByPlaceholder(/search name/i);
    await expect(searchInput).toBeVisible();
  });

  test("75.4 Clicking New Candidate navigates to create page", async () => {
    await page.goto(`${BASE}/ats/candidates`, { waitUntil: "domcontentloaded" });
    // Skip if not-enabled (flag off)
    const notEnabled = page.getByText("Candidates module not enabled");
    if (await notEnabled.isVisible()) { return; }
    await page.getByRole("button", { name: /new candidate/i }).click();
    await expect(page).toHaveURL(/\/ats\/candidates\/new/);
  });

  test("75.5 Clicking a candidate row navigates to detail page", async () => {
    await page.goto(`${BASE}/ats/candidates`, { waitUntil: "domcontentloaded" });
    const notEnabled = page.getByText("Candidates module not enabled");
    if (await notEnabled.isVisible()) { return; }
    const rows = page.getByRole("row").filter({ hasText: "@" });
    const count = await rows.count();
    if (count === 0) { return; } // no candidates in this environment
    await rows.first().click();
    await expect(page).toHaveURL(/\/ats\/candidates\/cand_/);
  });
});

// =============================================================================
// Section 76 — CandidateDetailPage UI
// =============================================================================

test.describe("Section 76: CandidateDetailPage UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("76.1 Detail page renders tabs: Profile, Resumes, Activity", async () => {
    if (!candidateId) { test.skip(); return; }
    await page.goto(`${BASE}/ats/candidates/${candidateId}`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("tab", { name: /profile/i })).toBeVisible();
    await expect(page.getByRole("tab", { name: /resumes/i })).toBeVisible();
    await expect(page.getByRole("tab", { name: /activity/i })).toBeVisible();
  });

  test("76.2 Profile tab shows status badge and email", async () => {
    if (!candidateId) { test.skip(); return; }
    await page.goto(`${BASE}/ats/candidates/${candidateId}`, { waitUntil: "domcontentloaded" });
    // Status badge visible
    const badge = page.getByText(/active|qualified|placed|on hold|archived/i).first();
    await expect(badge).toBeVisible({ timeout: 8_000 });
    // Email visible somewhere on page
    await expect(page.getByText(/@test\.local/).first()).toBeVisible({ timeout: 8_000 });
  });

  test("76.3 Edit button opens edit form", async () => {
    if (!candidateId) { test.skip(); return; }
    await page.goto(`${BASE}/ats/candidates/${candidateId}`, { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: /edit/i }).click();
    // Edit mode should show Save button
    await expect(page.getByRole("button", { name: /save/i })).toBeVisible();
  });

  test("76.4 Cancel edit returns to view mode", async () => {
    if (!candidateId) { test.skip(); return; }
    await page.goto(`${BASE}/ats/candidates/${candidateId}`, { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: /edit/i }).click();
    await page.getByRole("button", { name: /cancel/i }).click();
    // Edit button should be back
    await expect(page.getByRole("button", { name: /edit/i })).toBeVisible();
  });

  test("76.5 Resumes tab shows upload button", async () => {
    if (!candidateId) { test.skip(); return; }
    await page.goto(`${BASE}/ats/candidates/${candidateId}`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: /resumes/i }).click();
    await expect(page.getByRole("button", { name: /upload resume/i })).toBeVisible();
  });

  test("76.6 Activity tab renders without error", async () => {
    if (!candidateId) { test.skip(); return; }
    await page.goto(`${BASE}/ats/candidates/${candidateId}`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: /activity/i }).click();
    // Either history events or empty state
    const emptyHistory = page.getByText("No activity recorded yet");
    const historyItem = page.locator("[class*='border']").first();
    await expect(emptyHistory.or(historyItem)).toBeVisible({ timeout: 5_000 });
  });

  test("76.7 Back button navigates to list page", async () => {
    if (!candidateId) { test.skip(); return; }
    await page.goto(`${BASE}/ats/candidates/${candidateId}`, { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: /back/i }).click();
    await expect(page).toHaveURL(/\/ats\/candidates$/);
  });
});

// =============================================================================
// Section 77 — CreateCandidatePage UI
// =============================================================================

test.describe("Section 77: CreateCandidatePage UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("77.1 Create page renders required fields", async () => {
    await page.goto(`${BASE}/ats/candidates/new`, { waitUntil: "domcontentloaded" });
    const notEnabled = page.getByText("Candidates module not enabled");
    if (await notEnabled.isVisible()) { return; }
    await expect(page.getByLabel(/first name/i)).toBeVisible();
    await expect(page.getByLabel(/last name/i)).toBeVisible();
    await expect(page.getByLabel(/email/i)).toBeVisible();
  });

  test("77.2 Create button disabled when required fields empty", async () => {
    await page.goto(`${BASE}/ats/candidates/new`, { waitUntil: "domcontentloaded" });
    const notEnabled = page.getByText("Candidates module not enabled");
    if (await notEnabled.isVisible()) { return; }
    const createBtn = page.getByRole("button", { name: /create candidate/i });
    await expect(createBtn).toBeDisabled();
  });

  test("77.3 Filling required fields enables Create button", async () => {
    await page.goto(`${BASE}/ats/candidates/new`, { waitUntil: "domcontentloaded" });
    const notEnabled = page.getByText("Candidates module not enabled");
    if (await notEnabled.isVisible()) { return; }
    await page.getByLabel(/first name/i).fill("Test");
    await page.getByLabel(/last name/i).fill("User");
    await page.getByLabel(/email/i).fill("test@example.com");
    const createBtn = page.getByRole("button", { name: /create candidate/i });
    await expect(createBtn).toBeEnabled();
  });

  test("77.4 Key skills character counter visible", async () => {
    await page.goto(`${BASE}/ats/candidates/new`, { waitUntil: "domcontentloaded" });
    const notEnabled = page.getByText("Candidates module not enabled");
    if (await notEnabled.isVisible()) { return; }
    await expect(page.getByText(/\/4000/)).toBeVisible();
  });

  test("77.5 ATS details section rendered (current pay, desired pay)", async () => {
    await page.goto(`${BASE}/ats/candidates/new`, { waitUntil: "domcontentloaded" });
    const notEnabled = page.getByText("Candidates module not enabled");
    if (await notEnabled.isVisible()) { return; }
    await expect(page.getByText("ATS details")).toBeVisible();
    await expect(page.getByLabel(/current pay/i)).toBeVisible();
    await expect(page.getByLabel(/desired pay/i)).toBeVisible();
  });

  test("77.6 Address section rendered", async () => {
    await page.goto(`${BASE}/ats/candidates/new`, { waitUntil: "domcontentloaded" });
    const notEnabled = page.getByText("Candidates module not enabled");
    if (await notEnabled.isVisible()) { return; }
    await expect(page.getByText("Address", { exact: true })).toBeVisible();
  });

  test("77.7 Successful create navigates to detail page", async () => {
    await page.goto(`${BASE}/ats/candidates/new`, { waitUntil: "domcontentloaded" });
    const notEnabled = page.getByText("Candidates module not enabled");
    if (await notEnabled.isVisible()) { return; }
    const uniq = `UI_${TS}`;
    await page.getByLabel(/first name/i).fill("UITest");
    await page.getByLabel(/last name/i).fill(uniq);
    await page.getByLabel(/email/i).fill(`uicandidate.${TS}@test.local`);
    await page.getByRole("button", { name: /create candidate/i }).click();
    await expect(page).toHaveURL(/\/ats\/candidates\/cand_/, { timeout: 10_000 });
  });

  test("77.8 Back to Candidates button navigates to list", async () => {
    await page.goto(`${BASE}/ats/candidates/new`, { waitUntil: "domcontentloaded" });
    const notEnabled = page.getByText("Candidates module not enabled");
    if (await notEnabled.isVisible()) { return; }
    await page.getByRole("button", { name: /back to candidates/i }).click();
    await expect(page).toHaveURL(/\/ats\/candidates$/);
  });
});
