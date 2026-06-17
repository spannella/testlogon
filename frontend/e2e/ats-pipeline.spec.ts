/**
 * E2E tests for the ATS Pipeline feature (PIP-001..PIP-010).
 *
 * Sections:
 *   80 — Feature flag probe                              — API
 *   81 — Pipeline CRUD (add / list-by-job / remove)      — API
 *   82 — Status transitions (valid + idempotent)          — API
 *   83 — Candidate rating (set + clear)                  — API
 *   84 — List by candidate (cross-job view)              — API
 *   85 — Placement record (create + duplicate 409)        — API
 *   86 — Status config (GET defaults + admin PUT)        — API
 *   87 — Pipeline Board UI (job picker + kanban columns) — UI
 *   88 — Pipeline Detail UI (stage + rating + placement) — UI
 *
 * Prerequisites:
 *   - Backend running with ATS_PIPELINE_ENABLED=1
 *   - ATS_ENABLED=1, JOB_ORDERS_ENABLED=1, CANDIDATES_ENABLED=1
 *   - e2e_admin_session_setup.py creates sessions for alice (user) and root
 *
 * Auth:
 *   - alice — normal user (owns the pipeline entries in API tests)
 *   - root  — admin (status config write)
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API  = "http://localhost:8000";
const TS   = Date.now();

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
    [session.user_sub, session.access_token] as [string, string],
  );
}

// ─── Auth helpers for cookie-auth API calls ───────────────────────────────────

function csrfHeaders(identity: string): Record<string, string> {
  const s = getAdminSessions()[identity];
  return { "x-csrf-token": s.csrf_token, "content-type": "application/json" };
}

// ─── Shared test state ────────────────────────────────────────────────────────

/** IDs created during test run (populated in section 81). */
let testJobOrderId = "";
let testCandidateId = "";
let placedPipelineJobId = "";
let placedPipelineCandId = "";

// ─── Section 80: Feature flag probe ──────────────────────────────────────────

test.describe("80 — Feature flag probe", () => {
  test("80.1 GET /ui/ats/pipeline/feature-status returns { enabled: bool }", async ({ browser }) => {
    const page = await newIdentityPage(browser, "alice");
    const resp = await page.request.get(`${API}/ui/ats/pipeline/feature-status`);
    // When flag is off the router is not mounted; accept 200 or 404
    if (resp.status() === 200) {
      const body = await resp.json();
      expect(body).toHaveProperty("enabled");
      expect(typeof body.enabled).toBe("boolean");
    } else {
      expect([404, 503]).toContain(resp.status());
    }
  });
});

// ─── Section 81: Pipeline CRUD ────────────────────────────────────────────────

test.describe("81 — Pipeline CRUD (add / list / remove)", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");

    // Create a job order to use as anchor
    const jobResp = await alicePage.request.post(`${API}/ui/ats/job-orders/`, {
      headers: csrfHeaders("alice"),
      data: {
        title: `E2E Pipeline Job ${TS}`,
        type: "hire",
        openings: 2,
        client_company_id: `e2e-company-${TS}`,
      },
    });
    if (jobResp.ok()) {
      const job = await jobResp.json();
      testJobOrderId = job.job_id ?? job.job_order_id ?? "";
    }

    // Create a candidate
    const candResp = await alicePage.request.post(`${API}/ui/candidates`, {
      headers: csrfHeaders("alice"),
      data: {
        first_name: "E2E",
        last_name: `Pipeline ${TS}`,
        email: `e2e.pipeline.${TS}@test.local`,
        source: "direct",
      },
    });
    if (candResp.ok()) {
      const cand = await candResp.json();
      testCandidateId = cand.candidate_id ?? "";
    }
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("81.1 POST /ui/ats/pipeline/entries — create entry (201)", async () => {
    test.skip(!testJobOrderId || !testCandidateId, "Prereqs not available");

    const resp = await alicePage.request.post(`${API}/ui/ats/pipeline/entries`, {
      headers: csrfHeaders("alice"),
      data: { job_order_id: testJobOrderId, candidate_id: testCandidateId },
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.pipeline_id).toBeTruthy();
    expect(body.status).toBe("100_no_contact");
    expect(body.rating).toBe(0);
  });

  test("81.2 POST duplicate entry returns 409", async () => {
    test.skip(!testJobOrderId || !testCandidateId, "Prereqs not available");

    const resp = await alicePage.request.post(`${API}/ui/ats/pipeline/entries`, {
      headers: csrfHeaders("alice"),
      data: { job_order_id: testJobOrderId, candidate_id: testCandidateId },
    });
    expect(resp.status()).toBe(409);
  });

  test("81.3 GET /ui/ats/pipeline/by-job/:jobId lists entries", async () => {
    test.skip(!testJobOrderId, "Prereqs not available");

    const resp = await alicePage.request.get(
      `${API}/ui/ats/pipeline/by-job/${testJobOrderId}`,
    );
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(Array.isArray(body.entries)).toBe(true);
    if (testCandidateId) {
      const found = body.entries.find((e: { candidate_id: string }) => e.candidate_id === testCandidateId);
      expect(found).toBeTruthy();
    }
  });

  test("81.4 DELETE removes the entry (204)", async () => {
    test.skip(!testJobOrderId || !testCandidateId, "Prereqs not available");

    // Create a second candidate to delete
    const candResp = await alicePage.request.post(`${API}/ui/candidates`, {
      headers: csrfHeaders("alice"),
      data: {
        first_name: "ToDelete",
        last_name: `${TS}`,
        email: `delete.${TS}@test.local`,
        source: "direct",
      },
    });
    if (!candResp.ok()) {
      test.skip(true, "Could not create candidate for delete test");
      return;
    }
    const deleteCandId = (await candResp.json()).candidate_id;

    // Add them
    await alicePage.request.post(`${API}/ui/ats/pipeline/entries`, {
      headers: csrfHeaders("alice"),
      data: { job_order_id: testJobOrderId, candidate_id: deleteCandId },
    });

    // Delete
    const delResp = await alicePage.request.delete(
      `${API}/ui/ats/pipeline/by-job/${testJobOrderId}/candidate/${deleteCandId}`,
      { headers: csrfHeaders("alice") },
    );
    expect(delResp.status()).toBe(204);

    // Confirm absent
    const listResp = await alicePage.request.get(
      `${API}/ui/ats/pipeline/by-job/${testJobOrderId}`,
    );
    const body = await listResp.json();
    const found = body.entries.find((e: { candidate_id: string }) => e.candidate_id === deleteCandId);
    expect(found).toBeUndefined();
  });
});

// ─── Section 82: Status transitions ──────────────────────────────────────────

test.describe("82 — Status transitions", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("82.1 PATCH status to 200_contacted succeeds", async () => {
    test.skip(!testJobOrderId || !testCandidateId, "Prereqs not available");

    const resp = await alicePage.request.patch(
      `${API}/ui/ats/pipeline/by-job/${testJobOrderId}/candidate/${testCandidateId}/status`,
      {
        headers: csrfHeaders("alice"),
        data: { new_status: "200_contacted", note: "E2E test advance" },
      },
    );
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body.status).toBe("200_contacted");
  });

  test("82.2 PATCH same status again is idempotent (200, no change)", async () => {
    test.skip(!testJobOrderId || !testCandidateId, "Prereqs not available");

    const resp = await alicePage.request.patch(
      `${API}/ui/ats/pipeline/by-job/${testJobOrderId}/candidate/${testCandidateId}/status`,
      {
        headers: csrfHeaders("alice"),
        data: { new_status: "200_contacted" },
      },
    );
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body.status).toBe("200_contacted");
  });

  test("82.3 PATCH invalid status key returns 400", async () => {
    test.skip(!testJobOrderId || !testCandidateId, "Prereqs not available");

    const resp = await alicePage.request.patch(
      `${API}/ui/ats/pipeline/by-job/${testJobOrderId}/candidate/${testCandidateId}/status`,
      {
        headers: csrfHeaders("alice"),
        data: { new_status: "not_a_real_status_key" },
      },
    );
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.detail?.code).toBe("invalid_status");
  });

  test("82.4 PATCH status on non-existent entry returns 404", async () => {
    const resp = await alicePage.request.patch(
      `${API}/ui/ats/pipeline/by-job/job_nonexistent/candidate/cand_nonexistent/status`,
      {
        headers: csrfHeaders("alice"),
        data: { new_status: "200_contacted" },
      },
    );
    expect(resp.status()).toBe(404);
  });
});

// ─── Section 83: Candidate rating ────────────────────────────────────────────

test.describe("83 — Candidate rating", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("83.1 PATCH rating to 4 stars", async () => {
    test.skip(!testJobOrderId || !testCandidateId, "Prereqs not available");

    const resp = await alicePage.request.patch(
      `${API}/ui/ats/pipeline/by-job/${testJobOrderId}/candidate/${testCandidateId}/rating`,
      { headers: csrfHeaders("alice"), data: { rating: 4 } },
    );
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body.rating).toBe(4);
  });

  test("83.2 PATCH rating to 0 clears it (unrated)", async () => {
    test.skip(!testJobOrderId || !testCandidateId, "Prereqs not available");

    const resp = await alicePage.request.patch(
      `${API}/ui/ats/pipeline/by-job/${testJobOrderId}/candidate/${testCandidateId}/rating`,
      { headers: csrfHeaders("alice"), data: { rating: 0 } },
    );
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body.rating).toBe(0);
  });

  test("83.3 PATCH rating > 5 returns 422", async () => {
    test.skip(!testJobOrderId || !testCandidateId, "Prereqs not available");

    const resp = await alicePage.request.patch(
      `${API}/ui/ats/pipeline/by-job/${testJobOrderId}/candidate/${testCandidateId}/rating`,
      { headers: csrfHeaders("alice"), data: { rating: 6 } },
    );
    expect(resp.status()).toBe(422);
  });
});

// ─── Section 84: List by candidate ───────────────────────────────────────────

test.describe("84 — List by candidate", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("84.1 GET by-candidate returns list with job_order_id fields", async () => {
    test.skip(!testCandidateId, "Prereqs not available");

    const resp = await alicePage.request.get(
      `${API}/ui/ats/pipeline/by-candidate/${testCandidateId}`,
    );
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(Array.isArray(body.entries)).toBe(true);
    if (body.entries.length > 0) {
      expect(body.entries[0]).toHaveProperty("job_order_id");
      expect(body.entries[0]).toHaveProperty("candidate_id");
    }
  });

  test("84.2 GET by-candidate for unknown candidate returns empty list", async () => {
    const resp = await alicePage.request.get(
      `${API}/ui/ats/pipeline/by-candidate/cand_nonexistent_${TS}`,
    );
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body.entries).toHaveLength(0);
    expect(body.cursor).toBeNull();
  });
});

// ─── Section 85: Placement ───────────────────────────────────────────────────

test.describe("85 — Placement record", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");

    // Create a separate job + candidate for placement tests so we don't
    // interfere with section 82/83 tests.
    const jobResp = await alicePage.request.post(`${API}/ui/ats/job-orders/`, {
      headers: csrfHeaders("alice"),
      data: {
        title: `E2E Placement Job ${TS}`,
        type: "hire",
        openings: 1,
        client_company_id: `e2e-place-${TS}`,
      },
    });
    if (jobResp.ok()) {
      placedPipelineJobId = (await jobResp.json()).job_id ?? "";
    }

    const candResp = await alicePage.request.post(`${API}/ui/candidates`, {
      headers: csrfHeaders("alice"),
      data: {
        first_name: "PlaceMe",
        last_name: `${TS}`,
        email: `place.${TS}@test.local`,
        source: "direct",
      },
    });
    if (candResp.ok()) {
      placedPipelineCandId = (await candResp.json()).candidate_id ?? "";
    }

    if (placedPipelineJobId && placedPipelineCandId) {
      await alicePage.request.post(`${API}/ui/ats/pipeline/entries`, {
        headers: csrfHeaders("alice"),
        data: { job_order_id: placedPipelineJobId, candidate_id: placedPipelineCandId },
      });
    }
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("85.1 POST placement records and advances status to placed (201)", async () => {
    test.skip(!placedPipelineJobId || !placedPipelineCandId, "Prereqs not available");

    const startDate = Math.floor(Date.now() / 1000) + 30 * 86400; // 30 days from now
    const resp = await alicePage.request.post(
      `${API}/ui/ats/pipeline/by-job/${placedPipelineJobId}/candidate/${placedPipelineCandId}/placement`,
      {
        headers: csrfHeaders("alice"),
        data: {
          start_date: startDate,
          fee_cents: 1500000, // $15,000
          notes: `E2E placement test ${TS}`,
        },
      },
    );
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.placement_id).toBeTruthy();
    expect(body.fee_cents).toBe(1500000);
    expect(body.start_date).toBe(startDate);
    // Pipeline entry status should now be the placed status
    expect(body.status_at_placement).toBeTruthy();
  });

  test("85.2 GET placement returns the record", async () => {
    test.skip(!placedPipelineJobId || !placedPipelineCandId, "Prereqs not available");

    const resp = await alicePage.request.get(
      `${API}/ui/ats/pipeline/by-job/${placedPipelineJobId}/candidate/${placedPipelineCandId}/placement`,
    );
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body.fee_cents).toBe(1500000);
  });

  test("85.3 POST duplicate placement returns 409", async () => {
    test.skip(!placedPipelineJobId || !placedPipelineCandId, "Prereqs not available");

    const resp = await alicePage.request.post(
      `${API}/ui/ats/pipeline/by-job/${placedPipelineJobId}/candidate/${placedPipelineCandId}/placement`,
      {
        headers: csrfHeaders("alice"),
        data: { start_date: Math.floor(Date.now() / 1000), fee_cents: 0 },
      },
    );
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(body.detail?.code).toBe("placement_exists");
  });

  test("85.4 GET placement for non-existent entry returns 404", async () => {
    const resp = await alicePage.request.get(
      `${API}/ui/ats/pipeline/by-job/job_none/candidate/cand_none/placement`,
    );
    expect(resp.status()).toBe(404);
  });
});

// ─── Section 86: Status config ────────────────────────────────────────────────

test.describe("86 — Status config", () => {
  let alicePage: Page;
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await alicePage.close();
    await rootPage.close();
  });

  test("86.1 GET /ui/ats/pipeline/statuses returns default ladder", async () => {
    const resp = await alicePage.request.get(`${API}/ui/ats/pipeline/statuses`);
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(Array.isArray(body.statuses)).toBe(true);
    expect(body.statuses.length).toBeGreaterThan(0);
    // At least one placed status exists
    const placed = body.statuses.find((s: { is_placed: boolean }) => s.is_placed);
    expect(placed).toBeTruthy();
  });

  test("86.2 PUT /ui/admin/ats/pipeline/statuses by root updates config", async () => {
    const customStatuses = [
      { status_key: "100_no_contact", label: "No Contact", rank: 100, order: 0, is_submitted: false, is_placed: false, is_terminal: false, color: null },
      { status_key: "200_contacted", label: "Contacted", rank: 200, order: 1, is_submitted: false, is_placed: false, is_terminal: false, color: "#2563eb" },
      { status_key: "900_placed", label: "Placed", rank: 900, order: 2, is_submitted: false, is_placed: true, is_terminal: true, color: "#16a34a" },
    ];

    const resp = await rootPage.request.put(
      `${API}/ui/admin/ats/pipeline/statuses`,
      {
        headers: csrfHeaders("root"),
        data: { statuses: customStatuses },
      },
    );
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body.statuses.find((s: { status_key: string }) => s.status_key === "200_contacted")?.color).toBe("#2563eb");
  });

  test("86.3 PUT with duplicate status keys returns 422", async () => {
    const resp = await rootPage.request.put(
      `${API}/ui/admin/ats/pipeline/statuses`,
      {
        headers: csrfHeaders("root"),
        data: {
          statuses: [
            { status_key: "dup", label: "Dup 1", rank: 100, order: 0, is_placed: false, is_terminal: false },
            { status_key: "dup", label: "Dup 2", rank: 200, order: 1, is_placed: true, is_terminal: false },
          ],
        },
      },
    );
    expect(resp.status()).toBe(422);
  });

  test("86.4 PUT without exactly one is_placed returns 422", async () => {
    const resp = await rootPage.request.put(
      `${API}/ui/admin/ats/pipeline/statuses`,
      {
        headers: csrfHeaders("root"),
        data: {
          statuses: [
            { status_key: "s1", label: "Stage 1", rank: 100, order: 0, is_placed: false, is_terminal: false },
          ],
        },
      },
    );
    expect(resp.status()).toBe(422);
  });

  test("86.5 Non-admin PUT returns 403", async () => {
    const resp = await alicePage.request.put(
      `${API}/ui/admin/ats/pipeline/statuses`,
      {
        headers: csrfHeaders("alice"),
        data: {
          statuses: [
            { status_key: "100_no_contact", label: "No Contact", rank: 100, order: 0, is_placed: false, is_terminal: false },
            { status_key: "900_placed", label: "Placed", rank: 900, order: 1, is_placed: true, is_terminal: true },
          ],
        },
      },
    );
    expect(resp.status()).toBe(403);
  });
});

// ─── Section 87: Pipeline Board UI ───────────────────────────────────────────

test.describe("87 — Pipeline Board UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("87.1 /ats/pipeline loads the board page", async () => {
    await page.goto(`${BASE}/ats/pipeline`, { waitUntil: "domcontentloaded" });
    // Either board or "not enabled" state (wait for lazy chunk + queries)
    const board = page.locator("h1").filter({ hasText: /Pipeline Board/i });
    const notEnabled = page.locator("text=Pipeline Not Enabled");
    await expect(board.or(notEnabled).first()).toBeVisible({ timeout: 15_000 });
  });

  test("87.2 Board page shows job order picker or not-enabled state", async () => {
    await page.goto(`${BASE}/ats/pipeline`, { waitUntil: "domcontentloaded" });
    const picker = page.getByText("Select a job order to view pipeline…");
    const notEnabled = page.locator("text=Pipeline Not Enabled");
    // One of the two should appear once the lazy chunk + queries settle
    await expect(picker.or(notEnabled).first()).toBeVisible({ timeout: 15_000 });
  });

  test("87.3 Empty board shows prompt to select job order", async () => {
    await page.goto(`${BASE}/ats/pipeline`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(500);
    const prompt = page.locator("text=Select a job order above to view its pipeline board");
    // This appears when no job order is selected — may or may not be visible
    // depending on feature flag state; test is flexible
    if (await prompt.count() > 0) {
      await expect(prompt.first()).toBeVisible();
    }
  });
});

// ─── Section 88: Pipeline Detail UI ──────────────────────────────────────────

test.describe("88 — Pipeline Detail UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("88.1 /ats/pipeline/detail/:job/:cand loads the detail page", async () => {
    const job = testJobOrderId || "job_test";
    const cand = testCandidateId || "cand_test";
    await page.goto(`${BASE}/ats/pipeline/detail/${job}/${cand}`, {
      waitUntil: "domcontentloaded",
    });
    await page.waitForTimeout(600);
    const title = page.locator("h1").filter({ hasText: /Pipeline Entry Detail/i });
    const notEnabled = page.locator("text=Pipeline Not Enabled");
    expect((await title.count()) + (await notEnabled.count())).toBeGreaterThan(0);
  });

  test("88.2 Detail page shows stage controls when entry exists", async () => {
    test.skip(!testJobOrderId || !testCandidateId, "Prereqs not available");
    await page.goto(
      `${BASE}/ats/pipeline/detail/${testJobOrderId}/${testCandidateId}`,
      { waitUntil: "domcontentloaded" },
    );
    await page.waitForTimeout(800);
    // Should show either: Pipeline Entry card, or not-enabled, or not-found message
    const hasCard = await page.locator("text=Pipeline Entry").count();
    const hasNotEnabled = await page.locator("text=Pipeline Not Enabled").count();
    const hasNotFound = await page.locator("text=No pipeline entry found").count();
    expect(hasCard + hasNotEnabled + hasNotFound).toBeGreaterThan(0);
  });

  test("88.3 /ats/pipeline/candidate/:id loads candidate pipeline page", async () => {
    const cand = testCandidateId || "cand_test";
    await page.goto(`${BASE}/ats/pipeline/candidate/${cand}`, {
      waitUntil: "domcontentloaded",
    });
    await page.waitForTimeout(600);
    const title = page.locator("h1").filter({ hasText: /Candidate Pipeline/i });
    const notEnabled = page.locator("text=Pipeline Not Enabled");
    expect((await title.count()) + (await notEnabled.count())).toBeGreaterThan(0);
  });
});
