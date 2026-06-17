/**
 * E2E tests for Questionnaire Analytics UI (UX-005).
 *
 * Sections:
 *   85 — Questionnaire Analytics API (4 tests)
 *   86 — Questionnaire Analytics UI (4 tests)
 *
 * Auth: Alice session cookies (from e2e_session_setup.py).
 *
 * Endpoints under test:
 *   POST   /questionnaires/drafts
 *   POST   /questionnaires/drafts/{id}/sections
 *   POST   /questionnaires/drafts/{id}/questions
 *   POST   /questionnaires/drafts/{id}/publish
 *   POST   /questionnaires/published/{slug}/sessions
 *   PUT    /questionnaires/published/{slug}/sessions/{sid}
 *   POST   /questionnaires/published/{slug}/sessions/{sid}/submit
 *   GET    /questionnaires/drafts/{id}/analytics
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const API = "http://localhost:8000";
const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();

const Q_ID = `e2e_qa_${TS}`;
const Q_TITLE = `E2E Analytics ${TS}`;
const Q_DESC = `Analytics test questionnaire at ${TS}`;
const SEC_ID = `sec_qa_${TS}`;
const QTEXT_ID = `q_qa_text_${TS}`;
const SLUG = `e2e-analytics-${TS}`;

// ─── Session bootstrap ────────────────────────────────────────────────────────

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
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiGet(page: Page, path: string) {
  const session = getSessions()[ALICE_ID];
  return page.request.get(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiPost(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiPut(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.put(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 85: Questionnaire Analytics API
// ─────────────────────────────────────────────────────────────────────────────

test.describe.serial("Section 85: Questionnaire Analytics API", () => {
  let page: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    page = await browser.newPage();
    await injectAuth(page);

    // Create questionnaire draft
    const createResp = await apiPost(page, "/questionnaires/drafts", {
      questionnaire_id: Q_ID,
      title: Q_TITLE,
      description: Q_DESC,
      visibility: "public",
    });
    expect(createResp.status()).toBe(200);

    // Add a section
    await apiPost(page, `/questionnaires/drafts/${Q_ID}/sections`, {
      section_id: SEC_ID,
      title: "Main Section",
      description: "Test section",
    });

    // Add a text question
    await apiPost(page, `/questionnaires/drafts/${Q_ID}/questions`, {
      section_id: SEC_ID,
      question_id: QTEXT_ID,
      type: "text",
      label: "Your name",
      required: true,
      hint: "Enter your full name",
      config_json: { minLength: 1, maxLength: 200 },
    });

    // Publish
    const pubResp = await apiPost(page, `/questionnaires/drafts/${Q_ID}/publish`, {
      published_slug: SLUG,
    });
    expect(pubResp.status()).toBe(200);

    // Create a response session and submit it (creates analytics data)
    const sessResp = await apiPost(page, `/questionnaires/published/${SLUG}/sessions`, {});
    expect(sessResp.status()).toBe(200);
    const sessData = (await sessResp.json()) as { session: { response_session_id: string } };
    const sessionId = sessData.session.response_session_id;

    // Save answers
    await apiPut(page, `/questionnaires/published/${SLUG}/sessions/${sessionId}`, {
      answers_by_question_id: { [QTEXT_ID]: "Alice Test" },
      current_section_index: 0,
      current_question_id: QTEXT_ID,
    });

    // Submit
    const submitResp = await apiPost(
      page,
      `/questionnaires/published/${SLUG}/sessions/${sessionId}/submit`,
      { answers_by_question_id: { [QTEXT_ID]: "Alice Test" } },
    );
    expect(submitResp.status()).toBe(200);
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("85.1 Analytics endpoint returns funnel data", async () => {
    const resp = await apiGet(page, `/questionnaires/drafts/${Q_ID}/analytics`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as {
      analytics: {
        generated_at: string;
        freshness_sla_seconds: number;
        totals: { starts: number; completions: number };
        versions: Array<{ funnel: { starts: number; completions: number; completion_rate: number } }>;
      };
    };
    expect(data.analytics).toBeTruthy();
    expect(data.analytics.generated_at).toBeTruthy();
    expect(data.analytics.freshness_sla_seconds).toBe(60);
    expect(data.analytics.totals.starts).toBeGreaterThanOrEqual(1);
    expect(data.analytics.totals.completions).toBeGreaterThanOrEqual(1);
  });

  test("85.2 Analytics endpoint returns version-level funnel", async () => {
    const resp = await apiGet(page, `/questionnaires/drafts/${Q_ID}/analytics`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as {
      analytics: {
        versions: Array<{
          version_id: string;
          funnel: { starts: number; completions: number; completion_rate: number };
          dropoff_points: Array<{ label: string; count: number }>;
          validation_hotspots: Array<{ key: string; count: number }>;
        }>;
      };
    };
    expect(data.analytics.versions.length).toBeGreaterThanOrEqual(1);
    const ver = data.analytics.versions[0];
    expect(ver.version_id).toBeTruthy();
    expect(ver.funnel.starts).toBeGreaterThanOrEqual(1);
    expect(ver.funnel.completions).toBeGreaterThanOrEqual(1);
    expect(ver.funnel.completion_rate).toBeGreaterThan(0);
    expect(Array.isArray(ver.dropoff_points)).toBe(true);
    expect(Array.isArray(ver.validation_hotspots)).toBe(true);
  });

  test("85.3 Analytics returns dropoff data structure", async () => {
    const resp = await apiGet(page, `/questionnaires/drafts/${Q_ID}/analytics`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as {
      analytics: {
        totals: {
          top_dropoffs: Array<{ label: string; count: number }>;
          top_validation_hotspots: Array<{ key: string; count: number }>;
        };
      };
    };
    // top_dropoffs is an array (may be empty if all sessions completed)
    expect(Array.isArray(data.analytics.totals.top_dropoffs)).toBe(true);
    expect(Array.isArray(data.analytics.totals.top_validation_hotspots)).toBe(true);
  });

  test("85.4 Analytics for non-existent questionnaire returns 404", async () => {
    const resp = await apiGet(page, `/questionnaires/drafts/nonexistent_${TS}/analytics`);
    expect(resp.status()).toBe(404);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 86: Questionnaire Analytics UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe.serial("Section 86: Questionnaire Analytics UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("86.1 Analytics card visible on builder page", async () => {
    await page.goto(`${BASE}/questionnaires/${Q_ID}/builder`, {
      waitUntil: "domcontentloaded",
    });
    await expect(
      page.locator("[data-testid='questionnaire-analytics-card']"),
    ).toBeVisible({ timeout: 15000 });
    await expect(
      page.locator("[data-testid='questionnaire-analytics-card']").getByText("Response analytics"),
    ).toBeVisible();
  });

  test("86.2 Funnel chart renders with data", async () => {
    // Verify the API returns data first
    const analyticsResp = await apiGet(page, `/questionnaires/drafts/${Q_ID}/analytics`);
    expect(analyticsResp.status()).toBe(200);
    const data = await analyticsResp.json() as { analytics: { totals: { starts: number } } };
    expect(data.analytics.totals.starts).toBeGreaterThanOrEqual(1);

    // Reload to ensure analytics data is fresh
    await page.goto(`${BASE}/questionnaires/${Q_ID}/builder`, {
      waitUntil: "domcontentloaded",
    });
    // Wait for analytics API call to complete
    await page.waitForResponse(
      (r) => r.url().includes("/analytics") && r.status() === 200,
      { timeout: 10000 },
    ).catch(() => {});
    await expect(
      page.locator("[data-testid='questionnaire-analytics-card']"),
    ).toBeVisible({ timeout: 15000 });

    const funnelChart = page.locator("[data-testid='analytics-funnel-chart']");
    await expect(funnelChart).toBeVisible({ timeout: 15000 });
    await expect(funnelChart.getByText(/started/)).toBeVisible({ timeout: 10000 });
    await expect(funnelChart.getByText(/completed/)).toBeVisible();
    await expect(funnelChart.getByText(/completion rate/)).toBeVisible();
  });

  test("86.3 Completion gauge shows percentage", async () => {
    await expect(
      page.locator("[data-testid='analytics-completion-gauge']"),
    ).toBeVisible({ timeout: 10000 });
    // The gauge SVG should contain a percentage text
    await expect(
      page.locator("[data-testid='analytics-completion-gauge'] text"),
    ).toHaveText(/%/);
  });

  test("86.4 Summary stats show numeric content", async () => {
    const startsEl = page.locator("[data-testid='analytics-total-starts']");
    await expect(startsEl).toBeVisible();
    await expect(startsEl).toHaveText(/\d+/);

    const completionsEl = page.locator("[data-testid='analytics-total-completions']");
    await expect(completionsEl).toBeVisible();
    await expect(completionsEl).toHaveText(/\d+/);

    const versionsEl = page.locator("[data-testid='analytics-version-count']");
    await expect(versionsEl).toBeVisible();
    await expect(versionsEl).toHaveText(/\d+/);
  });
});
