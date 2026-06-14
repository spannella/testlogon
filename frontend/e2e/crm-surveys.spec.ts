/**
 * E2E tests for the SuiteCRM Surveys cluster (EVT-Surveys, EVT-008..010).
 *
 * Surveys reuse the questionnaires builder/publish/response pipeline.
 * Backend router: app/routers/questionnaires.py (mounted at root `/questionnaires`).
 *
 * Sections:
 *   80 — Survey CRUD (create / list / get / archive) — API
 *   81 — Builder: sections + questions + publish — API
 *   82 — Analytics + distribution (EVT-008, flag-gated) — API
 *   83 — Surveys list + builder UI
 *
 * Auth: uses e2e_admin_session_setup.py (all identities)
 *
 * Identities:
 *   alice – e2e_alice@test.local – role=user (survey owner)
 *   bob   – e2e_bob@test.local   – role=user
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
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
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
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
    [session.user_sub, session.access_token],
  );
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getAdminSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

// ─── Module-level shared state ────────────────────────────────────────────────

let surveyId = "";
let sectionId = "";

// ─────────────────────────────────────────────────────────────────────────────
// Section 80 — Survey CRUD — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 80: Survey CRUD (API)", () => {
  let alicePage: Page;
  const TITLE = `E2E survey ${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getAdminSessions();
    alicePage = await newIdentityPage(browser, "alice");
    surveyId = `e2e-survey-${TS}`;
    const resp = await apiPost(alicePage, "alice", "questionnaires/drafts", {
      questionnaire_id: surveyId,
      title: TITLE,
      description: "survey desc",
      visibility: "public",
    });
    if (!resp.ok()) throw new Error(`create survey failed: ${await resp.text()}`);
    const data = await resp.json() as { draft: { questionnaire_id: string } };
    expect(data.draft.questionnaire_id).toBe(surveyId);
  });

  test("80.1 Get survey → 200, status draft, owner is alice", async () => {
    const resp = await apiGet(alicePage, `questionnaires/drafts/${surveyId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { draft: Record<string, unknown> };
    expect(data.draft.status).toBe("draft");
    expect(data.draft.owner_id).toBe(ALICE_ID);
  });

  test("80.2 List surveys → includes new survey", async () => {
    const resp = await apiGet(alicePage, "questionnaires/drafts");
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { items: Array<{ questionnaire_id: string }> };
    expect(data.items.find((s) => s.questionnaire_id === surveyId)).toBeTruthy();
  });

  test("80.3 Update survey metadata → 200", async () => {
    const sess = getAdminSessions()["alice"];
    const resp = await alicePage.request.patch(`${API}/questionnaires/drafts/${surveyId}`, {
      data: { title: `${TS} updated` },
      headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { draft: { title: string } };
    expect(data.draft.title).toBe(`${TS} updated`);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 81 — Builder: sections + questions + publish — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 81: Builder + publish (API)", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test("81.1 Create section → 200", async () => {
    sectionId = `sec-${TS}`;
    const resp = await apiPost(alicePage, "alice", `questionnaires/drafts/${surveyId}/sections`, {
      section_id: sectionId,
      title: "General",
      description: "",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { section: { section_id: string } };
    expect(data.section.section_id).toBe(sectionId);
  });

  test("81.2 List sections → includes new section", async () => {
    const resp = await apiGet(alicePage, `questionnaires/drafts/${surveyId}/sections`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { items: Array<{ section_id: string }> };
    expect(data.items.find((s) => s.section_id === sectionId)).toBeTruthy();
  });

  test("81.3 Create radio question → 200", async () => {
    const resp = await apiPost(alicePage, "alice", `questionnaires/drafts/${surveyId}/questions`, {
      section_id: sectionId,
      question_id: `q-${TS}`,
      type: "radio",
      label: "How satisfied?",
      required: true,
      config_json: { options: ["Low", "High"] },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { question: { question_id: string } };
    expect(data.question.question_id).toBe(`q-${TS}`);
  });

  test("81.4 Schema snapshot reflects section + question", async () => {
    const resp = await apiGet(alicePage, `questionnaires/drafts/${surveyId}/schema`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as {
      sections: Array<{ section_id: string; questions: Array<{ question_id: string }> }>;
    };
    const sec = data.sections.find((s) => s.section_id === sectionId);
    expect(sec).toBeTruthy();
    expect(sec!.questions.find((q) => q.question_id === `q-${TS}`)).toBeTruthy();
  });

  test("81.5 Publish survey → 200, status becomes published", async () => {
    const resp = await apiPost(alicePage, "alice", `questionnaires/drafts/${surveyId}/publish`, {});
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { version: { version_number: number; published_slug: string } };
    expect(data.version.version_number).toBeGreaterThanOrEqual(1);

    const after = await apiGet(alicePage, `questionnaires/drafts/${surveyId}`);
    const adata = await after.json() as { draft: { status: string } };
    expect(adata.draft.status).toBe("published");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 82 — Analytics + distribution (EVT-008) — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 82: Analytics + distribution (API)", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test("82.1 Analytics → 200, has totals + versions", async () => {
    const resp = await apiGet(alicePage, `questionnaires/drafts/${surveyId}/analytics`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as {
      analytics: { totals: { starts: number; completions: number }; versions: unknown[] };
    };
    expect(typeof data.analytics.totals.starts).toBe("number");
    expect(Array.isArray(data.analytics.versions)).toBe(true);
  });

  test("82.2 Distribution summary → enabled (200) or flag-gated (404)", async () => {
    const resp = await apiGet(alicePage, `questionnaires/drafts/${surveyId}/distribution-summary`);
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const data = await resp.json() as { total_sent: number; response_rate: number };
      expect(typeof data.total_sent).toBe("number");
      expect(typeof data.response_rate).toBe("number");
    }
  });

  test("82.3 Distribute → flag-gated returns 404 when disabled", async () => {
    const resp = await apiPost(alicePage, "alice", `questionnaires/drafts/${surveyId}/distribute`, {
      recipients: ["target@example.com"],
      subject: "Take our survey",
    });
    // Either succeeds (flag on), is rate-limited/published-gated, or 404 (flag off).
    expect([200, 404, 409, 429]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 83 — Surveys UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 83: Surveys UI", () => {
  test.beforeEach(async ({ page }: { page: Page }) => {
    await injectAuth(page, "alice");
  });

  test("83.1 Surveys list page renders header", async ({ page }: { page: Page }) => {
    await page.goto(`${BASE}/crm/surveys`, { waitUntil: "domcontentloaded" });
    await expect(
      page.getByRole("heading", { name: "Surveys", exact: true }),
    ).toBeVisible({ timeout: 15_000 });
  });

  test("83.2 New survey button opens dialog", async ({ page }: { page: Page }) => {
    await page.goto(`${BASE}/crm/surveys`, { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: /new survey/i }).first().click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(page.getByLabel("Title")).toBeVisible();
  });

  test("83.3 Builder page loads for published survey", async ({ page }: { page: Page }) => {
    await page.goto(`${BASE}/crm/surveys/${surveyId}/build`, { waitUntil: "domcontentloaded" });
    await expect(page.getByText("Sections", { exact: true })).toBeVisible({ timeout: 15_000 });
  });

  test("83.4 Results page renders distribution + overall cards", async ({ page }: { page: Page }) => {
    await page.goto(`${BASE}/crm/surveys/${surveyId}/results`, { waitUntil: "domcontentloaded" });
    await expect(page.getByText("Distribution", { exact: true })).toBeVisible({ timeout: 15_000 });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Cleanup
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 84: cleanup", () => {
  test("84.1 Archive survey → 200", async ({ browser }: { browser: Browser }) => {
    const alicePage = await newIdentityPage(browser, "alice");
    const resp = await apiDelete(alicePage, "alice", `questionnaires/drafts/${surveyId}`);
    expect(resp.status()).toBe(200);
  });
});
