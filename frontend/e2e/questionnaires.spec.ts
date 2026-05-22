/**
 * E2E tests for Questionnaires feature.
 *
 * Sections:
 *   83 — Questionnaire Draft CRUD (8 tests)
 *   84 — Questionnaire Publish & Response Flow (7 tests)
 *
 * Auth: Alice session cookies (from e2e_session_setup.py).
 *
 * Endpoints under test (prefix: /questionnaires):
 *   POST   /drafts
 *   GET    /drafts
 *   GET    /drafts/{id}
 *   PATCH  /drafts/{id}
 *   DELETE /drafts/{id}
 *   POST   /drafts/{id}/sections
 *   GET    /drafts/{id}/sections
 *   POST   /drafts/{id}/questions
 *   GET    /drafts/{id}/sections/{sid}/questions
 *   POST   /drafts/{id}/questions/reorder
 *   POST   /drafts/{id}/publish
 *   GET    /published/{slug}
 *   GET    /published/by-id/{id}
 *   POST   /published/{slug}/sessions
 *   GET    /published/{slug}/sessions/{sid}
 *   PUT    /published/{slug}/sessions/{sid}
 *   POST   /published/{slug}/sessions/{sid}/validate
 *   POST   /published/{slug}/sessions/{sid}/submit
 *   GET    /drafts/{id}/analytics
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const API = "http://localhost:8000";
const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();

// Section 83 IDs
const Q83_ID = `e2e_q83_${TS}`;
const Q83_TITLE = `E2E Draft CRUD ${TS}`;
const Q83_DESC = `Test questionnaire for draft CRUD at ${TS}`;
const SEC83_1 = `sec83_general_${TS}`;
const SEC83_2 = `sec83_prefs_${TS}`;
const Q83_TEXT = `q83_name_${TS}`;
const Q83_SELECT = `q83_color_${TS}`;
const Q83_SLIDER = `q83_rating_${TS}`;

// Section 84 IDs (independent from section 83)
const Q84_ID = `e2e_q84_${TS}`;
const Q84_TITLE = `E2E Publish Flow ${TS}`;
const Q84_DESC = `Test questionnaire for publish & response at ${TS}`;
const SEC84 = `sec84_main_${TS}`;
const Q84_TEXT = `q84_name_${TS}`;
const Q84_SELECT = `q84_color_${TS}`;
const Q84_SLIDER = `q84_rating_${TS}`;
const Q84_SLUG = `e2e-form-${TS}`;

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
      "python3 /home/ubuntu/testlogon/e2e_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
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

async function apiPatch(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.patch(`${API}${path}`, {
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

async function apiDelete(page: Page, path: string) {
  const session = getSessions()[ALICE_ID];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 83: Questionnaire Draft CRUD
// ─────────────────────────────────────────────────────────────────────────────

test.describe.serial("Section 83: Questionnaire Draft CRUD", () => {
  let page: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("83.1 Create a new questionnaire draft", async () => {
    const resp = await apiPost(page, "/questionnaires/drafts", {
      questionnaire_id: Q83_ID,
      title: Q83_TITLE,
      description: Q83_DESC,
      visibility: "public",
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { draft: Record<string, unknown> };
    expect(data.draft).toBeTruthy();
    expect(data.draft.questionnaire_id).toBe(Q83_ID);
    expect(data.draft.title).toBe(Q83_TITLE);
    expect(data.draft.description).toBe(Q83_DESC);
    expect(data.draft.status).toBe("draft");
    expect(data.draft.visibility).toBe("public");
  });

  test("83.2 List drafts includes new draft", async () => {
    const resp = await apiGet(page, "/questionnaires/drafts");
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { items: Array<Record<string, unknown>> };
    expect(Array.isArray(data.items)).toBe(true);
    const found = data.items.find((d) => d.questionnaire_id === Q83_ID);
    expect(found).toBeTruthy();
    expect(found!.title).toBe(Q83_TITLE);
  });

  test("83.3 Get draft by id returns correct data", async () => {
    const resp = await apiGet(page, `/questionnaires/drafts/${Q83_ID}`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { draft: Record<string, unknown> };
    expect(data.draft.questionnaire_id).toBe(Q83_ID);
    expect(data.draft.title).toBe(Q83_TITLE);
    expect(data.draft.description).toBe(Q83_DESC);
  });

  test("83.4 Update draft title and description", async () => {
    const newTitle = `${Q83_TITLE} Updated`;
    const newDesc = `${Q83_DESC} - revised`;
    const resp = await apiPatch(page, `/questionnaires/drafts/${Q83_ID}`, {
      title: newTitle,
      description: newDesc,
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { draft: Record<string, unknown> };
    expect(data.draft.title).toBe(newTitle);
    expect(data.draft.description).toBe(newDesc);
  });

  test("83.5 Create sections within draft", async () => {
    const resp1 = await apiPost(page, `/questionnaires/drafts/${Q83_ID}/sections`, {
      section_id: SEC83_1,
      title: "General Info",
      description: "Basic information section",
    });
    expect(resp1.status()).toBe(200);
    const s1 = (await resp1.json()) as { section: Record<string, unknown> };
    expect(s1.section.section_id).toBe(SEC83_1);
    expect(s1.section.title).toBe("General Info");

    const resp2 = await apiPost(page, `/questionnaires/drafts/${Q83_ID}/sections`, {
      section_id: SEC83_2,
      title: "Preferences",
      description: "User preferences section",
    });
    expect(resp2.status()).toBe(200);
    const s2 = (await resp2.json()) as { section: Record<string, unknown> };
    expect(s2.section.section_id).toBe(SEC83_2);
  });

  test("83.6 Create multiple questions (text, select, slider)", async () => {
    // text question (required)
    const r1 = await apiPost(page, `/questionnaires/drafts/${Q83_ID}/questions`, {
      section_id: SEC83_1,
      question_id: Q83_TEXT,
      type: "text",
      label: "What is your name?",
      required: true,
      hint: "Enter your full name",
      config_json: {},
    });
    expect(r1.status()).toBe(200);
    const q1 = (await r1.json()) as { question: Record<string, unknown> };
    expect(q1.question.question_id).toBe(Q83_TEXT);
    expect(q1.question.label).toBe("What is your name?");
    expect(q1.question.required).toBe(true);

    // select question
    const r2 = await apiPost(page, `/questionnaires/drafts/${Q83_ID}/questions`, {
      section_id: SEC83_1,
      question_id: Q83_SELECT,
      type: "select",
      label: "Favorite color?",
      required: false,
      hint: "Pick one",
      config_json: { options: ["Red", "Green", "Blue"] },
    });
    expect(r2.status()).toBe(200);
    const q2 = (await r2.json()) as { question: Record<string, unknown> };
    expect(q2.question.question_id).toBe(Q83_SELECT);
    expect(q2.question.type).toBe("select");

    // slider question
    const r3 = await apiPost(page, `/questionnaires/drafts/${Q83_ID}/questions`, {
      section_id: SEC83_1,
      question_id: Q83_SLIDER,
      type: "slider",
      label: "Rate your experience (1-10)",
      required: false,
      config_json: { min: 1, max: 10, step: 1 },
    });
    expect(r3.status()).toBe(200);
    const q3 = (await r3.json()) as { question: Record<string, unknown> };
    expect(q3.question.question_id).toBe(Q83_SLIDER);
    expect(q3.question.type).toBe("slider");
  });

  test("83.7 Reorder questions changes position", async () => {
    // Reorder: slider first, then text, then select
    const resp = await apiPost(page, `/questionnaires/drafts/${Q83_ID}/questions/reorder`, {
      section_id: SEC83_1,
      question_ids: [Q83_SLIDER, Q83_TEXT, Q83_SELECT],
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { items: Array<Record<string, unknown>> };
    expect(data.items.length).toBe(3);
    expect(data.items[0].question_id).toBe(Q83_SLIDER);
    expect(data.items[1].question_id).toBe(Q83_TEXT);
    expect(data.items[2].question_id).toBe(Q83_SELECT);
  });

  test("83.8 Archive (delete) draft returns archived status", async () => {
    // Create a throwaway draft to archive (do not archive Q83_ID)
    const archiveId = `e2e_q83_archive_${TS}`;
    const createResp = await apiPost(page, "/questionnaires/drafts", {
      questionnaire_id: archiveId,
      title: "To be archived",
      description: "",
    });
    expect(createResp.status()).toBe(200);

    const delResp = await apiDelete(page, `/questionnaires/drafts/${archiveId}`);
    expect(delResp.status()).toBe(200);
    const data = (await delResp.json()) as { draft: Record<string, unknown> };
    expect(data.draft.status).toBe("archived");

    // Verify it no longer appears in default list (include_archived=false)
    const listResp = await apiGet(page, "/questionnaires/drafts");
    const listData = (await listResp.json()) as { items: Array<Record<string, unknown>> };
    const found = listData.items.find((d) => d.questionnaire_id === archiveId);
    expect(found).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 84: Questionnaire Publish & Response Flow
// ─────────────────────────────────────────────────────────────────────────────

test.describe.serial("Section 84: Questionnaire Publish & Response Flow", () => {
  let page: Page;
  let publishedSlug = "";
  let responseSessionId = "";

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    page = await browser.newPage();
    await injectAuth(page);

    // Create a self-contained draft for section 84
    const createResp = await apiPost(page, "/questionnaires/drafts", {
      questionnaire_id: Q84_ID,
      title: Q84_TITLE,
      description: Q84_DESC,
      visibility: "public",
    });
    if (createResp.status() !== 200) {
      throw new Error(`Failed to create draft: ${createResp.status()} ${await createResp.text()}`);
    }

    // Create section
    const secResp = await apiPost(page, `/questionnaires/drafts/${Q84_ID}/sections`, {
      section_id: SEC84,
      title: "Main Section",
      description: "Questions for the response flow test",
    });
    if (secResp.status() !== 200) {
      throw new Error(`Failed to create section: ${secResp.status()} ${await secResp.text()}`);
    }

    // Create questions: text (required), select, slider
    for (const q of [
      { question_id: Q84_TEXT, type: "text", label: "Your name?", required: true, config_json: {} },
      { question_id: Q84_SELECT, type: "select", label: "Color?", required: false, config_json: { options: ["Red", "Green", "Blue"] } },
      { question_id: Q84_SLIDER, type: "slider", label: "Rating?", required: false, config_json: { min: 1, max: 10, step: 1 } },
    ]) {
      const qResp = await apiPost(page, `/questionnaires/drafts/${Q84_ID}/questions`, {
        section_id: SEC84,
        ...q,
      });
      if (qResp.status() !== 200) {
        throw new Error(`Failed to create question ${q.question_id}: ${qResp.status()} ${await qResp.text()}`);
      }
    }

    // Publish the draft
    const pubResp = await apiPost(page, `/questionnaires/drafts/${Q84_ID}/publish`, {
      published_slug: Q84_SLUG,
    });
    if (pubResp.status() !== 200) {
      throw new Error(`Failed to publish: ${pubResp.status()} ${await pubResp.text()}`);
    }
    const pubData = (await pubResp.json()) as { version: Record<string, unknown> };
    publishedSlug = pubData.version.published_slug as string;

    // Start a response session
    const sessResp = await apiPost(page, `/questionnaires/published/${publishedSlug}/sessions`, {
      questionnaire_id: Q84_ID,
    });
    if (sessResp.status() !== 200) {
      throw new Error(`Failed to start session: ${sessResp.status()} ${await sessResp.text()}`);
    }
    const sessData = (await sessResp.json()) as { session: Record<string, unknown> };
    responseSessionId = sessData.session.response_session_id as string;
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("84.1 Published questionnaire is retrievable by slug", async () => {
    expect(publishedSlug).toBeTruthy();
    const resp = await apiGet(page, `/questionnaires/published/${publishedSlug}`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { version: Record<string, unknown> };
    expect(data.version.questionnaire_id).toBe(Q84_ID);
    expect(data.version.published_slug).toBe(publishedSlug);
    expect(data.version.schema_json).toBeTruthy();
    const schema = data.version.schema_json as { sections: Array<Record<string, unknown>> };
    expect(schema.sections.length).toBeGreaterThanOrEqual(1);
  });

  test("84.2 Published questionnaire is also retrievable by id", async () => {
    const resp = await apiGet(page, `/questionnaires/published/by-id/${Q84_ID}`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { version: Record<string, unknown> };
    expect(data.version.questionnaire_id).toBe(Q84_ID);
    expect(data.version.published_slug).toBe(publishedSlug);
  });

  test("84.3 Get response session state shows in_progress", async () => {
    const resp = await apiGet(
      page,
      `/questionnaires/published/${publishedSlug}/sessions/${responseSessionId}`,
    );
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as {
      session: Record<string, unknown>;
      answers_by_question_id: Record<string, unknown>;
    };
    expect(data.session.status).toBe("in_progress");
    expect(data.session.response_session_id).toBe(responseSessionId);
  });

  test("84.4 Save partial answers to session", async () => {
    const resp = await apiPut(
      page,
      `/questionnaires/published/${publishedSlug}/sessions/${responseSessionId}`,
      {
        answers_by_question_id: {
          [Q84_SELECT]: "Blue",
          [Q84_SLIDER]: 7,
        },
        current_section_index: 0,
      },
    );
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as {
      session: Record<string, unknown>;
      answers_by_question_id: Record<string, unknown>;
    };
    expect(data.session.status).toBe("in_progress");
    expect(data.answers_by_question_id[Q84_SELECT]).toBe("Blue");
    expect(Number(data.answers_by_question_id[Q84_SLIDER])).toBe(7);
  });

  test("84.5 Validate answers — missing required field flagged in errors", async () => {
    // The text question (Q84_TEXT) is required but not answered
    const resp = await apiPost(
      page,
      `/questionnaires/published/${publishedSlug}/sessions/${responseSessionId}/validate`,
      {
        answers_by_question_id: {
          [Q84_SELECT]: "Blue",
          [Q84_SLIDER]: 7,
          // Q84_TEXT deliberately omitted — it is required
        },
        final_submit: false,
      },
    );
    // Server returns 200 with validation result; is_valid=false when required field missing
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as {
      is_valid: boolean;
      errors: Record<string, Array<{ code: string; message: string }>>;
    };
    expect(data.is_valid).toBe(false);
    expect(data.errors[Q84_TEXT]).toBeTruthy();
    expect(data.errors[Q84_TEXT].length).toBeGreaterThanOrEqual(1);
    expect(data.errors[Q84_TEXT][0].code).toBe("required");
  });

  test("84.6 Submit completed response succeeds with all required answers", async () => {
    // Save all answers including the required text field
    const saveResp = await apiPut(
      page,
      `/questionnaires/published/${publishedSlug}/sessions/${responseSessionId}`,
      {
        answers_by_question_id: {
          [Q84_TEXT]: "Alice Smith",
          [Q84_SELECT]: "Blue",
          [Q84_SLIDER]: 7,
        },
        current_section_index: 0,
      },
    );
    expect(saveResp.status()).toBe(200);

    // Submit
    const resp = await apiPost(
      page,
      `/questionnaires/published/${publishedSlug}/sessions/${responseSessionId}/submit`,
      {
        answers_by_question_id: {
          [Q84_TEXT]: "Alice Smith",
          [Q84_SELECT]: "Blue",
          [Q84_SLIDER]: 7,
        },
        final_submit: true,
      },
    );
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as {
      session: Record<string, unknown>;
      result: Record<string, unknown>;
    };
    expect(data.session.status).toBe("submitted");
    expect(data.result.is_valid).toBe(true);
    expect(data.result.can_submit).toBe(true);
  });

  test("84.7 Analytics shows at least one submission", async () => {
    const resp = await apiGet(page, `/questionnaires/drafts/${Q84_ID}/analytics`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { analytics: Record<string, unknown> };
    expect(data.analytics).toBeTruthy();
    const totals = data.analytics.totals as { starts: number; completions: number };
    expect(totals.starts).toBeGreaterThanOrEqual(1);
    expect(totals.completions).toBeGreaterThanOrEqual(1);
  });
});
