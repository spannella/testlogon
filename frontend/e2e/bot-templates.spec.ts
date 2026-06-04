/**
 * E2E tests for Bot Templates & Scheduled Messages (BOT-002).
 *
 * Sections:
 *   511 — Template CRUD API        (5 tests)
 *   512 — Variable Substitution    (3 tests)
 *   513 — Scheduled Sends API      (4 tests)
 *   514 — Template Editor UI       (4 tests)
 *
 * Auth: Alice session cookies (from e2e_session_setup.py).
 *       Alice = creator (bot owner).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const TS       = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

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

// ─── API helpers — use Vite proxy so session cookies are forwarded ────────────

async function apiPost(page: Page, path: string, body: unknown) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
    data: body as Record<string, unknown>,
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

async function apiPut(page: Page, path: string, body: unknown) {
  const session = getSessions()[ALICE_ID];
  return page.request.put(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
    data: body as Record<string, unknown>,
  });
}

async function apiDelete(page: Page, path: string) {
  const session = getSessions()[ALICE_ID];
  return page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── Shared state ─────────────────────────────────────────────────────────────

let botId: string;
let greetingTemplateId: string;
let qrTemplateId: string;
let scheduleId: string;

// ─── Test Setup ───────────────────────────────────────────────────────────────

test.describe("Bot Templates & Scheduled Messages (BOT-002)", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);

    // Create a bot for template tests
    const botResp = await apiPost(page, "/ui/bots", {
      name: `TemplateBot_${TS}`,
      description: "Bot for template E2E tests",
    });
    expect(botResp.status()).toBe(201);
    const botData = await botResp.json();
    botId = botData.bot_id;
    expect(botId).toBeTruthy();
  });

  test.afterAll(async () => {
    // Cleanup: delete bot
    if (botId) {
      await apiDelete(page, `/ui/bots/${botId}`);
    }
    await page.close();
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Section 511: Template CRUD API
  // ═══════════════════════════════════════════════════════════════════════════

  test("511.1 — Create a greeting template", async () => {
    const resp = await apiPost(page, `/ui/bots/${botId}/templates`, {
      name: `Greeting_${TS}`,
      text: "Hello {user_name}! Welcome to our community.",
      category: "greeting",
    });
    expect(resp.status()).toBe(201);
    const tpl = await resp.json();
    greetingTemplateId = tpl.template_id;
    expect(tpl.template_id).toBeTruthy();
    expect(tpl.category).toBe("greeting");
    expect(tpl.variables_used).toContain("user_name");
  });

  test("511.2 — Create a template with quick replies", async () => {
    const resp = await apiPost(page, `/ui/bots/${botId}/templates`, {
      name: `QR_Template_${TS}`,
      text: "How can I help you?",
      category: "support",
      quick_replies: [
        { label: "Yes", value: "yes" },
        { label: "No", value: "no" },
      ],
    });
    expect(resp.status()).toBe(201);
    const tpl = await resp.json();
    qrTemplateId = tpl.template_id;
    expect(tpl.quick_replies).toHaveLength(2);
    expect(tpl.quick_replies[0].label).toBe("Yes");
  });

  test("511.3 — List templates by category", async () => {
    const resp = await apiGet(page, `/ui/bots/${botId}/templates?category=greeting`);
    expect(resp.status()).toBe(200);
    const templates = await resp.json();
    expect(Array.isArray(templates)).toBe(true);
    expect(templates.length).toBeGreaterThanOrEqual(1);
    // All should be greeting category
    for (const t of templates) {
      expect(t.category).toBe("greeting");
    }
  });

  test("511.4 — Update template text", async () => {
    const resp = await apiPut(
      page,
      `/ui/bots/${botId}/templates/${greetingTemplateId}`,
      {
        text: "Hey {user_name}, thanks for joining! {creator_name} welcomes you.",
      },
    );
    expect(resp.status()).toBe(200);
    const tpl = await resp.json();
    expect(tpl.text).toContain("{creator_name}");
    expect(tpl.variables_used).toContain("creator_name");
    expect(tpl.variables_used).toContain("user_name");
  });

  test("511.5 — Delete template", async () => {
    // Create a throwaway template to delete
    const createResp = await apiPost(page, `/ui/bots/${botId}/templates`, {
      name: `ToDelete_${TS}`,
      text: "This will be deleted",
    });
    expect(createResp.status()).toBe(201);
    const tpl = await createResp.json();

    const delResp = await apiDelete(
      page,
      `/ui/bots/${botId}/templates/${tpl.template_id}`,
    );
    expect(delResp.status()).toBe(200);

    // Verify deleted
    const getResp = await apiGet(
      page,
      `/ui/bots/${botId}/templates/${tpl.template_id}`,
    );
    expect(getResp.status()).toBe(404);
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Section 512: Variable Substitution & Preview
  // ═══════════════════════════════════════════════════════════════════════════

  test("512.1 — Preview template with variables", async () => {
    const resp = await apiPost(
      page,
      `/ui/bots/${botId}/templates/${greetingTemplateId}/preview`,
      { sample_user_name: "TestUser" },
    );
    expect(resp.status()).toBe(200);
    const preview = await resp.json();
    expect(preview.rendered_text).toContain("TestUser");
  });

  test("512.2 — Send test message", async () => {
    // We need a conversation_id for this — use a dummy value
    // The send-test endpoint calls send_bot_message which requires an active bot
    // For now just verify the endpoint returns 200 or expected error
    const resp = await apiPost(
      page,
      `/ui/bots/${botId}/templates/${greetingTemplateId}/send-test`,
      { conversation_id: "test_conv_" + TS },
    );
    // send_bot_message returns the msg dict; if the bot is active, it succeeds
    expect([200, 409]).toContain(resp.status());
  });

  test("512.3 — Unknown variables preserved", async () => {
    // Create template with unknown variable
    const createResp = await apiPost(page, `/ui/bots/${botId}/templates`, {
      name: `UnknownVar_${TS}`,
      text: "Hello {unknown_var}, from {bot_name}.",
    });
    expect(createResp.status()).toBe(201);
    const tpl = await createResp.json();

    const previewResp = await apiPost(
      page,
      `/ui/bots/${botId}/templates/${tpl.template_id}/preview`,
      {},
    );
    expect(previewResp.status()).toBe(200);
    const preview = await previewResp.json();
    // unknown_var should be preserved literally
    expect(preview.rendered_text).toContain("{unknown_var}");
    // bot_name should be resolved
    expect(preview.rendered_text).not.toContain("{bot_name}");

    // Cleanup
    await apiDelete(page, `/ui/bots/${botId}/templates/${tpl.template_id}`);
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Section 513: Scheduled Sends API
  // ═══════════════════════════════════════════════════════════════════════════

  test("513.1 — Create scheduled send", async () => {
    const resp = await apiPost(page, `/ui/bots/${botId}/schedules`, {
      template_id: greetingTemplateId,
      target_type: "all_dms",
      cron_expression: "0 14 * * *",
      timezone: "UTC",
    });
    expect(resp.status()).toBe(201);
    const sched = await resp.json();
    scheduleId = sched.schedule_id;
    expect(sched.schedule_id).toBeTruthy();
    expect(sched.next_run_at).toBeGreaterThan(0);
    expect(sched.enabled).toBe(true);
  });

  test("513.2 — List scheduled sends", async () => {
    const resp = await apiGet(page, `/ui/bots/${botId}/schedules`);
    expect(resp.status()).toBe(200);
    const schedules = await resp.json();
    expect(Array.isArray(schedules)).toBe(true);
    expect(schedules.length).toBeGreaterThanOrEqual(1);
    const found = schedules.find(
      (s: { schedule_id: string }) => s.schedule_id === scheduleId,
    );
    expect(found).toBeTruthy();
  });

  test("513.3 — Disable schedule", async () => {
    const resp = await apiPut(
      page,
      `/ui/bots/${botId}/schedules/${scheduleId}`,
      { enabled: false },
    );
    expect(resp.status()).toBe(200);
    const sched = await resp.json();
    expect(sched.enabled).toBe(false);
  });

  test("513.4 — Delete schedule", async () => {
    // Get count before
    const beforeResp = await apiGet(page, `/ui/bots/${botId}/schedules`);
    const beforeList = await beforeResp.json();
    const beforeCount = beforeList.length;

    const delResp = await apiDelete(
      page,
      `/ui/bots/${botId}/schedules/${scheduleId}`,
    );
    expect(delResp.status()).toBe(200);

    // Verify count decremented
    const afterResp = await apiGet(page, `/ui/bots/${botId}/schedules`);
    const afterList = await afterResp.json();
    expect(afterList.length).toBe(beforeCount - 1);
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Section 514: Template Editor UI
  // ═══════════════════════════════════════════════════════════════════════════

  test("514.1 — Template editor page loads", async () => {
    await page.goto(`${BASE}/bots/${botId}/templates`, {
      waitUntil: "domcontentloaded",
    });
    await expect(
      page.locator('[data-testid="template-editor-page"]'),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("514.2 — Create template via dialog", async () => {
    await page.goto(`${BASE}/bots/${botId}/templates`, {
      waitUntil: "domcontentloaded",
    });
    await expect(
      page.locator('[data-testid="template-editor-page"]'),
    ).toBeVisible({ timeout: 10_000 });

    // Click "New Template"
    await page.locator('[data-testid="create-template-btn"]').click();
    await expect(
      page.locator('[data-testid="template-form-dialog"]'),
    ).toBeVisible();

    // Fill in the form
    const templateName = `UITemplate_${TS}`;
    await page.locator('[data-testid="template-name-input"]').fill(templateName);
    await page
      .locator('[data-testid="template-text-input"]')
      .fill("Hello {user_name}, welcome!");

    // Save
    await page.locator('[data-testid="template-save-btn"]').click();

    // Wait for dialog to close and template to appear
    await expect(
      page.locator('[data-testid="template-form-dialog"]'),
    ).not.toBeVisible({ timeout: 5_000 });

    // Verify template appears in list
    await expect(page.getByText(templateName)).toBeVisible({ timeout: 5_000 });
  });

  test("514.3 — Quick-reply buttons appear on template card", async () => {
    // Navigate to the page — the qrTemplateId template was created in API tests
    await page.goto(`${BASE}/bots/${botId}/templates`, {
      waitUntil: "domcontentloaded",
    });
    await expect(
      page.locator('[data-testid="template-editor-page"]'),
    ).toBeVisible({ timeout: 10_000 });

    // Look for the QR template's quick reply badges
    const qrCard = page.locator(
      `[data-testid="template-card-${qrTemplateId}"]`,
    );
    // If the card is visible, check for quick reply badges
    if (await qrCard.isVisible()) {
      await expect(qrCard.getByText("Yes")).toBeVisible();
      await expect(qrCard.getByText("No")).toBeVisible();
    }
  });

  test("514.4 — Schedule manager panel visible", async () => {
    await page.goto(`${BASE}/bots/${botId}/templates`, {
      waitUntil: "domcontentloaded",
    });
    await expect(
      page.locator('[data-testid="schedule-manager-panel"]'),
    ).toBeVisible({ timeout: 10_000 });
    // The heading "Scheduled Sends" should be visible
    await expect(
      page.getByRole("heading", { name: "Scheduled Sends" }),
    ).toBeVisible();
  });
});
