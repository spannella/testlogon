import { test, expect, type Browser, type Page } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const SHOULD_RUN = process.env.RUN_MESSAGING_E2E === "1";

test.describe("messaging drafts lifecycle", () => {
  test.skip(!SHOULD_RUN, "Set RUN_MESSAGING_E2E=1 to run messaging draft e2e tests");

  test("save/reload/load/isolate/remove draft across conversations and sessions", async ({ browser, page }) => {
    const createdConversationIds: string[] = [];
    const fixtureSuffix = Date.now();

    const convA = await createGroupConversation(page, `Draft E2E A ${fixtureSuffix}`);
    const convB = await createGroupConversation(page, `Draft E2E B ${fixtureSuffix}`);
    createdConversationIds.push(convA.conversation_id, convB.conversation_id);

    try {
      await gotoMessages(page, ALICE_ID);
      await openConversation(page, convA.title);

      const draftText = `draft-text-${fixtureSuffix}`;
      const composer = getComposer(page);
      await composer.fill(draftText);
      await page.getByRole("button", { name: "Save draft" }).click();
      await expect(page.getByText("Draft saved")).toBeVisible();
      await expectDraftVisible(page, draftText);

      await page.reload({ waitUntil: "networkidle" });
      await openConversation(page, convA.title);
      await expectDraftVisible(page, draftText);

      await page.getByRole("button", { name: "Load" }).first().click();
      await expect(composer).toHaveValue(draftText);

      await openConversation(page, convB.title);
      await expectDraftHidden(page, draftText);

      const secondPage = await openAuthenticatedMessagesPage(browser, ALICE_ID);
      await openConversation(secondPage, convA.title);
      await expectDraftVisible(secondPage, draftText);

      await secondPage.getByRole("button", { name: "Remove" }).first().click();
      await expectDraftHidden(secondPage, draftText);

      await page.reload({ waitUntil: "networkidle" });
      await openConversation(page, convA.title);
      await expectDraftHidden(page, draftText);

      await secondPage.close();
    } finally {
      await cleanupConversationDrafts(page, createdConversationIds);
    }
  });

  test("falls back locally when draft save API fails with auth/session error", async ({ page }) => {
    const createdConversationIds: string[] = [];
    const fixtureSuffix = Date.now();
    const conv = await createGroupConversation(page, `Draft E2E Auth ${fixtureSuffix}`);
    createdConversationIds.push(conv.conversation_id);

    try {
      await gotoMessages(page, ALICE_ID);
      await openConversation(page, conv.title);

      const draftText = `draft-auth-fallback-${fixtureSuffix}`;
      await getComposer(page).fill(draftText);

      await page.route(`**/messaging/conversations/${conv.conversation_id}/drafts`, async (route) => {
        if (route.request().method() === "POST") {
          await route.fulfill({
            status: 401,
            contentType: "application/json",
            body: JSON.stringify({ detail: "Session expired" }),
          });
          return;
        }
        await route.continue();
      }, { times: 1 });

      await page.getByRole("button", { name: "Save draft" }).click();
      await expect(page.getByText("Draft saved")).toBeVisible();
      await expectDraftVisible(page, draftText);

      await page.reload({ waitUntil: "networkidle" });
      await openConversation(page, conv.title);
      await expectDraftVisible(page, draftText);
    } finally {
      await cleanupConversationDrafts(page, createdConversationIds);
    }
  });
});

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
  if (_sessions) return _sessions;
  const raw = execSync("python3 e2e_session_setup.py", {
    cwd: "/workspace/testlogon",
    timeout: 30_000,
  }).toString();
  _sessions = JSON.parse(raw);
  return _sessions;
}

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

async function gotoMessages(page: Page, userId: string) {
  await injectAuth(page, userId);
  const conversationsLoaded = page.waitForResponse(
    (r) => r.url().includes("/messaging/conversations")
      && r.request().method() === "GET"
      && !r.url().match(/\/conversations\/[^/]+$/),
    { timeout: 15_000 },
  );
  await page.goto(`${BASE}/messages`, { waitUntil: "networkidle" });
  await conversationsLoaded;
}

async function openConversation(page: Page, title: string) {
  const conversation = page.locator("li, [role='listitem'], button").filter({ hasText: title }).first();
  await expect(conversation).toBeVisible({ timeout: 10_000 });
  await conversation.click();
  await expect(getComposer(page)).toBeVisible({ timeout: 10_000 });
}

function getComposer(page: Page) {
  return page.locator("textarea").last();
}

async function expectDraftVisible(page: Page, draftText: string) {
  await expect(page.getByText("Saved drafts")).toBeVisible();
  await expect(page.getByText(draftText)).toBeVisible();
}

async function expectDraftHidden(page: Page, draftText: string) {
  await expect(page.getByText(draftText)).toHaveCount(0);
}

async function openAuthenticatedMessagesPage(browser: Browser, userId: string): Promise<Page> {
  const context = await browser.newContext();
  const page = await context.newPage();
  await gotoMessages(page, userId);
  return page;
}

async function createGroupConversation(page: Page, title: string): Promise<{ conversation_id: string; title: string }> {
  const resp = await page.request.post(`${API}/messaging/conversations/group`, {
    data: { participant_ids: [BOB_ID], title },
    headers: { Authorization: `Bearer ${ALICE_ID}` },
  });
  expect(resp.ok()).toBeTruthy();
  const body = await resp.json();
  return {
    conversation_id: body.conversation_id,
    title: body.title ?? title,
  };
}

async function cleanupConversationDrafts(page: Page, conversationIds: string[]) {
  for (const conversationId of conversationIds) {
    const listResp = await page.request.get(`${API}/messaging/conversations/${conversationId}/drafts?limit=100`, {
      headers: { Authorization: `Bearer ${ALICE_ID}` },
    });
    if (!listResp.ok()) continue;
    const body = await listResp.json();
    for (const draft of body.items ?? []) {
      await page.request.delete(`${API}/messaging/conversations/${conversationId}/drafts/${draft.draft_id}`, {
        headers: { Authorization: `Bearer ${ALICE_ID}` },
      });
    }
  }
}
