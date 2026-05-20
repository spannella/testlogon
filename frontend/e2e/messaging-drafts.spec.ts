import { test, expect, type Browser, type Page } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const CHARLIE_ID = "e2e_charlie@test.local";
test.describe("messaging drafts lifecycle", () => {

  test("save/reload/load/remove draft persists across sessions", async ({ browser, page }) => {
    test.setTimeout(90_000);
    const createdConversationIds: string[] = [];
    const fixtureSuffix = Date.now();

    const conv = await createGroupConversation(page, `Draft E2E ${fixtureSuffix}`);
    createdConversationIds.push(conv.conversation_id);

    try {
      await gotoMessages(page, ALICE_ID);
      await openConversation(page, conv.title);

      const draftText = `draft-text-${fixtureSuffix}`;
      const composer = getComposer(page);
      await composer.fill(draftText);
      await page.getByRole("button", { name: "Save draft" }).click();
      await expect(page.locator("#main-content").getByText("Draft saved")).toBeVisible({ timeout: 8000 });
      await expectDraftVisible(page, draftText);

      // Draft persists after reload
      await reloadMessages(page);
      await openConversation(page, conv.title);
      await expectDraftVisible(page, draftText);

      // Draft visible in a second browser session
      const secondPage = await openAuthenticatedMessagesPage(browser, ALICE_ID);
      await openConversation(secondPage, conv.title);
      await expectDraftVisible(secondPage, draftText);

      // Remove all drafts from second session
      while (await secondPage.getByRole("button", { name: "Remove" }).first().isVisible().catch(() => false)) {
        await secondPage.getByRole("button", { name: "Remove" }).first().click();
        await secondPage.waitForTimeout(500);
      }
      await expectDraftHidden(secondPage, draftText);

      // Removal propagates to first session after clearing local + server drafts
      await cleanupConversationDrafts(page, createdConversationIds);
      await page.evaluate((convId) => {
        localStorage.removeItem(`messaging:drafts:${convId}`);
      }, conv.conversation_id);
      await reloadMessages(page);
      await openConversation(page, conv.title);
      await expectDraftHidden(page, draftText);

      // Load: save a fresh draft, reload, then load it
      await composer.fill(draftText);
      await page.getByRole("button", { name: "Save draft" }).click();
      await expect(page.locator("#main-content").getByText("Draft saved")).toBeVisible({ timeout: 8000 });
      await composer.fill("");
      await reloadMessages(page);
      await openConversation(page, conv.title);
      await page.getByRole("button", { name: "Load" }).first().click();
      await expect(composer).toHaveValue(draftText);

      await secondPage.close();
    } finally {
      await cleanupConversationDrafts(page, createdConversationIds);
    }
  });

  test("falls back locally when draft save API fails with auth/session error", async ({ page }) => {
    test.setTimeout(90_000);
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
      await expect(page.locator("#main-content").getByText("Draft saved")).toBeVisible({ timeout: 8000 });
      await expectDraftVisible(page, draftText);

      await reloadMessages(page);
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
    cwd: "/home/ubuntu/testlogon",
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
  await page.goto(`${BASE}/messages`, { waitUntil: "domcontentloaded" });
  await conversationsLoaded;
}

async function reloadMessages(page: Page) {
  const conversationsLoaded = page.waitForResponse(
    (r) => r.url().includes("/messaging/conversations")
      && r.request().method() === "GET"
      && !r.url().match(/\/conversations\/[^/]+$/),
    { timeout: 15_000 },
  );
  await page.reload({ waitUntil: "domcontentloaded" });
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
  await expect(page.getByText("Saved drafts")).toBeVisible({ timeout: 8000 });
  await expect(page.locator("p").filter({ hasText: draftText }).first()).toBeVisible({ timeout: 8000 });
}

async function expectDraftHidden(page: Page, draftText: string) {
  await expect(page.locator("p").filter({ hasText: draftText })).toHaveCount(0, { timeout: 8000 });
}

async function openAuthenticatedMessagesPage(browser: Browser, userId: string): Promise<Page> {
  const context = await browser.newContext();
  const page = await context.newPage();
  await gotoMessages(page, userId);
  return page;
}

async function createGroupConversation(page: Page, title: string): Promise<{ conversation_id: string; title: string }> {
  const resp = await page.request.post(`${API}/messaging/conversations/group`, {
    data: { participant_ids: [ALICE_ID, BOB_ID, CHARLIE_ID], title },
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
