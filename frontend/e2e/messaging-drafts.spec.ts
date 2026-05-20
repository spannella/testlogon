import { test, expect, type Page, type APIRequestContext } from "@playwright/test";
import { execSync } from "child_process";
import { randomUUID } from "crypto";

const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const CHARLIE_ID = "e2e_charlie@test.local";

test.describe("messaging drafts lifecycle", () => {
  test("draft CRUD via API: save, list, load, remove persists across requests", async ({ request }) => {
    test.setTimeout(60_000);
    const ts = Date.now();
    const conv = await createGroupBearer(request, `Draft E2E ${ts}`);
    const draftText = `draft-text-${ts}`;

    try {
      // Save a draft
      const saveResp = await request.post(
        `${API}/messaging/conversations/${conv.conversation_id}/drafts`,
        {
          data: { text: draftText },
          headers: { ...bearer(ALICE_ID), "Idempotency-Key": randomUUID() },
        },
      );
      expect(saveResp.ok(), `save failed: ${saveResp.status()}`).toBeTruthy();
      const saved = (await saveResp.json()).draft;
      expect(saved.draft_id).toBeTruthy();
      expect(saved.text).toBe(draftText);

      // List drafts — should include the one we just saved
      const listResp = await request.get(
        `${API}/messaging/conversations/${conv.conversation_id}/drafts?limit=50`,
        { headers: bearer(ALICE_ID) },
      );
      expect(listResp.ok()).toBeTruthy();
      const listed = await listResp.json();
      const items: Array<{ draft_id: string; text: string }> = listed.items ?? [];
      expect(items.some((d) => d.draft_id === saved.draft_id && d.text === draftText)).toBeTruthy();

      // Delete the draft
      const delResp = await request.delete(
        `${API}/messaging/conversations/${conv.conversation_id}/drafts/${saved.draft_id}`,
        { headers: bearer(ALICE_ID) },
      );
      expect(delResp.ok()).toBeTruthy();

      // Confirm deleted
      const listAfter = await request.get(
        `${API}/messaging/conversations/${conv.conversation_id}/drafts?limit=50`,
        { headers: bearer(ALICE_ID) },
      );
      expect(listAfter.ok()).toBeTruthy();
      const afterItems: Array<{ draft_id: string }> = ((await listAfter.json()).items ?? []);
      expect(afterItems.some((d) => d.draft_id === saved.draft_id)).toBeFalsy();
    } finally {
      await cleanupDraftsBearer(request, conv.conversation_id);
    }
  });

  test("UI shows saved drafts panel with Load/Remove buttons", async ({ browser }) => {
    test.setTimeout(90_000);
    const ts = Date.now();
    const session = getSessions()[ALICE_ID];

    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    const conv = await createGroupWithCsrf(page.request, `Draft E2E UI ${ts}`, session.csrf_token);
    const draftText = `draft-ui-${ts}`;

    try {
      // Pre-create a draft via API so we don't depend on UI save + server sync
      const saveResp = await page.request.post(
        `${API}/messaging/conversations/${conv.conversation_id}/drafts`,
        {
          data: { text: draftText },
          headers: {
            "x-csrf-token": session.csrf_token,
            "Idempotency-Key": randomUUID(),
          },
        },
      );
      expect(saveResp.ok(), `draft save failed: ${saveResp.status()}`).toBeTruthy();

      await gotoMessages(page);
      await openConversation(page, conv.title);

      // Drafts panel should show the pre-created draft
      await expect(page.getByText("Saved drafts")).toBeVisible({ timeout: 10_000 });
      await expect(page.locator("p").filter({ hasText: draftText }).first()).toBeVisible({ timeout: 8_000 });
      await expect(page.getByRole("button", { name: "Load" }).first()).toBeVisible();
      await expect(page.getByRole("button", { name: "Remove" }).first()).toBeVisible();

      // Click Load — composer should populate
      await page.getByRole("button", { name: "Load" }).first().click();
      await expect(page.locator("textarea").last()).toHaveValue(draftText);
    } finally {
      await cleanupDraftsCsrf(page.request, conv.conversation_id, session.csrf_token);
      await ctx.close();
    }
  });
});

function bearer(userId: string) {
  return { Authorization: `Bearer ${userId}` };
}

async function createGroupBearer(
  req: APIRequestContext,
  title: string,
): Promise<{ conversation_id: string; title: string }> {
  const resp = await req.post(`${API}/messaging/conversations/group`, {
    data: { participant_ids: [ALICE_ID, BOB_ID, CHARLIE_ID], title },
    headers: bearer(ALICE_ID),
  });
  expect(resp.ok(), `createGroup failed: ${resp.status()} ${await resp.text()}`).toBeTruthy();
  const body = await resp.json();
  return { conversation_id: body.conversation_id, title: body.title ?? title };
}

async function createGroupWithCsrf(
  req: APIRequestContext,
  title: string,
  csrfToken: string,
): Promise<{ conversation_id: string; title: string }> {
  const resp = await req.post(`${API}/messaging/conversations/group`, {
    data: { participant_ids: [ALICE_ID, BOB_ID, CHARLIE_ID], title },
    headers: { "x-csrf-token": csrfToken },
  });
  expect(resp.ok(), `createGroup failed: ${resp.status()} ${await resp.text()}`).toBeTruthy();
  const body = await resp.json();
  return { conversation_id: body.conversation_id, title: body.title ?? title };
}

async function cleanupDraftsBearer(req: APIRequestContext, conversationId: string) {
  const resp = await req.get(
    `${API}/messaging/conversations/${conversationId}/drafts?limit=100`,
    { headers: bearer(ALICE_ID) },
  );
  if (!resp.ok()) return;
  const items: Array<{ draft_id: string }> = ((await resp.json()).items ?? []);
  for (const d of items) {
    await req.delete(
      `${API}/messaging/conversations/${conversationId}/drafts/${d.draft_id}`,
      { headers: bearer(ALICE_ID) },
    );
  }
}

async function cleanupDraftsCsrf(req: APIRequestContext, conversationId: string, csrfToken: string) {
  const resp = await req.get(
    `${API}/messaging/conversations/${conversationId}/drafts?limit=100`,
  );
  if (!resp.ok()) return;
  const items: Array<{ draft_id: string }> = ((await resp.json()).items ?? []);
  for (const d of items) {
    await req.delete(
      `${API}/messaging/conversations/${conversationId}/drafts/${d.draft_id}`,
      { headers: { "x-csrf-token": csrfToken } },
    );
  }
}

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
  return _sessions!;
}

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto("http://localhost:3000/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

async function gotoMessages(page: Page) {
  const loaded = page.waitForResponse(
    (r) =>
      r.url().includes("/messaging/conversations") &&
      r.request().method() === "GET" &&
      !r.url().match(/\/conversations\/[^/]+$/),
    { timeout: 15_000 },
  );
  await page.goto("http://localhost:3000/messages", { waitUntil: "domcontentloaded" });
  await loaded;
}

async function openConversation(page: Page, title: string) {
  const entry = page.locator("li, [role='listitem'], button").filter({ hasText: title }).first();
  await expect(entry).toBeVisible({ timeout: 10_000 });
  await entry.click();
  await expect(page.locator("textarea").last()).toBeVisible({ timeout: 10_000 });
}
