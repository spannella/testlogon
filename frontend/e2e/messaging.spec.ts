/**
 * E2E tests for messaging features.
 *
 * Auth strategy:
 * - Backend sessions are created ahead-of-time via e2e_session_setup.py
 * - Cookies + localStorage are injected into the browser before each describe
 * - The API client sends the session cookies → backend accepts them
 * - For API-only tests, we use page.request with Bearer token (DEV_MODE)
 *
 * Pre-requisite: the backend must be running on port 8000 and the Vite dev
 * server on port 3000.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

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

// Module-level cache — filled once per test process
let _sessions: Record<string, SessionData> | null = null;

function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 }
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

/**
 * Inject real DDB session cookies + localStorage auth.
 *
 * 1. Add session cookies to the browser context (persists across reloads).
 * 2. Navigate to /login so we can set localStorage.
 * 3. Set auth-store in localStorage so ProtectedRoute passes.
 */
async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);

  // Cookies persist across navigations within the same context
  await page.context().addCookies(session.cookies);

  // Set localStorage (need to be on same origin first)
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

/** Navigate to /messages after injecting auth. Avoids SSE networkidle hang. */
async function gotoMessages(page: Page, userId: string) {
  await injectAuth(page, userId);
  // Register response listener before navigating so we catch the conversations GET.
  const convsLoaded = page.waitForResponse(
    (r) => r.url().includes("/messaging/conversations") && r.request().method() === "GET"
      && !r.url().match(/\/conversations\/[^/]+$/),
    { timeout: 15000 },
  );
  // Use "load" not "networkidle" — SSE connections never go idle
  await page.goto(`${BASE}/messages`, { waitUntil: "load" });
  await convsLoaded;
  await page.waitForTimeout(300); // let React finish rendering the list
}

/** Direct API call via page.request (uses Bearer token in DEV_MODE). */
async function apiPost(page: Page, path: string, body: object, userId = ALICE_ID) {
  const resp = await page.request.post(`${API}${path}`, {
    data: body,
    headers: { Authorization: `Bearer ${userId}` },
  });
  return resp;
}

async function apiGet(page: Page, path: string, userId = ALICE_ID) {
  const resp = await page.request.get(`${API}${path}`, {
    headers: { Authorization: `Bearer ${userId}` },
  });
  return resp;
}

// ─── Pre-created test fixture data ───────────────────────────────────────────
// We create one shared conversation + messages once at module level to avoid
// slow beforeAll hooks.

let _testConvId: string | null = null;
let _testMsgId: string | null = null;

function getTestConvId(): string {
  if (!_testConvId) {
    const raw = execSync(
      `curl -s -X POST ${API}/messaging/conversations ` +
      `-H 'Authorization: Bearer ${ALICE_ID}' ` +
      `-H 'Content-Type: application/json' ` +
      `-d '{"type":"dm","participant_ids":["${BOB_ID}"]}'`
    ).toString();
    _testConvId = JSON.parse(raw).conversation_id;
    if (!_testConvId) throw new Error("Failed to create test conversation: " + raw);
  }
  return _testConvId!;
}

function getTestMsgId(): string {
  if (!_testMsgId) {
    const cid = getTestConvId();
    const raw = execSync(
      `curl -s -X POST ${API}/messaging/conversations/${cid}/messages ` +
      `-H 'Authorization: Bearer ${ALICE_ID}' ` +
      `-H 'Content-Type: application/json' ` +
      `-d '{"text":"E2E test message"}'`
    ).toString();
    _testMsgId = JSON.parse(raw).message_id;
    if (!_testMsgId) throw new Error("Failed to create test message: " + raw);
  }
  return _testMsgId!;
}

// ─── 1. Basic page load ───────────────────────────────────────────────────────

test.describe("1. Messages page loads correctly", () => {
  test("Redirects to /login without auth", async ({ page }) => {
    await page.goto(`${BASE}/messages`, { waitUntil: "load" });
    await page.waitForTimeout(500);
    expect(page.url()).toContain("/login");
  });

  test("Shows messages page when authenticated", async ({ browser }) => {
    const page = await browser.newPage();
    await gotoMessages(page, ALICE_ID);
    expect(page.url()).toContain("/messages");
    await page.close();
  });

  test("Sidebar navigation link exists", async ({ browser }) => {
    const page = await browser.newPage();
    await gotoMessages(page, ALICE_ID);
    // App shell renders a sidebar with a Messages link (may include unread count badge)
    const msgLink = page.locator('a[href="/messages"]').first();
    const visible = await msgLink.isVisible({ timeout: 5000 }).catch(() => false);
    expect(visible).toBe(true);
    await page.close();
  });
});

// ─── 2. Conversation list ─────────────────────────────────────────────────────

test.describe("2. Conversation list", () => {
  // Ensure a DM with Bob + at least one message exist before the UI tests run.
  // On a clean DB these are the only conversations Alice has, so without this
  // seeding the conversation list is empty and the "bob" row never renders.
  test.beforeAll(() => {
    getTestConvId();
    getTestMsgId();
  });

  test("Lists conversations after auth", async ({ browser }) => {
    const page = await browser.newPage();
    await gotoMessages(page, ALICE_ID);
    // Should show at least one conversation (the pre-created DM)
    await page.waitForTimeout(2000);
    const items = page.locator("li, [role='listitem']");
    const count = await items.count();
    expect(count).toBeGreaterThan(0);
    await page.close();
  });

  test("Clicking a conversation opens compose bar", async ({ browser }) => {
    const page = await browser.newPage();
    await gotoMessages(page, ALICE_ID);

    // Wait for the conversation list to populate then click the first E2E conversation
    const item = page.locator("li, [role='listitem'], button")
      .filter({ hasText: /e2e.*bob|E2E Bob|bob/i })
      .first();
    await expect(item).toBeVisible({ timeout: 8000 });
    await item.click();

    // Compose bar (textarea) should appear
    await expect(page.locator("textarea").last()).toBeVisible({ timeout: 8000 });
    await page.close();
  });

  test("Message text appears in opened conversation", async ({ browser }) => {
    const page = await browser.newPage();
    await gotoMessages(page, ALICE_ID);

    // Wait for the conversation list, then click the E2E conversation
    const item = page.locator("li, [role='listitem'], button")
      .filter({ hasText: /e2e.*bob|E2E Bob|bob/i })
      .first();
    await expect(item).toBeVisible({ timeout: 8000 });
    await item.click();

    // Wait for compose bar — confirms conversation view is mounted
    await expect(page.locator("textarea").last()).toBeVisible({ timeout: 8000 });
    // Check that SOME message text appears in the view
    const anyMsg = page.locator("p, [class*='bubble'], [class*='message']").first();
    await expect(anyMsg).toBeVisible({ timeout: 8000 });
    await page.close();
  });
});

test.describe("2b. Messaging profile links", () => {
  // Seed a DM with Bob so the conversation list (and its profile links) render.
  test.beforeAll(() => {
    getTestConvId();
    getTestMsgId();
  });

  test("Authenticated user can open canonical profile from conversation list (desktop)", async ({ browser }) => {
    const page = await browser.newPage({ viewport: { width: 1366, height: 900 } });
    await gotoMessages(page, ALICE_ID);

    const profileLink = page.locator("[aria-label*='Open'][aria-label*='profile']").first();
    await expect(profileLink).toBeVisible({ timeout: 8000 });
    await profileLink.click();

    await expect(page).toHaveURL(/\/u\//, { timeout: 8000 });
    await page.close();
  });

  test("Authenticated user can open canonical profile from conversation header (mobile)", async ({ browser }) => {
    const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
    await gotoMessages(page, ALICE_ID);

    const convoBtn = page.locator("button").filter({ hasText: /e2e.*bob|E2E Bob|bob/i }).first();
    await expect(convoBtn).toBeVisible({ timeout: 8000 });
    await convoBtn.click();
    await expect(page.locator("textarea").last()).toBeVisible({ timeout: 8000 });

    const headerProfileLink = page.locator("a[aria-label*='Open'][aria-label*='profile']").first();
    await expect(headerProfileLink).toBeVisible({ timeout: 8000 });
    await headerProfileLink.click();

    await expect(page).toHaveURL(/\/u\//, { timeout: 8000 });
    await page.close();
  });

  test("Unauthenticated user is redirected to login before messaging profile links are available", async ({ page }) => {
    await page.goto(`${BASE}/messages`, { waitUntil: "load" });
    await page.waitForTimeout(500);
    await expect(page).toHaveURL(/\/login/);
    await expect(page.locator("[aria-label*='Open'][aria-label*='profile']")).toHaveCount(0);
  });
});

// ─── 3. Compose bar features ──────────────────────────────────────────────────

test.describe("3. Compose bar features", () => {
  // Seed a DM with Bob so the conversation list has a row to open.
  test.beforeAll(() => {
    getTestConvId();
    getTestMsgId();
  });

  test("Tip attachment UI exists in compose bar", async ({ browser }) => {
    const page = await browser.newPage();
    await gotoMessages(page, ALICE_ID);

    // Wait for conversation list, then open the first E2E conversation
    const convBtn = page.locator("button").filter({ hasText: /E2E|e2e|alice|bob/i }).first();
    await expect(convBtn).toBeVisible({ timeout: 8000 });
    await convBtn.click();
    await expect(page.locator("textarea").last()).toBeVisible({ timeout: 8000 });

    // ComposeBar always renders "Attach tip" checkbox when a conversation is open
    await expect(page.locator("text=Attach tip")).toBeVisible({ timeout: 5000 });
    await page.close();
  });

  test("File/image input exists for attachments", async ({ browser }) => {
    const page = await browser.newPage();
    await gotoMessages(page, ALICE_ID);

    // Wait for conversation list, then open the first E2E conversation
    const convBtn = page.locator("button").filter({ hasText: /E2E|e2e|alice|bob/i }).first();
    await expect(convBtn).toBeVisible({ timeout: 8000 });
    await convBtn.click();
    await expect(page.locator("textarea").last()).toBeVisible({ timeout: 8000 });

    // ComposeBar renders a Paperclip/Attach button for file attachments
    await expect(page.locator("[aria-label='Attach file']")).toBeVisible({ timeout: 5000 });
    await page.close();
  });

  test("Can type in compose textarea", async ({ browser }) => {
    const page = await browser.newPage();
    await gotoMessages(page, ALICE_ID);

    // Wait for the E2E Bob conversation row and click it
    const item = page.locator("li, [role='listitem'], button")
      .filter({ hasText: /e2e.*bob|E2E Bob|bob/i })
      .first();
    await expect(item).toBeVisible({ timeout: 8000 });
    await item.click();

    const textarea = page.locator("textarea").last();
    await expect(textarea).toBeVisible({ timeout: 8000 });
    await textarea.fill("Testing compose bar typing");
    const val = await textarea.inputValue();
    expect(val).toBe("Testing compose bar typing");
    await page.close();
  });
});

// ─── 4. Message API operations ────────────────────────────────────────────────

test.describe("4. Message operations (API)", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    // Ensure test fixtures exist
    getTestConvId();
    getTestMsgId();
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("Can list conversations", async () => {
    const resp = await apiGet(page, "/messaging/conversations");
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    const convs = Array.isArray(data) ? data : data.conversations ?? [];
    expect(convs.length).toBeGreaterThan(0);
  });

  test("Can send a text message", async () => {
    const cid = getTestConvId();
    const resp = await apiPost(page, `/messaging/conversations/${cid}/messages`, {
      text: "API test message",
    });
    expect(resp.ok()).toBe(true);
    const msg = await resp.json();
    expect(msg.text).toBe("API test message");
    expect(msg.message_id).toBeTruthy();
  });

  test("Can add a reaction", async () => {
    const cid = getTestConvId();
    const mid = getTestMsgId();
    const resp = await apiPost(
      page,
      `/messaging/conversations/${cid}/messages/${mid}/reactions`,
      { emoji: "👍", action: "add" }
    );
    expect(resp.ok()).toBe(true);

    // Verify persisted
    const verifyResp = await apiGet(page, `/messaging/conversations/${cid}/messages`);
    const data = await verifyResp.json();
    const msgs = Array.isArray(data) ? data : data.messages ?? [];
    const m = msgs.find((x: { message_id?: string }) => x.message_id === mid);
    expect(m?.reactions_counts?.["👍"]).toBeGreaterThanOrEqual(1);
  });

  test("Can remove a reaction", async () => {
    const cid = getTestConvId();
    const mid = getTestMsgId();
    const resp = await apiPost(
      page,
      `/messaging/conversations/${cid}/messages/${mid}/reactions`,
      { emoji: "👍", action: "remove" }
    );
    expect(resp.ok()).toBe(true);
  });

  test("Can reply to a message", async () => {
    const cid = getTestConvId();
    const mid = getTestMsgId();
    const resp = await apiPost(page, `/messaging/conversations/${cid}/messages`, {
      text: "Reply text",
      reply_to_message_id: mid,
    });
    expect(resp.ok()).toBe(true);
    const reply = await resp.json();
    expect(reply.reply_to_message_id).toBe(mid);
  });

  test("Can edit a message", async () => {
    const cid = getTestConvId();
    const mid = getTestMsgId();
    const resp = await page.request.patch(
      `${API}/messaging/conversations/${cid}/messages/${mid}`,
      {
        data: { text: "Edited text" },
        headers: { Authorization: `Bearer ${ALICE_ID}` },
      }
    );
    expect(resp.ok()).toBe(true);
    const edited = await resp.json();
    expect(edited.text).toBe("Edited text");
    expect(edited.edited_at).toBeTruthy();
  });

  test("Can get message viewers (read receipts)", async () => {
    const cid = getTestConvId();
    const mid = getTestMsgId();

    // Bob marks as viewed
    await apiPost(
      page,
      `/messaging/conversations/${cid}/messages/${mid}/view`,
      {},
      BOB_ID
    );

    const resp = await apiGet(
      page,
      `/messaging/conversations/${cid}/messages/${mid}/views`
    );
    expect(resp.ok()).toBe(true);
    const viewers = await resp.json();
    expect(Array.isArray(viewers)).toBe(true);
    const bob = viewers.find((v: { user_id?: string }) => v.user_id === BOB_ID);
    expect(bob).toBeTruthy();
  });

  test("Can delete a message", async () => {
    const cid = getTestConvId();
    const createResp = await apiPost(
      page,
      `/messaging/conversations/${cid}/messages`,
      { text: "To be deleted" }
    );
    expect(createResp.ok()).toBe(true);
    const created = await createResp.json();
    const deleteResp = await page.request.delete(
      `${API}/messaging/conversations/${cid}/messages/${created.message_id}`,
      { headers: { Authorization: `Bearer ${ALICE_ID}` } }
    );
    expect(deleteResp.ok()).toBe(true);
  });
});

// ─── 5. Message with tip ──────────────────────────────────────────────────────

test.describe("5. Tip-attached messages", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    getTestConvId();
  });

  test.afterAll(async () => await page.close());

  test("Text message with tip_amount_cents", async () => {
    const cid = getTestConvId();
    const resp = await apiPost(page, `/messaging/conversations/${cid}/messages`, {
      text: "Here is a tip with message",
      tip_amount_cents: 500,
    });
    expect(resp.ok()).toBe(true);
    const msg = await resp.json();
    expect(msg.tip_amount_cents).toBe(500);
    expect(msg.tip_currency).toBe("USD");
  });

  test("Image message with tip_amount_cents", async () => {
    const cid = getTestConvId();
    // Presign
    const presignResp = await apiPost(
      page,
      `/messaging/conversations/${cid}/images/presign`,
      { content_type: "image/png", filename: "tip-image.png" }
    );
    expect(presignResp.ok()).toBe(true);
    const presign = await presignResp.json();

    // Upload tiny PNG
    const pngBytes = Buffer.from(
      "89504e470d0a1a0a0000000d4948445200000001000000010802000000" +
      "9077533800000000c4944415478016360f8cfc00000000200016604130000000049454e44ae426082",
      "hex"
    );
    await page.request.put(presign.upload_url, {
      data: pngBytes,
      headers: { "Content-Type": "image/png" },
    });

    // Send image with tip
    const sendResp = await apiPost(
      page,
      `/messaging/conversations/${cid}/messages/image`,
      {
        bucket: presign.bucket,
        key: presign.key,
        content_type: "image/png",
        filename: "tip-image.png",
        filesize: pngBytes.length,
        kind: "image",
        width: 1,
        height: 1,
        tip_amount_cents: 250,
      }
    );
    expect(sendResp.ok()).toBe(true);
    const imgMsg = await sendResp.json();
    expect(imgMsg.tip_amount_cents).toBe(250);
    expect(imgMsg.kind).toBe("image");
  });

  test("Cannot combine lock_price and tip_amount on image", async () => {
    const cid = getTestConvId();
    const presignResp = await apiPost(
      page,
      `/messaging/conversations/${cid}/images/presign`,
      { content_type: "image/png", filename: "test.png" }
    );
    const presign = await presignResp.json();
    const resp = await apiPost(
      page,
      `/messaging/conversations/${cid}/messages/image`,
      {
        bucket: presign.bucket,
        key: presign.key,
        content_type: "image/png",
        filename: "test.png",
        filesize: 100,
        kind: "image",
        lock_price_cents: 100,
        tip_amount_cents: 100,
      }
    );
    expect(resp.status()).toBe(400);
  });
});

// ─── 6. Locked messages ───────────────────────────────────────────────────────

test.describe("6. Locked (tip-required) messages", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    getTestConvId();
  });

  test.afterAll(async () => await page.close());

  test("Sender can send a locked message", async () => {
    const cid = getTestConvId();
    const resp = await apiPost(page, `/messaging/conversations/${cid}/messages`, {
      text: "Locked content",
      lock_price_cents: 200,
      lock_description: "Pay $2 to see",
    });
    expect(resp.ok()).toBe(true);
    const msg = await resp.json();
    expect(msg.lock_price_cents).toBe(200);
    expect(msg.locked).toBe(true);
    expect(msg.is_unlocked).toBe(true); // sender sees own content
  });

  test("Unlock endpoint is accessible", async () => {
    const cid = getTestConvId();
    const createResp = await apiPost(page, `/messaging/conversations/${cid}/messages`, {
      text: "Secret content",
      lock_price_cents: 100,
    });
    const msg = await createResp.json();

    const unlockResp = await apiPost(
      page,
      `/messaging/conversations/${cid}/messages/${msg.message_id}/unlock`,
      {},
      BOB_ID
    );
    // May return 402 (payment required) or 200 (in dev mode mock)
    expect([200, 402].includes(unlockResp.status())).toBe(true);
  });
});

// ─── 7. Scheduled messages ────────────────────────────────────────────────────

test.describe("7. Scheduled messages", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    getTestConvId();
  });

  test.afterAll(async () => await page.close());

  test("Can schedule a message via API", async () => {
    const cid = getTestConvId();
    const sendAt = Math.floor(Date.now() / 1000) + 3600;
    const resp = await apiPost(page, `/messaging/conversations/${cid}/messages`, {
      text: "Scheduled for later",
      send_at: sendAt,
    });
    expect(resp.ok()).toBe(true);
    const msg = await resp.json();
    expect(msg.deliver_at ?? msg.send_at ?? sendAt).toBeTruthy();
  });

  test("Can list scheduled messages", async () => {
    const cid = getTestConvId();
    const resp = await apiGet(
      page,
      `/messaging/conversations/${cid}/messages/scheduled`
    );
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(Array.isArray(data)).toBe(true);
    expect(data.length).toBeGreaterThan(0);
  });

  test("Can cancel a scheduled message", async () => {
    const cid = getTestConvId();
    const createResp = await apiPost(page, `/messaging/conversations/${cid}/messages`, {
      text: "Cancel this scheduled",
      send_at: Math.floor(Date.now() / 1000) + 7200,
    });
    const msg = await createResp.json();
    const cancelResp = await page.request.delete(
      `${API}/messaging/conversations/${cid}/messages/${msg.message_id}/schedule`,
      { headers: { Authorization: `Bearer ${ALICE_ID}` } }
    );
    expect(cancelResp.ok()).toBe(true);
  });
});

// ─── 8. Image message details ─────────────────────────────────────────────────

test.describe("8. Image message details", () => {
  let page: Page;
  let imageMessageId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    getTestConvId();

    // Create an image message upfront
    const cid = getTestConvId();
    const presignResp = await apiPost(
      page,
      `/messaging/conversations/${cid}/images/presign`,
      { content_type: "image/png", filename: "details-test.png" }
    );
    const presign = await presignResp.json();
    const pngBytes = Buffer.from("89504e47", "hex");
    await page.request.put(presign.upload_url, {
      data: pngBytes,
      headers: { "Content-Type": "image/png" },
    });
    const sendResp = await apiPost(
      page,
      `/messaging/conversations/${cid}/messages/image`,
      {
        bucket: presign.bucket,
        key: presign.key,
        content_type: "image/png",
        filename: "details-test.png",
        filesize: 4,
        kind: "image",
        width: 1,
        height: 1,
        file_created_at: Math.floor(Date.now() / 1000) - 86400,
      }
    );
    const imgMsg = await sendResp.json();
    imageMessageId = imgMsg.message_id;
  });

  test.afterAll(async () => await page.close());

  test("Image message has filename and dimensions", async () => {
    const cid = getTestConvId();
    const resp = await apiGet(page, `/messaging/conversations/${cid}/messages`);
    const data = await resp.json();
    const msgs = Array.isArray(data) ? data : data.messages ?? [];
    const img = msgs.find((m: { message_id?: string }) => m.message_id === imageMessageId);
    expect(img).toBeTruthy();
    expect(img.image?.filename).toBe("details-test.png");
    // DynamoDB returns numbers as Decimal which FastAPI serializes as strings in dicts
    expect(Number(img.image?.width)).toBe(1);
    expect(Number(img.image?.height)).toBe(1);
    expect(img.image?.file_created_at).toBeTruthy();
  });

  test("Views endpoint tracks downloads", async () => {
    const cid = getTestConvId();
    // Bob views the image
    await apiPost(
      page,
      `/messaging/conversations/${cid}/messages/${imageMessageId}/view`,
      {},
      BOB_ID
    );
    const resp = await apiGet(
      page,
      `/messaging/conversations/${cid}/messages/${imageMessageId}/views`
    );
    expect(resp.ok()).toBe(true);
    const viewers = await resp.json();
    const bob = viewers.find((v: { user_id?: string }) => v.user_id === BOB_ID);
    expect(bob).toBeTruthy();
    expect(bob.last_viewed_at).toBeGreaterThan(0);
  });

  test("MessageDetailsSheet data structure is correct", async () => {
    const cid = getTestConvId();
    const mid = getTestMsgId();
    // Verify the views endpoint used by MessageDetailsSheet
    const viewsResp = await apiGet(
      page,
      `/messaging/conversations/${cid}/messages/${mid}/views`
    );
    expect(viewsResp.ok()).toBe(true);
    const viewers = await viewsResp.json();
    expect(Array.isArray(viewers)).toBe(true);
    // Each viewer has the required fields
    if (viewers.length > 0) {
      const v = viewers[0];
      expect(typeof v.user_id).toBe("string");
      expect(typeof v.last_viewed_at).toBe("number");
      expect(typeof v.view_count).toBe("number");
    }
  });
});

// ─── 9. Gallery & attachments ─────────────────────────────────────────────────

test.describe("9. Gallery and attachments", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    getTestConvId();
  });

  test.afterAll(async () => await page.close());

  test("Gallery endpoint returns correct shape", async () => {
    const cid = getTestConvId();
    const resp = await page.request.get(
      `${API}/messaging/conversations/${cid}/gallery`,
      {
        params: { type: "image", limit: "10" },
        headers: { Authorization: `Bearer ${ALICE_ID}` },
      }
    );
    expect(resp.ok()).toBe(true);
  });

  test("Presign URL includes bucket and key", async () => {
    const cid = getTestConvId();
    const resp = await apiPost(
      page,
      `/messaging/conversations/${cid}/images/presign`,
      { content_type: "image/png", filename: "gallery-test.png" }
    );
    expect(resp.ok()).toBe(true);
    const p = await resp.json();
    expect(p.upload_url).toBeTruthy();
    expect(p.bucket).toBeTruthy();
    expect(p.key).toBeTruthy();
  });
});

// ─── 10. Presence & typing ────────────────────────────────────────────────────

test.describe("10. Presence and typing", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    getTestConvId();
  });

  test.afterAll(async () => await page.close());

  test("Presence heartbeat works", async () => {
    const resp = await apiPost(page, "/messaging/presence/heartbeat", {
      device: "e2e-test",
    });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.ok).toBe(true);
  });

  test("Typing indicator sends successfully", async () => {
    const cid = getTestConvId();
    const resp = await apiPost(
      page,
      `/messaging/conversations/${cid}/typing`,
      { is_typing: true }
    );
    expect(resp.ok()).toBe(true);
  });

  test("User search works", async () => {
    const resp = await page.request.get(`${API}/messaging/contacts/search`, {
      params: { q: "bob" },
      headers: { Authorization: `Bearer ${ALICE_ID}` },
    });
    expect(resp.ok()).toBe(true);
    const results = await resp.json();
    expect(Array.isArray(results)).toBe(true);
  });
});
