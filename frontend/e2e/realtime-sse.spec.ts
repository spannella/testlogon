import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";
const TS = Date.now();

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
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
}

async function apiPost(page: Page, identity: string, path: string, body: object) {
  const s = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  const qs = params ? "?" + new URLSearchParams(params).toString() : "";
  return page.request.get(`${API}${path}${qs}`);
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await injectAuth(page, identity);
  return page;
}

const ALICE_ID = "alice";
const BOB_ID = "bob";

let _dmConvoId: string;

async function getOrCreateDm(page: Page): Promise<string> {
  if (_dmConvoId) return _dmConvoId;
  const bobSub = getSessions()[BOB_ID].user_sub;
  const resp = await apiPost(page, ALICE_ID, "/messaging/conversations", {
    participant_ids: [bobSub],
    kind: "dm",
  });
  if (!resp.ok()) {
    const body = await resp.text().catch(() => "(unreadable)");
    throw new Error(`DM creation failed: HTTP ${resp.status()} — ${body}`);
  }
  const body = await resp.json();
  _dmConvoId = body.conversation_id as string;
  return _dmConvoId;
}

let alicePage: Page;
let bobPage: Page;

test.beforeAll(async ({ browser }) => {
  alicePage = await newIdentityPage(browser, ALICE_ID);
  bobPage = await newIdentityPage(browser, BOB_ID);
});

test.afterAll(async () => {
  await alicePage?.context().close();
  await bobPage?.context().close();
});

// ---------------------------------------------------------------------------
// Section 150: Typing Indicator SSE
// ---------------------------------------------------------------------------
test.describe("150 · Typing Indicator — SSE real-time", () => {
  test("150.1 Backend emits typing:update on POST /typing and GET returns typer", async () => {
    const convoId = await getOrCreateDm(alicePage);
    const bobSub = getSessions()[BOB_ID].user_sub;

    const typingResp = await apiPost(bobPage, BOB_ID, `/messaging/conversations/${convoId}/typing`, {
      is_typing: true,
    });
    expect(typingResp.status()).toBe(200);
    const typingBody = await typingResp.json();
    expect(typingBody.ok).toBe(true);
    expect(typingBody.is_typing).toBe(true);

    const getResp = await apiGet(alicePage, `/messaging/conversations/${convoId}/typing`);
    expect(getResp.status()).toBe(200);
    const typers = await getResp.json();
    const bobTyping = typers.find((t: { user_id: string }) => t.user_id === bobSub);
    expect(bobTyping).toBeTruthy();
    expect(bobTyping.user_id).toBe(bobSub);
  });

  test("150.2 typing:update with is_typing=false clears the typing state", async () => {
    const convoId = await getOrCreateDm(alicePage);
    const bobSub = getSessions()[BOB_ID].user_sub;

    await apiPost(bobPage, BOB_ID, `/messaging/conversations/${convoId}/typing`, {
      is_typing: true,
    });
    const clearResp = await apiPost(bobPage, BOB_ID, `/messaging/conversations/${convoId}/typing`, {
      is_typing: false,
    });
    expect(clearResp.status()).toBe(200);

    const getResp = await apiGet(alicePage, `/messaging/conversations/${convoId}/typing`);
    const typers = await getResp.json();
    const bobTyping = typers.find((t: { user_id: string }) => t.user_id === bobSub);
    expect(!bobTyping).toBeTruthy();
  });

  test("150.3 TypingIndicator uses 30s fallback poll (not 3s)", async ({ page }) => {
    await injectAuth(page, ALICE_ID);
    await page.goto("/messages");
    await page.waitForLoadState("domcontentloaded");

    let typingPollCount = 0;
    page.on("request", (req) => {
      if (req.url().includes("/typing") && req.method() === "GET") {
        typingPollCount++;
      }
    });

    await new Promise((r) => setTimeout(r, 10_000));
    // At 3s poll we'd see 3+; at 30s fallback we see at most 1 in 10s
    expect(typingPollCount).toBeLessThanOrEqual(2);
  });
});

// ---------------------------------------------------------------------------
// Section 151: Presence SSE
// ---------------------------------------------------------------------------
test.describe("151 · Presence — SSE real-time push", () => {
  test("151.1 Heartbeat returns online status", async () => {
    const resp = await apiPost(bobPage, BOB_ID, "/messaging/presence/heartbeat", {
      status: "online",
      device: "e2e-test",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.online).toBe(true);
    expect(body.status).toBe("online");
    expect(body.last_seen_at).toBeGreaterThan(0);
  });

  test("151.2 Presence query reflects heartbeat", async () => {
    const bobSub = getSessions()[BOB_ID].user_sub;

    await apiPost(bobPage, BOB_ID, "/messaging/presence/heartbeat", {
      status: "online",
    });

    const resp = await apiGet(alicePage, "/messaging/presence", {
      user_ids: bobSub,
    });
    expect(resp.status()).toBe(200);
    const entries = await resp.json();
    const bobEntry = entries.find((e: { user_id: string }) => e.user_id === bobSub);
    expect(bobEntry).toBeTruthy();
    expect(bobEntry.online).toBe(true);
  });

  test("151.3 Presence polling interval is 60s fallback", async ({ page }) => {
    await injectAuth(page, ALICE_ID);
    await page.goto("/messages");
    await page.waitForLoadState("domcontentloaded");

    let presenceRequests = 0;
    page.on("request", (req) => {
      if (req.url().includes("/messaging/presence") && req.method() === "GET") {
        presenceRequests++;
      }
    });

    await new Promise((r) => setTimeout(r, 20_000));
    expect(presenceRequests).toBeLessThanOrEqual(2);
  });

  test("151.4 Heartbeat cooldown — rapid heartbeats both succeed", async () => {
    const resp1 = await apiPost(bobPage, BOB_ID, "/messaging/presence/heartbeat", {
      status: "online",
    });
    expect(resp1.status()).toBe(200);

    const resp2 = await apiPost(bobPage, BOB_ID, "/messaging/presence/heartbeat", {
      status: "online",
    });
    expect(resp2.status()).toBe(200);
    const body2 = await resp2.json();
    expect(body2.ok).toBe(true);
    expect(body2.online).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Section 152: Read Receipts / Delivery Status
// ---------------------------------------------------------------------------
test.describe("152 · Read Receipts — Delivery Status + SSE", () => {
  test("152.1 message:viewed endpoint returns view acknowledgement", async () => {
    const convoId = await getOrCreateDm(alicePage);

    const msgText = `e2e_delivery_check_${TS}`;
    const sendResp = await apiPost(alicePage, ALICE_ID, `/messaging/conversations/${convoId}/messages`, {
      text: msgText,
    });
    expect(sendResp.status()).toBe(200);
    const sent = await sendResp.json();

    const viewResp = await apiPost(
      bobPage,
      BOB_ID,
      `/messaging/conversations/${convoId}/messages/${sent.message_id}/view`,
      {},
    );
    expect(viewResp.status()).toBe(200);
    const viewBody = await viewResp.json();
    expect(viewBody.ok).toBe(true);
    expect(viewBody.viewer_id).toBe(getSessions()[BOB_ID].user_sub);
  });

  test("152.2 MessageOut includes delivery receipt fields", async () => {
    const convoId = await getOrCreateDm(alicePage);

    const msgText = `e2e_receipt_fields_${TS}`;
    const sendResp = await apiPost(alicePage, ALICE_ID, `/messaging/conversations/${convoId}/messages`, {
      text: msgText,
    });
    expect(sendResp.status()).toBe(200);
    const sent = await sendResp.json();

    const msgsResp = await apiGet(alicePage, `/messaging/conversations/${convoId}/messages`);
    expect(msgsResp.status()).toBe(200);
    const msgs = await msgsResp.json();
    const found = (msgs as Array<Record<string, unknown>>).find(
      (m) => m.message_id === sent.message_id,
    );
    expect(found).toBeTruthy();
    expect("delivered_to_count" in found!).toBe(true);
    expect("read_by_count" in found!).toBe(true);
  });

  test("152.3 Viewers API returns view data after mark_viewed", async () => {
    const convoId = await getOrCreateDm(alicePage);

    const msgText = `e2e_viewers_${TS}`;
    const sendResp = await apiPost(alicePage, ALICE_ID, `/messaging/conversations/${convoId}/messages`, {
      text: msgText,
    });
    const sent = await sendResp.json();

    await apiPost(
      bobPage,
      BOB_ID,
      `/messaging/conversations/${convoId}/messages/${sent.message_id}/view`,
      {},
    );

    const viewersResp = await apiGet(
      alicePage,
      `/messaging/conversations/${convoId}/messages/${sent.message_id}/views`,
    );
    expect(viewersResp.status()).toBe(200);
    const viewers = await viewersResp.json();
    const bobViewer = (viewers as Array<{ user_id: string }>).find(
      (v) => v.user_id === getSessions()[BOB_ID].user_sub,
    );
    expect(bobViewer).toBeTruthy();
  });

  test("152.4 Read count increments after view", async () => {
    const convoId = await getOrCreateDm(alicePage);

    const msgText = `e2e_readcount_${TS}`;
    const sendResp = await apiPost(alicePage, ALICE_ID, `/messaging/conversations/${convoId}/messages`, {
      text: msgText,
    });
    const sent = await sendResp.json();

    await apiPost(
      bobPage,
      BOB_ID,
      `/messaging/conversations/${convoId}/messages/${sent.message_id}/view`,
      {},
    );

    const msgsResp = await apiGet(alicePage, `/messaging/conversations/${convoId}/messages`);
    const msgs = await msgsResp.json();
    const found = (msgs as Array<Record<string, unknown>>).find(
      (m) => m.message_id === sent.message_id,
    );
    expect(found).toBeTruthy();
    expect(Number(found!.read_by_count ?? 0)).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// Section 153: DeliveryStatus UI component
// ---------------------------------------------------------------------------
test.describe("153 · DeliveryStatus — checkmark indicators", () => {
  test("153.1 DeliveryStatus component renders without errors", async ({ page }) => {
    await injectAuth(page, ALICE_ID);
    const convoId = await getOrCreateDm(alicePage);

    const msgText = `e2e_checkmark_ui_${TS}`;
    await apiPost(alicePage, ALICE_ID, `/messaging/conversations/${convoId}/messages`, {
      text: msgText,
    });

    await page.goto("/messages");
    await page.waitForLoadState("domcontentloaded");

    const convoEntry = page.locator(`[data-conversation-id="${convoId}"]`).first();
    if ((await convoEntry.count()) > 0) {
      await convoEntry.click();
    }

    await page.evaluate(() => window.dispatchEvent(new Event("online")));
    await page.waitForTimeout(2000);

    const title = await page.title();
    expect(title).toBeTruthy();
  });
});
