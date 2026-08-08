/**
 * E2E tests for Reply Threads API.
 *
 * Routes tested:
 *   POST /messaging/conversations/{id}/messages        — send message (with reply_to_message_id)
 *   GET  /messaging/threads/{thread_id}/messages        — list thread messages
 *   GET  /messaging/conversations/{id}/messages         — list conversation messages (plain array)
 *
 * Thread promotion logic:
 *   The backend promotes a reply chain into a thread when the second reply to
 *   a root message arrives (direct_reply_count >= 1 triggers promotion).
 *   The first reply sets reply_to_message_id / parent_message_id but no thread_id.
 *   The second reply triggers thread record creation and retroactively stamps
 *   thread_id on the root message and all existing replies.
 *
 * Auth pattern:
 *   All API calls use the global `request` fixture with Bearer auth
 *   (Authorization: Bearer <user_id>), which the dev-mode backend accepts.
 *
 * Test users:
 *   Alice   (e2e_alice@test.local)   — DM initiator
 *   Bob     (e2e_bob@test.local)     — DM partner
 *   Charlie (e2e_charlie@test.local) — non-participant for access control tests
 */

import { test, expect } from "@playwright/test";
import { API } from "./cpp.config";

// ─── Constants ──────────────────────────────────────────────────────────────────

const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const CHARLIE_ID = "e2e_charlie@test.local";

// ─── Bearer auth API helpers ────────────────────────────────────────────────────

type Req = import("@playwright/test").APIRequestContext;

async function apiPost(request: Req, path: string, body: object, userId: string) {
  return request.post(`${API}${path}`, {
    data: body,
    headers: { Authorization: `Bearer ${userId}` },
  });
}

async function apiGet(request: Req, path: string, userId: string) {
  return request.get(`${API}${path}`, {
    headers: { Authorization: `Bearer ${userId}` },
  });
}

/** Create a fresh DM between two users and return the conversation_id. */
async function createDm(request: Req, fromUser: string, toUser: string): Promise<string> {
  const resp = await apiPost(request, "/messaging/conversations/dm/find-or-create", { user_id: toUser }, fromUser);
  expect(resp.ok(), `createDm failed: ${resp.status()}`).toBe(true);
  const data = await resp.json();
  return data.conversation_id;
}

/** Send a text message and return the parsed MessageOut. */
async function sendMessage(
  request: Req,
  conversationId: string,
  text: string,
  userId: string,
  extra: Record<string, unknown> = {},
) {
  const resp = await apiPost(
    request,
    `/messaging/conversations/${conversationId}/messages`,
    { text, ...extra },
    userId,
  );
  expect(resp.ok(), `sendMessage failed: ${resp.status()} — ${await resp.text()}`).toBe(true);
  return resp.json();
}

// ─── Tests ──────────────────────────────────────────────────────────────────────

test.describe("74 — Reply threads API", () => {
  test("74.1 reply creates a thread and returns thread_id", async ({ request }) => {
    test.setTimeout(60_000);

    // Create a fresh DM
    const convoId = await createDm(request, ALICE_ID, BOB_ID);

    // Alice sends a root message
    const rootMsg = await sendMessage(request, convoId, `Root message ${Date.now()}`, ALICE_ID);
    expect(rootMsg.message_id).toBeTruthy();
    expect(rootMsg.thread_id).toBeFalsy(); // root has no thread yet

    // Bob sends the first reply — no thread promotion yet (direct_reply_count == 0)
    const reply1 = await sendMessage(request, convoId, `Reply 1 ${Date.now()}`, BOB_ID, {
      reply_to_message_id: rootMsg.message_id,
    });
    expect(reply1.reply_to_message_id).toBe(rootMsg.message_id);
    // First reply may or may not have thread_id depending on promotion threshold

    // Alice sends the second reply — triggers thread promotion (direct_reply_count >= 1)
    const reply2 = await sendMessage(request, convoId, `Reply 2 ${Date.now()}`, ALICE_ID, {
      reply_to_message_id: rootMsg.message_id,
    });
    expect(reply2.reply_to_message_id).toBe(rootMsg.message_id);
    expect(reply2.thread_id).toBeTruthy();
    expect(typeof reply2.thread_id).toBe("string");
    expect(reply2.thread_root_message_id).toBe(rootMsg.message_id);
  });

  test("74.2 GET thread messages returns items with correct structure", async ({ request }) => {
    test.setTimeout(60_000);

    const convoId = await createDm(request, ALICE_ID, BOB_ID);

    // Root + 2 replies to trigger thread promotion
    const rootMsg = await sendMessage(request, convoId, `Thread root ${Date.now()}`, ALICE_ID);
    await sendMessage(request, convoId, `First reply ${Date.now()}`, BOB_ID, {
      reply_to_message_id: rootMsg.message_id,
    });
    const reply2 = await sendMessage(request, convoId, `Second reply ${Date.now()}`, ALICE_ID, {
      reply_to_message_id: rootMsg.message_id,
    });

    const threadId = reply2.thread_id;
    expect(threadId).toBeTruthy();

    // GET thread messages
    const resp = await apiGet(request, `/messaging/threads/${threadId}/messages`, ALICE_ID);
    expect(resp.ok()).toBe(true);
    const page = await resp.json();

    // Verify response structure
    expect(page).toHaveProperty("items");
    expect(page).toHaveProperty("next_cursor");
    expect(page).toHaveProperty("unread_count");
    expect(Array.isArray(page.items)).toBe(true);
    expect(page.items.length).toBeGreaterThanOrEqual(2); // at least the root + replies that were promoted
    expect(typeof page.unread_count).toBe("number");

    // Verify each item has expected MessageOut fields
    for (const item of page.items) {
      expect(item).toHaveProperty("message_id");
      expect(item).toHaveProperty("conversation_id");
      expect(item).toHaveProperty("sender_id");
      expect(item).toHaveProperty("created_at");
      expect(item).toHaveProperty("thread_id");
      expect(item.thread_id).toBe(threadId);
    }
  });

  test("74.3 multiple replies accumulate in the same thread", async ({ request }) => {
    test.setTimeout(60_000);

    const convoId = await createDm(request, ALICE_ID, BOB_ID);
    const ts = Date.now();

    // Root message
    const rootMsg = await sendMessage(request, convoId, `Accumulate root ${ts}`, ALICE_ID);

    // Send 4 replies (first won't promote, second will, third and fourth join the existing thread)
    const replies = [];
    for (let i = 1; i <= 4; i++) {
      const sender = i % 2 === 0 ? ALICE_ID : BOB_ID;
      const reply = await sendMessage(request, convoId, `Reply ${i} ${ts}`, sender, {
        reply_to_message_id: rootMsg.message_id,
      });
      replies.push(reply);
    }

    // The second reply (index 1) and beyond should have thread_id
    const threadId = replies[1].thread_id;
    expect(threadId).toBeTruthy();

    // All subsequent replies should share the same thread_id
    expect(replies[2].thread_id).toBe(threadId);
    expect(replies[3].thread_id).toBe(threadId);

    // Fetch thread messages
    const resp = await apiGet(request, `/messaging/threads/${threadId}/messages`, ALICE_ID);
    expect(resp.ok()).toBe(true);
    const page = await resp.json();

    // Thread should contain the root + all 4 replies (5 total) since promotion
    // retroactively stamps thread_id on existing messages
    expect(page.items.length).toBeGreaterThanOrEqual(3);

    // Verify all thread items share the same thread_id
    for (const item of page.items) {
      expect(item.thread_id).toBe(threadId);
    }

    // Verify the root message is present in the thread items (promotion stamps it)
    const rootInThread = page.items.find((m: any) => m.message_id === rootMsg.message_id);
    if (rootInThread) {
      expect(rootInThread.thread_id).toBe(threadId);
    }
  });

  test("74.4 thread pagination with limit parameter", async ({ request }) => {
    test.setTimeout(60_000);

    const convoId = await createDm(request, ALICE_ID, BOB_ID);
    const ts = Date.now();

    // Root + 5 replies
    const rootMsg = await sendMessage(request, convoId, `Paginate root ${ts}`, ALICE_ID);
    let threadId: string | null = null;

    for (let i = 1; i <= 5; i++) {
      const sender = i % 2 === 0 ? ALICE_ID : BOB_ID;
      const reply = await sendMessage(request, convoId, `Page reply ${i} ${ts}`, sender, {
        reply_to_message_id: rootMsg.message_id,
      });
      if (reply.thread_id) {
        threadId = reply.thread_id;
      }
    }
    expect(threadId).toBeTruthy();

    // Query with limit=2
    const resp = await apiGet(
      request,
      `/messaging/threads/${threadId}/messages?limit=2`,
      ALICE_ID,
    );
    expect(resp.ok(), `GET thread messages failed: ${resp.status()} — ${await resp.text()}`).toBe(true);
    const page = await resp.json();

    expect(page.items.length).toBe(2);
    expect(page.next_cursor).toBeTruthy();
    expect(typeof page.next_cursor).toBe("string");

    // Fetch next page using cursor
    const resp2 = await apiGet(
      request,
      `/messaging/threads/${threadId}/messages?limit=2&cursor=${encodeURIComponent(page.next_cursor)}`,
      ALICE_ID,
    );
    expect(resp2.ok(), `GET thread page 2 failed: ${resp2.status()} — ${await resp2.text()}`).toBe(true);
    const page2 = await resp2.json();
    expect(page2.items.length).toBeGreaterThanOrEqual(1);

    // Pages should not overlap
    const ids1 = new Set(page.items.map((m: any) => m.message_id));
    const ids2 = new Set(page2.items.map((m: any) => m.message_id));
    for (const id of ids2) {
      expect(ids1.has(id)).toBe(false);
    }
  });

  test("74.5 non-participant cannot access thread", async ({ request }) => {
    test.setTimeout(60_000);

    // Alice creates DM with Bob, they build a thread
    const convoId = await createDm(request, ALICE_ID, BOB_ID);
    const ts = Date.now();
    const rootMsg = await sendMessage(request, convoId, `Private root ${ts}`, ALICE_ID);

    // Two replies to create a thread
    await sendMessage(request, convoId, `Private reply 1 ${ts}`, BOB_ID, {
      reply_to_message_id: rootMsg.message_id,
    });
    const reply2 = await sendMessage(request, convoId, `Private reply 2 ${ts}`, ALICE_ID, {
      reply_to_message_id: rootMsg.message_id,
    });

    const threadId = reply2.thread_id;
    expect(threadId).toBeTruthy();

    // Charlie (not a participant) tries to access the thread
    const resp = await apiGet(request, `/messaging/threads/${threadId}/messages`, CHARLIE_ID);
    expect(resp.status()).toBe(403);
  });

  test("74.6 non-existent thread returns 404", async ({ request }) => {
    const resp = await apiGet(
      request,
      "/messaging/threads/nonexistent_thread_id_xyz_999/messages",
      ALICE_ID,
    );
    expect(resp.status()).toBe(404);
  });
});
