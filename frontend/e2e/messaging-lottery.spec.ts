import { test, expect, type APIRequestContext, type TestInfo } from "@playwright/test";

const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const CHARLIE_ID = "e2e_charlie@test.local";

async function apiPostBearer(req: APIRequestContext, path: string, body: object, userId: string) {
  return req.post(`${API}${path}`, {
    data: body,
    headers: { Authorization: `Bearer ${userId}` },
  });
}

async function apiGetBearer(req: APIRequestContext, path: string, userId: string) {
  return req.get(`${API}${path}`, {
    headers: { Authorization: `Bearer ${userId}` },
  });
}

async function attachJson(testInfo: TestInfo, name: string, data: unknown) {
  await testInfo.attach(name, {
    body: JSON.stringify(data, null, 2),
    contentType: "application/json",
  });
}

async function ensureLotteryEnabled(req: APIRequestContext) {
  const cfgRes = await apiGetBearer(req, "/messaging/config", ALICE_ID);
  expect(cfgRes.ok()).toBeTruthy();
  const cfg = await cfgRes.json();
  expect(cfg?.messaging_dm_lottery_enabled).toBe(true);
}

async function createDmConversation(req: APIRequestContext, senderId: string, recipientId: string) {
  const resp = await apiPostBearer(req, "/messaging/conversations", {
    type: "dm",
    participant_ids: [recipientId],
  }, senderId);
  expect(resp.ok()).toBeTruthy();
  return resp.json();
}

async function createLottery(req: APIRequestContext, senderId: string, conversationId: string) {
  const resp = await apiPostBearer(req, "/messaging/messages/lottery", {
    conversation_id: conversationId,
    lottery_config: {
      version: "v1",
      outcomes: [
        { outcome_id: "o1", display_label: "small", payload_type: "text", text_content: "Small reward", weight_bps: 1000 },
        { outcome_id: "o2", display_label: "medium", payload_type: "text", text_content: "Medium reward", weight_bps: 3000 },
        { outcome_id: "o3", display_label: "large", payload_type: "text", text_content: "Large reward", weight_bps: 6000 },
      ],
    },
  }, senderId);
  expect(resp.ok()).toBeTruthy();
  return resp.json();
}

test.describe("Messaging lottery DM end-to-end", () => {
  test("sender creates weighted outcomes and recipient unlocks once", async ({ request }, testInfo) => {
    await ensureLotteryEnabled(request);

    const dm = await createDmConversation(request, ALICE_ID, BOB_ID);
    const lottery = await createLottery(request, ALICE_ID, dm.conversation_id);
    const unlockRes = await apiPostBearer(request, `/messaging/messages/${lottery.message_id}/lottery/unlock`, {}, BOB_ID);

    expect(unlockRes.ok()).toBeTruthy();
    const unlock = await unlockRes.json();

    expect(unlock.lock_state).toBe("unlocked");
    expect(unlock.selected_outcome.outcome_id).toBeTruthy();
    expect(unlock.selected_outcome.payload_type).toBe("text");

    await attachJson(testInfo, "lottery-single-unlock", {
      conversation_id: dm.conversation_id,
      message_id: lottery.message_id,
      unlock,
    });
  });

  test("repeated unlock returns same selected outcome", async ({ request }, testInfo) => {
    await ensureLotteryEnabled(request);

    const dm = await createDmConversation(request, ALICE_ID, BOB_ID);
    const lottery = await createLottery(request, ALICE_ID, dm.conversation_id);

    const firstRes = await apiPostBearer(request, `/messaging/messages/${lottery.message_id}/lottery/unlock`, {}, BOB_ID);
    const secondRes = await apiPostBearer(request, `/messaging/messages/${lottery.message_id}/lottery/unlock`, {}, BOB_ID);

    expect(firstRes.ok()).toBeTruthy();
    expect(secondRes.ok()).toBeTruthy();

    const first = await firstRes.json();
    const second = await secondRes.json();

    expect(first.selected_outcome.outcome_id).toBe(second.selected_outcome.outcome_id);
    expect(first.selected_outcome.payload_type).toBe(second.selected_outcome.payload_type);

    await attachJson(testInfo, "lottery-repeated-unlock", {
      conversation_id: dm.conversation_id,
      message_id: lottery.message_id,
      first,
      second,
    });
  });

  test("second recipient in separate DM has independent unlock flow", async ({ request }, testInfo) => {
    await ensureLotteryEnabled(request);

    const dmBob = await createDmConversation(request, ALICE_ID, BOB_ID);
    const dmCharlie = await createDmConversation(request, ALICE_ID, CHARLIE_ID);

    const lotteryBob = await createLottery(request, ALICE_ID, dmBob.conversation_id);
    const lotteryCharlie = await createLottery(request, ALICE_ID, dmCharlie.conversation_id);

    const bobUnlockRes = await apiPostBearer(request, `/messaging/messages/${lotteryBob.message_id}/lottery/unlock`, {}, BOB_ID);
    const charlieUnlockRes = await apiPostBearer(request, `/messaging/messages/${lotteryCharlie.message_id}/lottery/unlock`, {}, CHARLIE_ID);

    expect(bobUnlockRes.ok()).toBeTruthy();
    expect(charlieUnlockRes.ok()).toBeTruthy();

    const bobUnlock = await bobUnlockRes.json();
    const charlieUnlock = await charlieUnlockRes.json();

    expect(lotteryBob.message_id).not.toBe(lotteryCharlie.message_id);
    expect(bobUnlock.lock_state).toBe("unlocked");
    expect(charlieUnlock.lock_state).toBe("unlocked");
    expect(bobUnlock.selected_outcome.outcome_id).toBeTruthy();
    expect(charlieUnlock.selected_outcome.outcome_id).toBeTruthy();

    await attachJson(testInfo, "lottery-independent-dms", {
      bob: {
        conversation_id: dmBob.conversation_id,
        message_id: lotteryBob.message_id,
        unlock: bobUnlock,
      },
      charlie: {
        conversation_id: dmCharlie.conversation_id,
        message_id: lotteryCharlie.message_id,
        unlock: charlieUnlock,
      },
    });
  });
});
