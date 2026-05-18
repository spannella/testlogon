import { beforeEach, describe, expect, it, vi } from "vitest";

import * as client from "@/api/client";
import {
  createConversationDraft,
  deleteConversationDraft,
  getConversationDraft,
  listConversationDrafts,
  updateConversationDraft,
} from "@/api/endpoints/messaging";

describe("messaging draft endpoints", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("maps list request query params and adapts numeric fields", async () => {
    const getSpy = vi.spyOn(client.api, "get").mockResolvedValue({
      items: [
        {
          draft_id: "d1",
          conversation_id: "c1",
          owner_user_id: "u1",
          text: "hello",
          version: "2",
          created_at: "100",
          updated_at: "200",
          client_updated_at: "150",
        },
      ],
      next_cursor: "n1",
    } as never);

    const out = await listConversationDrafts("c1", "abc", 50);

    expect(getSpy).toHaveBeenCalledWith("/messaging/conversations/c1/drafts", {
      limit: "50",
      cursor: "abc",
    });
    expect(out.items[0]).toEqual(
      expect.objectContaining({
        draft_id: "d1",
        version: 2,
        created_at: 100,
        updated_at: 200,
        client_updated_at: 150,
      }),
    );
  });

  it("uses idempotency header for create and adapts response", async () => {
    const apiSpy = vi.spyOn(client, "api").mockResolvedValue({
      draft: {
        draft_id: "d1",
        conversation_id: "c1",
        owner_user_id: "u1",
        text: "hello",
        version: "1",
        created_at: "111",
        updated_at: "112",
      },
    } as never);

    const out = await createConversationDraft("c1", { text: "hello" }, "idem-1");

    expect(apiSpy).toHaveBeenCalledWith("/messaging/conversations/c1/drafts", {
      method: "POST",
      body: JSON.stringify({ text: "hello" }),
      headers: { "Idempotency-Key": "idem-1" },
    });
    expect(out.version).toBe(1);
    expect(out.created_at).toBe(111);
  });

  it("maps get/update/delete paths", async () => {
    const getSpy = vi.spyOn(client.api, "get").mockResolvedValue({
      draft: {
        draft_id: "d1",
        conversation_id: "c1",
        owner_user_id: "u1",
        text: "hello",
        version: 1,
        created_at: 100,
        updated_at: 101,
      },
    } as never);
    const patchSpy = vi.spyOn(client.api, "patch").mockResolvedValue({
      draft: {
        draft_id: "d1",
        conversation_id: "c1",
        owner_user_id: "u1",
        text: "updated",
        version: 2,
        created_at: 100,
        updated_at: 120,
      },
    } as never);
    const delSpy = vi.spyOn(client.api, "del").mockResolvedValue(undefined as never);

    const got = await getConversationDraft("c1", "d1");
    expect(getSpy).toHaveBeenCalledWith("/messaging/conversations/c1/drafts/d1");
    expect(got.draft_id).toBe("d1");

    const updated = await updateConversationDraft("c1", "d1", { text: "updated" });
    expect(patchSpy).toHaveBeenCalledWith("/messaging/conversations/c1/drafts/d1", { text: "updated" });
    expect(updated.version).toBe(2);

    await deleteConversationDraft("c1", "d1");
    expect(delSpy).toHaveBeenCalledWith("/messaging/conversations/c1/drafts/d1");
  });
});
