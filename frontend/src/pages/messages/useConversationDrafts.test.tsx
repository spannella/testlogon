import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import { ApiError } from "@/api/client";

import { useConversationDrafts, __private__ } from "./useConversationDrafts";

const messagingMock = vi.hoisted(() => ({
  listConversationDrafts: vi.fn(),
  createConversationDraft: vi.fn(),
  getConversationDraft: vi.fn(),
  updateConversationDraft: vi.fn(),
  deleteConversationDraft: vi.fn(),
}));

const featureFlagMock = vi.hoisted(() => ({
  isMessagingDraftsEnabled: vi.fn(() => true),
}));

vi.mock("@/api/endpoints/messaging", () => messagingMock);
vi.mock("@/lib/featureFlags", () => featureFlagMock);

describe("useConversationDrafts", () => {
  beforeEach(() => {
    window.localStorage.clear();
    vi.useRealTimers();
    messagingMock.listConversationDrafts.mockReset();
    messagingMock.createConversationDraft.mockReset();
    messagingMock.getConversationDraft.mockReset();
    messagingMock.updateConversationDraft.mockReset();
    messagingMock.deleteConversationDraft.mockReset();
    featureFlagMock.isMessagingDraftsEnabled.mockReset();

    messagingMock.listConversationDrafts.mockResolvedValue({ items: [], next_cursor: undefined });
    messagingMock.createConversationDraft.mockResolvedValue({
      draft_id: "srv-1",
      conversation_id: "c-1",
      owner_user_id: "u-1",
      text: "server",
      version: 1,
      created_at: 1_700_000_000,
      updated_at: 1_700_000_000,
    });
    messagingMock.getConversationDraft.mockResolvedValue({
      draft_id: "srv-load",
      conversation_id: "c-1",
      owner_user_id: "u-1",
      text: "loaded",
      version: 1,
      created_at: 1_700_000_000,
      updated_at: 1_700_000_000,
    });
    messagingMock.updateConversationDraft.mockResolvedValue({});
    messagingMock.deleteConversationDraft.mockResolvedValue(undefined);
    featureFlagMock.isMessagingDraftsEnabled.mockReturnValue(true);
  });

  it("normalizes malformed values safely", () => {
    const normalized = __private__.normalizeDrafts([
      { id: "d1", text: "ok", saved_at: 2 },
      { id: "bad", text: 42, saved_at: 3 },
      null,
      { id: "d0", text: "old", saved_at: 1 },
    ]);
    expect(normalized.map((d) => d.id)).toEqual(["d1", "d0"]);
  });

  it("reconciles local and server drafts with last-write-wins", () => {
    const merged = __private__.mergeDrafts(
      [{ id: "same", text: "old", saved_at: 1000 }],
      [{ id: "same", text: "new", saved_at: 2000 }],
      20,
    );
    expect(merged).toEqual([{ id: "same", text: "new", saved_at: 2000 }]);
  });

  it("classifies network TypeError as network sync issue", () => {
    expect(__private__.classifySyncIssue(new TypeError("Failed to fetch"))).toBe("network");
  });

  it("falls back to local drafts when list API fails", async () => {
    window.localStorage.setItem(
      "messaging:drafts:c-2",
      JSON.stringify([{ id: "local-1", text: "offline", saved_at: 10 }]),
    );
    messagingMock.listConversationDrafts.mockRejectedValueOnce(new Error("offline"));

    const { result } = renderHook(() => useConversationDrafts("c-2"));

    await waitFor(() => {
      expect(result.current.drafts.map((d) => d.text)).toEqual(["offline"]);
    });
  });

  it("retries refresh when browser comes back online", async () => {
    window.localStorage.setItem(
      "messaging:drafts:c-online",
      JSON.stringify([{ id: "local-1", text: "offline copy", saved_at: 10 }]),
    );
    messagingMock.listConversationDrafts
      .mockRejectedValueOnce(new Error("offline"))
      .mockResolvedValueOnce({
        items: [{
          draft_id: "srv-online-1",
          conversation_id: "c-online",
          owner_user_id: "u-1",
          text: "synced after reconnect",
          version: 1,
          created_at: 1_700_000_000,
          updated_at: 1_700_000_001,
        }],
        next_cursor: undefined,
      });

    const { result } = renderHook(() => useConversationDrafts("c-online"));
    await waitFor(() => {
      expect(result.current.drafts[0]?.text).toBe("offline copy");
    });

    window.dispatchEvent(new Event("online"));
    await waitFor(() => {
      expect(result.current.drafts[0]?.text).toBe("synced after reconnect");
    });
    expect(messagingMock.listConversationDrafts).toHaveBeenCalledTimes(2);
  });

  it("flags re-auth requirement when refresh fails with auth error", async () => {
    messagingMock.listConversationDrafts.mockRejectedValueOnce(
      new ApiError(401, "Authentication required"),
    );
    const { result } = renderHook(() => useConversationDrafts("c-auth"));

    await waitFor(() => {
      expect(result.current.syncIssue).toBe("auth");
    });
    expect(result.current.requiresReauth).toBe(true);
  });

  it("syncs local cache to server response on refresh", async () => {
    window.localStorage.setItem(
      "messaging:drafts:c-3",
      JSON.stringify([{ id: "srv-1", text: "stale", saved_at: 1000 }]),
    );
    messagingMock.listConversationDrafts.mockResolvedValueOnce({
      items: [{
        draft_id: "srv-1",
        conversation_id: "c-3",
        owner_user_id: "u-1",
        text: "fresh",
        version: 2,
        created_at: 1_700_000_000,
        updated_at: 1_700_000_010,
      }],
      next_cursor: undefined,
    });

    const { result } = renderHook(() => useConversationDrafts("c-3"));

    await waitFor(() => {
      expect(result.current.drafts[0]?.text).toBe("fresh");
    });

    const stored = JSON.parse(window.localStorage.getItem("messaging:drafts:c-3") ?? "[]");
    expect(stored[0].text).toBe("fresh");
  });

  it("saves optimistic local draft and reconciles to server create", async () => {
    messagingMock.createConversationDraft.mockResolvedValueOnce({
      draft_id: "srv-created",
      conversation_id: "c-4",
      owner_user_id: "u-1",
      text: "hello",
      version: 1,
      created_at: 1_700_000_000,
      updated_at: 1_700_000_001,
    });

    const { result } = renderHook(() => useConversationDrafts("c-4"));

    act(() => {
      expect(result.current.saveDraft("hello")).toBe(true);
    });

    await waitFor(() => {
      expect(result.current.drafts[0]?.id).toBe("srv-created");
    });
  });

  it("keeps local optimistic draft when create API fails", async () => {
    messagingMock.createConversationDraft.mockRejectedValueOnce(new Error("down"));

    const { result } = renderHook(() => useConversationDrafts("c-5"));
    act(() => {
      result.current.saveDraft("keep-local");
    });

    await waitFor(() => {
      expect(result.current.drafts[0]?.id.startsWith("local-")).toBe(true);
      expect(result.current.drafts[0]?.text).toBe("keep-local");
    });
  });

  it("deletes locally and calls server delete for persisted drafts", async () => {
    const { result } = renderHook(() => useConversationDrafts("c-6"));

    act(() => {
      result.current.saveDraft("remote");
    });

    await waitFor(() => {
      expect(result.current.drafts[0]?.id).toBe("srv-1");
    });

    act(() => {
      result.current.deleteDraft("srv-1");
    });

    expect(messagingMock.deleteConversationDraft).toHaveBeenCalledWith("c-6", "srv-1");
    expect(result.current.drafts).toHaveLength(0);
  });

  it("isolates drafts across conversation changes (no leakage)", async () => {
    messagingMock.createConversationDraft.mockImplementation(async (conversationId: string, body: { text: string }) => ({
      draft_id: `srv-${conversationId}`,
      conversation_id: conversationId,
      owner_user_id: "u-1",
      text: body.text,
      version: 1,
      created_at: 1_700_000_000,
      updated_at: 1_700_000_001,
    }));

    const { result, rerender } = renderHook(
      ({ conversationId }) => useConversationDrafts(conversationId),
      { initialProps: { conversationId: "scope-a" } },
    );

    act(() => {
      result.current.saveDraft("draft-a");
    });
    await waitFor(() => {
      expect(result.current.drafts[0]?.text).toBe("draft-a");
    });

    rerender({ conversationId: "scope-b" });
    await waitFor(() => {
      expect(result.current.drafts).toEqual([]);
    });

    act(() => {
      result.current.saveDraft("draft-b");
    });
    await waitFor(() => {
      expect(result.current.drafts[0]?.text).toBe("draft-b");
    });

    rerender({ conversationId: "scope-a" });
    await waitFor(() => {
      expect(result.current.drafts[0]?.text).toBe("draft-a");
    });
  });

  it("requires a non-empty conversation id", () => {
    expect(() => renderHook(() => useConversationDrafts("  "))).toThrow(
      "useConversationDrafts requires a non-empty conversationId",
    );
  });

  it("no-ops when messaging drafts feature is disabled", async () => {
    featureFlagMock.isMessagingDraftsEnabled.mockReturnValue(false);
    const { result } = renderHook(() => useConversationDrafts("c-disabled"));
    await waitFor(() => {
      expect(result.current.drafts).toEqual([]);
    });
    expect(result.current.saveDraft("hello")).toBe(false);
    await expect(result.current.loadDraft("d1")).resolves.toBeNull();
    result.current.deleteDraft("d1");
    expect(messagingMock.listConversationDrafts).not.toHaveBeenCalled();
  });

  it("returns remote text when loadDraft falls back to server", async () => {
    messagingMock.getConversationDraft.mockResolvedValueOnce({
      draft_id: "srv-load-2",
      conversation_id: "c-load",
      owner_user_id: "u-1",
      text: "server-loaded",
      version: 1,
      created_at: 1_700_000_000,
      updated_at: 1_700_000_000,
    });

    const { result } = renderHook(() => useConversationDrafts("c-load"));
    const loaded = await result.current.loadDraft("srv-load-2");

    expect(loaded).toBe("server-loaded");
    await waitFor(() => {
      expect(result.current.drafts.some((d) => d.id === "srv-load-2")).toBe(true);
    });
  });

  it("syncs drafts from same conversation when localStorage changes in another tab", async () => {
    const { result } = renderHook(() => useConversationDrafts("c-cross-tab"));
    await waitFor(() => {
      expect(result.current.drafts).toEqual([]);
    });

    const nextValue = JSON.stringify([
      { id: "remote-tab-1", text: "from another tab", saved_at: 1234 },
    ]);
    window.dispatchEvent(new StorageEvent("storage", {
      key: "messaging:drafts:c-cross-tab",
      newValue: nextValue,
      storageArea: window.localStorage,
    }));

    await waitFor(() => {
      expect(result.current.drafts).toEqual([
        { id: "remote-tab-1", text: "from another tab", saved_at: 1234 },
      ]);
    });
  });

  it("ignores storage events for other conversations", async () => {
    const { result } = renderHook(() => useConversationDrafts("c-local-only"));
    act(() => {
      result.current.saveDraft("mine");
    });
    await waitFor(() => {
      expect(result.current.drafts.length).toBeGreaterThan(0);
    });

    window.dispatchEvent(new StorageEvent("storage", {
      key: "messaging:drafts:other-conversation",
      newValue: JSON.stringify([{ id: "x", text: "other", saved_at: 1 }]),
      storageArea: window.localStorage,
    }));

    await waitFor(() => {
      expect(result.current.drafts[0]?.text).toBe("server");
    });
  });
});
