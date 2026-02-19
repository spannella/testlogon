import { render, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, expect, it, vi } from "vitest";
import { ConversationView } from "./ConversationView";

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (state: { userId: string }) => unknown) => selector({ userId: "u1" }),
}));

vi.mock("@/api/endpoints/messaging", () => ({
  getMessages: vi.fn(async () => ({ messages: [], next_cursor: null })),
  sendTextMessage: vi.fn(async () => ({})),
  sendImageMessage: vi.fn(async () => ({})),
  markRead: vi.fn(async () => ({ ok: true })),
}));

vi.mock("./MessageBubble", () => ({ MessageBubble: () => null }));
vi.mock("./ComposeBar", () => ({ ComposeBar: () => null }));
vi.mock("./TypingIndicator", () => ({ TypingIndicator: () => null, useTypingSignal: () => () => {} }));
vi.mock("./PresenceDot", () => ({ PresenceDot: () => null }));
vi.mock("./ParticipantsPanel", () => ({ ParticipantsPanel: () => null }));

describe("ConversationView reconnect reconciliation", () => {
  it("invalidates message/conversation queries on online and visibility reconnect paths", async () => {
    const client = new QueryClient();
    const invalidateSpy = vi.spyOn(client, "invalidateQueries");

    const conversation = {
      conversation_id: "c1",
      type: "dm",
      participants: [{ user_id: "u1" }, { user_id: "u2", display_name: "U2" }],
      unread_count: 0,
    } as any;

    render(
      <QueryClientProvider client={client}>
        <ConversationView conversation={conversation} />
      </QueryClientProvider>,
    );

    window.dispatchEvent(new Event("online"));

    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => "visible",
    });
    document.dispatchEvent(new Event("visibilitychange"));

    await waitFor(() => {
      expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ["messages", "c1"] });
      expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ["conversations"] });
    });
  });
});
