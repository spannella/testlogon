import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { ConversationView } from "./ConversationView";

const getMessages = vi.fn();

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (state: { userId: string }) => unknown) => selector({ userId: "u1" }),
}));

vi.mock("@/api/endpoints/messaging", () => ({
  getMessages: (...args: unknown[]) => getMessages(...args),
  sendTextMessage: vi.fn(async () => ({})),
  sendImageMessage: vi.fn(async () => ({})),
  sendGalleryMessage: vi.fn(async () => ({})),
  sendFileShareMessage: vi.fn(async () => ({})),
  sendCalendarShareMessage: vi.fn(async () => ({})),
  sendCalendarEventMessage: vi.fn(async () => ({})),
  sendMeetingPollMessage: vi.fn(async () => ({})),
  markRead: vi.fn(async () => ({ ok: true })),
  claimHelpdeskConversation: vi.fn(async () => ({ ok: true })),
}));

vi.mock("./MessageBubble", () => ({ MessageBubble: () => <div data-testid="message-bubble" /> }));
vi.mock("./ComposeBar", () => ({ ComposeBar: () => null }));
vi.mock("./TypingIndicator", () => ({ TypingIndicator: () => null, useTypingSignal: () => () => {} }));
vi.mock("./PresenceDot", () => ({ PresenceDot: () => null }));
vi.mock("./ParticipantsPanel", () => ({ ParticipantsPanel: () => null }));
vi.mock("./ConversationGallery", () => ({ ConversationGallery: () => null }));
vi.mock("./ScheduledMessages", () => ({ ScheduledMessages: () => null }));

vi.mock("./HiddenMessagesPanel", () => ({
  HiddenMessagesPanel: ({ open, onJumpToMessage }: { open: boolean; onJumpToMessage: (id: string) => void }) =>
    open ? (
      <div role="dialog" aria-label="Hidden messages panel">
        <button onClick={() => onJumpToMessage("m1")}>Jump hidden</button>
      </div>
    ) : null,
}));

vi.mock("./PinnedMessagesPanel", () => ({
  PinnedMessagesPanel: ({ open, onJumpToMessage }: { open: boolean; onJumpToMessage: (id: string) => void }) =>
    open ? (
      <div role="dialog" aria-label="Pinned messages panel">
        <button onClick={() => onJumpToMessage("m1")}>Jump pinned</button>
      </div>
    ) : null,
}));

const scrollIntoViewMock = vi.fn();
if (!Element.prototype.scrollIntoView) {
  Object.defineProperty(Element.prototype, "scrollIntoView", {
    value: scrollIntoViewMock,
  });
} else {
  Element.prototype.scrollIntoView = scrollIntoViewMock;
}

function renderView() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const conversation = {
    conversation_id: "c1",
    type: "dm",
    participants: [{ user_id: "u1" }, { user_id: "u2", display_name: "U2" }],
    unread_count: 0,
    latest_pinned_message_id: "m1",
    latest_pinned_at: 1700000000,
  } as any;

  return render(
    <QueryClientProvider client={client}>
      <ConversationView conversation={conversation} />
    </QueryClientProvider>,
  );
}

describe("ConversationView message controls UX", () => {
  beforeEach(() => {
    scrollIntoViewMock.mockClear();
    getMessages.mockReset();
    getMessages.mockResolvedValue({
      messages: [
        {
          message_id: "m1",
          conversation_id: "c1",
          sender_id: "u2",
          kind: "text",
          text: "Pinned content",
          created_at: 10,
        },
      ],
      next_cursor: undefined,
    });
  });

  it("opens hidden panel from menu and jump highlights target message", async () => {
    renderView();

    await userEvent.click(screen.getByRole("button", { name: "Conversation menu" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: /Hidden messages/i }));

    expect(await screen.findByRole("dialog", { name: "Hidden messages panel" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Jump hidden" }));

    await waitFor(() => {
      expect(scrollIntoViewMock).toHaveBeenCalled();
    });
  });

  it("supports pin banner + pins panel interactions", async () => {
    renderView();

    expect(await screen.findByRole("button", { name: "View all pins" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "View all pins" }));

    expect(await screen.findByRole("dialog", { name: "Pinned messages panel" })).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Jump pinned" }));
    await waitFor(() => {
      expect(scrollIntoViewMock).toHaveBeenCalled();
    });

    await userEvent.click(screen.getByRole("button", { name: "Dismiss pinned banner" }));
    await waitFor(() => {
      expect(screen.queryByRole("button", { name: "View all pins" })).not.toBeInTheDocument();
    });
  });
});
