import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, expect, it, vi, beforeEach } from "vitest";
import type { Message } from "@/api/types";
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

vi.mock("./MessageBubble", () => ({
  MessageBubble: ({
    message,
    onViewThread,
    onReply,
  }: {
    message: Message;
    onViewThread?: (m: Message) => void;
    onReply?: (m: Message) => void;
  }) => (
    <div data-testid={`msg-${message.message_id}`}>
      <span>{message.has_thread ? `thread:${message.thread_reply_count ?? 0}` : "nothread"}</span>
      <button onClick={() => onViewThread?.(message)} aria-label={`view-thread-${message.message_id}`}>view</button>
      <button onClick={() => onReply?.(message)} aria-label={`reply-${message.message_id}`}>reply</button>
    </div>
  ),
}));

vi.mock("./ThreadPanel", () => ({
  ThreadPanel: ({
    open,
    anchorMessage,
  }: {
    open: boolean;
    anchorMessage: Message | null;
  }) => (
    open ? <div role="dialog" aria-label="Thread panel">anchor:{anchorMessage?.message_id}</div> : null
  ),
}));

vi.mock("./ComposeBar", () => ({ ComposeBar: () => null }));
vi.mock("./TypingIndicator", () => ({ TypingIndicator: () => null, useTypingSignal: () => () => {} }));
vi.mock("./PresenceDot", () => ({ PresenceDot: () => null }));
vi.mock("./ParticipantsPanel", () => ({ ParticipantsPanel: () => null }));
vi.mock("./ConversationGallery", () => ({ ConversationGallery: () => null }));
vi.mock("./ScheduledMessages", () => ({ ScheduledMessages: () => null }));
vi.mock("./HiddenMessagesPanel", () => ({ HiddenMessagesPanel: () => null }));
vi.mock("./PinnedMessagesPanel", () => ({ PinnedMessagesPanel: () => null }));
vi.mock("./PinnedMessageBanner", () => ({ PinnedMessageBanner: () => null }));

function renderView() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const conversation = {
    conversation_id: "c1",
    type: "dm",
    participants: [{ user_id: "u1" }, { user_id: "u2" }],
    unread_count: 0,
  } as any;
  return render(
    <QueryClientProvider client={client}>
      <ConversationView conversation={conversation} />
    </QueryClientProvider>,
  );
}

describe("ConversationView thread E2E scenarios", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("navigates timeline -> thread panel from thread entry point", async () => {
    getMessages.mockResolvedValue({
      messages: [
        {
          message_id: "m_root",
          conversation_id: "c1",
          sender_id: "u2",
          kind: "text",
          text: "root",
          created_at: 100,
          has_thread: true,
          thread_reply_count: 2,
          thread_id: "thr_1",
          thread_root_message_id: "m_root",
        },
      ],
      next_cursor: undefined,
    });
    renderView();

    await userEvent.click(await screen.findByRole("button", { name: "view-thread-m_root" }));
    expect(await screen.findByRole("dialog", { name: "Thread panel" })).toHaveTextContent("anchor:m_root");
  });

  it("routes reply-to-reply workflow into thread context", async () => {
    getMessages.mockResolvedValue({
      messages: [
        {
          message_id: "m_reply",
          conversation_id: "c1",
          sender_id: "u2",
          kind: "text",
          text: "reply",
          created_at: 100,
          parent_message_id: "m_root",
          thread_id: "thr_1",
          thread_root_message_id: "m_root",
          has_thread: true,
          thread_reply_count: 2,
        },
      ],
      next_cursor: undefined,
    });
    renderView();

    await userEvent.click(await screen.findByRole("button", { name: "reply-m_reply" }));
    expect(await screen.findByRole("dialog", { name: "Thread panel" })).toHaveTextContent("anchor:m_reply");
  });

  it("keeps timeline thread metadata consistent after reconnect refresh", async () => {
    getMessages
      .mockResolvedValueOnce({
        messages: [
          {
            message_id: "m_root",
            conversation_id: "c1",
            sender_id: "u2",
            kind: "text",
            text: "root",
            created_at: 100,
            has_thread: false,
          },
        ],
        next_cursor: undefined,
      })
      .mockResolvedValueOnce({
        messages: [
          {
            message_id: "m_root",
            conversation_id: "c1",
            sender_id: "u2",
            kind: "text",
            text: "root",
            created_at: 100,
            has_thread: true,
            thread_reply_count: 2,
            thread_id: "thr_1",
            thread_root_message_id: "m_root",
          },
        ],
        next_cursor: undefined,
      });

    renderView();
    expect(await screen.findByTestId("msg-m_root")).toHaveTextContent("nothread");

    window.dispatchEvent(new Event("online"));

    await waitFor(() => {
      expect(screen.getByTestId("msg-m_root")).toHaveTextContent("thread:2");
    });
  });
});
