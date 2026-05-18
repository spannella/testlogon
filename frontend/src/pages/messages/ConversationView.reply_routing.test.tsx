import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, expect, it, vi, beforeEach } from "vitest";
import type { Message } from "@/api/types";
import { ConversationView } from "./ConversationView";

const getMessages = vi.fn();
const sendTextMessage = vi.fn();

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (state: { userId: string }) => unknown) => selector({ userId: "u1" }),
}));

vi.mock("@/api/endpoints/messaging", () => ({
  getMessages: (...args: unknown[]) => getMessages(...args),
  sendTextMessage: (...args: unknown[]) => sendTextMessage(...args),
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
  MessageBubble: ({ message, onReply }: { message: Message; onReply?: (m: Message) => void }) => (
    <button onClick={() => onReply?.(message)}>Reply {message.message_id}</button>
  ),
}));
vi.mock("./ComposeBar", () => ({
  ComposeBar: ({ onSendText, replyingTo }: { onSendText: (p: { text: string }) => void; replyingTo?: Message | null }) => (
    <div>
      <div data-testid="replying-to">{replyingTo?.message_id ?? "none"}</div>
      <button onClick={() => onSendText({ text: "hello from compose" })}>Send text</button>
    </div>
  ),
}));
vi.mock("./ThreadPanel", () => ({
  ThreadPanel: ({ open }: { open: boolean }) => (
    open ? <div role="dialog" aria-label="Thread panel">Thread panel open</div> : null
  ),
}));
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

describe("ConversationView reply routing", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getMessages.mockResolvedValue({
      messages: [
        {
          message_id: "m_root",
          conversation_id: "c1",
          sender_id: "u2",
          kind: "text",
          text: "Root message",
          created_at: 10,
        },
        {
          message_id: "m_reply",
          conversation_id: "c1",
          sender_id: "u2",
          kind: "text",
          text: "Reply message",
          created_at: 11,
          parent_message_id: "m_root",
          thread_id: "thr_1",
          thread_root_message_id: "m_root",
        },
      ],
      next_cursor: undefined,
    });
    sendTextMessage.mockResolvedValue({});
  });

  it("routes reply-to-reply into thread context by opening the thread panel", async () => {
    renderView();

    await userEvent.click(await screen.findByRole("button", { name: "Reply m_reply" }));

    expect(await screen.findByRole("dialog", { name: "Thread panel" })).toBeInTheDocument();
    expect(screen.getByTestId("replying-to")).toHaveTextContent("none");
  });

  it("includes linkage fields when sending direct composer replies", async () => {
    renderView();

    await userEvent.click(await screen.findByRole("button", { name: "Reply m_root" }));
    expect(screen.getByTestId("replying-to")).toHaveTextContent("m_root");

    await userEvent.click(screen.getByRole("button", { name: "Send text" }));

    await waitFor(() => {
      expect(sendTextMessage).toHaveBeenCalledWith(
        "c1",
        expect.objectContaining({
          text: "hello from compose",
          reply_to_message_id: "m_root",
          parent_message_id: "m_root",
          thread_root_message_id: "m_root",
        }),
      );
    });
  });
});
