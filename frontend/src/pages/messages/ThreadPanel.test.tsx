import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, expect, it, vi, beforeEach } from "vitest";
import type { Message } from "@/api/types";
import { ThreadPanel } from "./ThreadPanel";

const getThreadMessages = vi.fn();
const sendTextMessage = vi.fn();

vi.mock("@/api/endpoints/messaging", () => ({
  getThreadMessages: (...args: unknown[]) => getThreadMessages(...args),
  sendTextMessage: (...args: unknown[]) => sendTextMessage(...args),
}));
vi.mock("./MessageBubble", () => ({
  MessageBubble: ({ message }: { message: Message }) => <div data-testid={`thread-msg-${message.message_id}`}>{message.text}</div>,
}));

function renderPanel() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <ThreadPanel
        open
        onOpenChange={() => {}}
        conversationId="c1"
        currentUserId="u1"
        anchorMessage={{
          message_id: "m_root",
          conversation_id: "c1",
          sender_id: "u1",
          kind: "text",
          created_at: 100,
          text: "Root",
          thread_id: "thr_1",
          thread_root_message_id: "m_root",
          has_thread: true,
          thread_reply_count: 2,
        }}
      />
    </QueryClientProvider>,
  );
}

describe("ThreadPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getThreadMessages.mockResolvedValue({
      items: [
        {
          message_id: "m_root",
          conversation_id: "c1",
          sender_id: "u1",
          kind: "text",
          created_at: 100,
          text: "Root",
          thread_id: "thr_1",
          thread_root_message_id: "m_root",
        },
        {
          message_id: "m_reply",
          conversation_id: "c1",
          sender_id: "u2",
          kind: "text",
          created_at: 110,
          text: "Reply",
          thread_id: "thr_1",
          thread_root_message_id: "m_root",
          reply_to_message_id: "m_root",
        },
      ],
      next_cursor: null,
    });
    sendTextMessage.mockResolvedValue({});
  });

  it("loads thread messages and sends new reply in thread context", async () => {
    renderPanel();

    expect(await screen.findByTestId("thread-msg-m_root")).toBeInTheDocument();
    expect(screen.getByTestId("thread-msg-m_reply")).toBeInTheDocument();

    await userEvent.type(screen.getByPlaceholderText("Reply in thread…"), "New thread reply");
    await userEvent.click(screen.getByRole("button", { name: /Send reply/i }));

    await waitFor(() => {
      expect(sendTextMessage).toHaveBeenCalledWith("c1", {
        text: "New thread reply",
        reply_to_message_id: "m_reply",
        parent_message_id: "m_reply",
        thread_id: "thr_1",
        thread_root_message_id: "m_root",
      });
    });
  });
});
