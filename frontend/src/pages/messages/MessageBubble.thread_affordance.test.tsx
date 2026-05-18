import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import type { Message } from "@/api/types";
import { MessageBubble } from "./MessageBubble";

vi.mock("@/api/endpoints/messaging", () => ({
  deleteMessage: vi.fn(async () => ({ ok: true })),
  editMessage: vi.fn(async () => ({ ok: true })),
  reactToMessage: vi.fn(async () => ({ ok: true })),
  hideMessage: vi.fn(async () => ({ ok: true })),
  reportMessage: vi.fn(async () => ({ ok: true })),
  createOnceMediaAttachmentGrant: vi.fn(),
  consumeOnceMediaAttachment: vi.fn(),
  buildAttachmentDownloadUrl: vi.fn(),
  sendMessageTip: vi.fn(),
  unlockMessage: vi.fn(),
  getMeetingPoll: vi.fn(),
  voteMeetingPoll: vi.fn(),
  confirmMeetingPoll: vi.fn(),
  markViewed: vi.fn(async () => ({ ok: true })),
}));
vi.mock("./ReadReceipts", () => ({ ReadReceipts: () => null, ViewTracker: () => null }));
vi.mock("./ForwardDialog", () => ({ ForwardDialog: () => null }));
vi.mock("./MessageDetailsSheet", () => ({ MessageDetailsSheet: () => null }));
vi.mock("@/api/endpoints/billing", () => ({ getPaymentMethods: vi.fn(async () => []) }));
vi.mock("@/lib/featureFlags", () => ({ isMessagingEncryptionEnabled: vi.fn(() => true) }));

function renderBubble(message: Message, onViewThread?: (message: Message) => void) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <MessageBubble
          conversationId="c1"
          isOwn={false}
          message={message}
          onViewThread={onViewThread}
        />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("MessageBubble thread affordance", () => {
  it("renders thread entry point with reply count and last activity for threaded messages", () => {
    renderBubble({
      message_id: "m-thread-root",
      conversation_id: "c1",
      sender_id: "u2",
      kind: "text",
      created_at: 1_710_000_000,
      text: "Root message",
      has_thread: true,
      thread_reply_count: 3,
      thread_last_reply_at: 1_710_000_600,
      thread_id: "thr_1",
    });

    expect(screen.getByRole("button", { name: /View thread/i })).toBeInTheDocument();
    expect(screen.getByText("3 replies")).toBeInTheDocument();
    expect(screen.getByText(/Last activity/i)).toBeInTheDocument();
  });

  it("keeps non-threaded messages unchanged (no thread affordance)", () => {
    const onViewThread = vi.fn();
    renderBubble({
      message_id: "m-plain",
      conversation_id: "c1",
      sender_id: "u2",
      kind: "text",
      created_at: 1_710_000_000,
      text: "Plain message",
      has_thread: false,
      thread_reply_count: 0,
    }, onViewThread);

    expect(screen.queryByRole("button", { name: /View thread/i })).not.toBeInTheDocument();
  });

  it("invokes entry-point callback when thread affordance is clicked", async () => {
    const onViewThread = vi.fn();
    const message: Message = {
      message_id: "m-thread",
      conversation_id: "c1",
      sender_id: "u2",
      kind: "text",
      created_at: 1_710_000_000,
      text: "Threaded",
      has_thread: true,
      thread_reply_count: 1,
      thread_id: "thr_1",
    };
    renderBubble(message, onViewThread);

    await userEvent.click(screen.getByRole("button", { name: /View thread/i }));
    expect(onViewThread).toHaveBeenCalledWith(message);
  });
});
