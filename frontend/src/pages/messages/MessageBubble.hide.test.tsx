import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider, type InfiniteData } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { MessageBubble } from "./MessageBubble";

const hideMessage = vi.fn();
const toastSuccess = vi.fn();
const toastError = vi.fn();

vi.mock("@/api/endpoints/messaging", () => ({
  deleteMessage: vi.fn(async () => ({ ok: true })),
  editMessage: vi.fn(async () => ({ ok: true })),
  reactToMessage: vi.fn(async () => ({ ok: true })),
  hideMessage: (...args: unknown[]) => hideMessage(...args),
  createOnceMediaAttachmentGrant: vi.fn(),
  consumeOnceMediaAttachment: vi.fn(),
  buildAttachmentDownloadUrl: vi.fn(),
  sendMessageTip: vi.fn(),
  unlockMessage: vi.fn(),
  getMeetingPoll: vi.fn(),
  voteMeetingPoll: vi.fn(),
  confirmMeetingPoll: vi.fn(),
  markViewed: vi.fn(),
}));

vi.mock("sonner", () => ({
  toast: {
    success: (...args: unknown[]) => toastSuccess(...args),
    error: (...args: unknown[]) => toastError(...args),
  },
}));

vi.mock("./ReadReceipts", () => ({ ReadReceipts: () => null, ViewTracker: () => null }));
vi.mock("./ForwardDialog", () => ({ ForwardDialog: () => null }));
vi.mock("./MessageDetailsSheet", () => ({ MessageDetailsSheet: () => null }));
vi.mock("@/api/endpoints/billing", () => ({ getPaymentMethods: vi.fn(async () => []) }));
vi.mock("@/lib/featureFlags", () => ({ isMessagingEncryptionEnabled: vi.fn(() => true) }));

const queryKey = ["messages", "c1"] as const;

type MessagesPage = { messages: Array<{ message_id: string } & Record<string, unknown>>; next_cursor?: string };

function makeClientWithMessages() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  client.setQueryData<InfiniteData<MessagesPage>>(queryKey, {
    pages: [
      {
        messages: [
          { message_id: "m1", conversation_id: "c1", sender_id: "u2", kind: "text", text: "hello", created_at: 1 },
          { message_id: "m2", conversation_id: "c1", sender_id: "u2", kind: "text", text: "other", created_at: 2 },
        ],
      },
    ],
    pageParams: [undefined],
  });
  return client;
}

function renderBubble(client: QueryClient) {
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <MessageBubble
          conversationId="c1"
          isOwn={false}
          message={{
            message_id: "m1",
            conversation_id: "c1",
            sender_id: "u2",
            kind: "text",
            created_at: 1,
            text: "hello",
          }}
        />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("MessageBubble hide action", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("optimistically removes message and calls hide endpoint", async () => {
    let resolveHide: (() => void) | undefined;
    hideMessage.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          resolveHide = resolve;
        }),
    );

    const client = makeClientWithMessages();
    renderBubble(client);

    await userEvent.click(screen.getByRole("button", { name: "Message actions" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: /Hide for me/i }));

    const dataAfterMutate = client.getQueryData<InfiniteData<MessagesPage>>(queryKey);
    expect(dataAfterMutate?.pages[0]?.messages.map((m) => m.message_id)).toEqual(["m2"]);
    expect(hideMessage).toHaveBeenCalledWith("c1", "m1");

    resolveHide?.();
    await waitFor(() => expect(toastSuccess).toHaveBeenCalledWith("Message hidden"));
  });

  it("rolls back optimistic removal on hide failure", async () => {
    hideMessage.mockRejectedValueOnce(new Error("boom"));

    const client = makeClientWithMessages();
    renderBubble(client);

    await userEvent.click(screen.getByRole("button", { name: "Message actions" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: /Hide for me/i }));

    await waitFor(() => expect(toastError).toHaveBeenCalledWith("Failed to hide message"));

    const rolledBack = client.getQueryData<InfiniteData<MessagesPage>>(queryKey);
    expect(rolledBack?.pages[0]?.messages.map((m) => m.message_id)).toEqual(["m1", "m2"]);
  });
});
