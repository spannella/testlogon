import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MessageBubble } from "./MessageBubble";
import type { Message } from "@/api/types";

// MessageBubble pulls in a large messaging surface; stub the API + side modules
// (mirrors MessageBubble.tradingcards.test.tsx).
vi.mock("@/api/endpoints/messaging", () => ({
  deleteMessage: vi.fn(),
  editMessage: vi.fn(),
  reactToMessage: vi.fn(),
  hideMessage: vi.fn(),
  reportMessage: vi.fn(),
  createOnceMediaAttachmentGrant: vi.fn(),
  consumeOnceMediaAttachment: vi.fn(),
  buildAttachmentDownloadUrl: vi.fn(),
  sendMessageTip: vi.fn(),
  sendTextMessage: vi.fn(),
  unlockMessage: vi.fn(),
  unlockLotteryMessage: vi.fn(),
  getMeetingPoll: vi.fn(),
  voteMeetingPoll: vi.fn(),
  confirmMeetingPoll: vi.fn(),
  markViewed: vi.fn(),
}));
vi.mock("@/api/endpoints/messagingAi", () => ({ translateMessage: vi.fn() }));
vi.mock("@/api/endpoints/calendar", () => ({ createEvent: vi.fn() }));
vi.mock("@/api/endpoints/billing", () => ({ getPaymentMethods: vi.fn(async () => []) }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("./ReadReceipts", () => ({ ReadReceipts: () => null, ViewTracker: () => null }));
vi.mock("./ForwardDialog", () => ({ ForwardDialog: () => null }));
vi.mock("./MessageDetailsSheet", () => ({ MessageDetailsSheet: () => null }));

function renderBubble(message: Message, isOwn: boolean) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <MessageBubble conversationId="c1" isOwn={isOwn} message={message} />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

const base = {
  message_id: "m1",
  conversation_id: "c1",
  sender_id: "u-sender",
  created_at: 1,
  reactions_counts: {},
};

beforeEach(() => {
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: vi.fn().mockImplementation((query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  });
});

describe("MessageBubble crypto_transfer card", () => {
  it("renders a SENT transfer (own message) with amount, fiat and sent styling", () => {
    renderBubble(
      {
        ...base,
        kind: "crypto_transfer",
        asset: "ETH",
        amount: "0.50",
        decimals: 18,
        fiat_cents: 100000,
        status: "complete",
      } as unknown as Message,
      true,
    );

    const card = screen.getByTestId("crypto-transfer-card");
    expect(card).toBeInTheDocument();
    expect(card).toHaveAttribute("data-direction", "sent");
    expect(screen.getByTestId("crypto-transfer-direction")).toHaveTextContent("Sent crypto");
    expect(screen.getByTestId("crypto-transfer-amount")).toHaveTextContent("0.5 ETH");
    expect(screen.getByTestId("crypto-transfer-fiat")).toHaveTextContent("$1,000.00");
    expect(screen.getByTestId("crypto-transfer-status")).toHaveTextContent("Complete");
  });

  it("renders a RECEIVED transfer (other's message) with received styling + pending badge", () => {
    renderBubble(
      {
        ...base,
        kind: "crypto_transfer",
        asset: "USDC",
        amount: "100",
        decimals: 6,
        status: "pending",
      } as unknown as Message,
      false,
    );

    const card = screen.getByTestId("crypto-transfer-card");
    expect(card).toHaveAttribute("data-direction", "received");
    expect(screen.getByTestId("crypto-transfer-direction")).toHaveTextContent("Received crypto");
    expect(screen.getByTestId("crypto-transfer-amount")).toHaveTextContent("100 USDC");
    expect(screen.getByTestId("crypto-transfer-status")).toHaveTextContent("Pending");
  });
});
