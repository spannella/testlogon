import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MessageBubble } from "./MessageBubble";
import type { Message } from "@/api/types";

// MessageBubble pulls in a large messaging surface; stub the API + side modules
// (mirrors MessageBubble.cryptotransfer.test.tsx).
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

describe("MessageBubble product_card (FE-150)", () => {
  it("renders title, price, in-stock badge and an enabled Buy button", () => {
    renderBubble(
      {
        ...base,
        kind: "product_card",
        product_id: "it-1",
        category_id: "cat-1",
        title: "Blue Widget",
        price_cents: 1299,
        currency: "USD",
        in_stock: true,
      } as unknown as Message,
      false,
    );

    expect(screen.getByTestId("product-card")).toBeInTheDocument();
    expect(screen.getByTestId("product-card-title")).toHaveTextContent("Blue Widget");
    expect(screen.getByTestId("product-card-price")).toHaveTextContent("$12.99");
    expect(screen.getByTestId("product-card-stock")).toHaveTextContent("In stock");
    const buy = screen.getByTestId("product-card-buy");
    expect(buy).toBeInTheDocument();
    expect(buy).not.toBeDisabled();
  });

  it("disables Buy for an out-of-stock product", () => {
    renderBubble(
      {
        ...base,
        kind: "product_card",
        product_id: "it-2",
        title: "Sold Out Thing",
        price_cents: 500,
        currency: "USD",
        in_stock: false,
      } as unknown as Message,
      false,
    );
    expect(screen.getByTestId("product-card-stock")).toHaveTextContent("Out of stock");
    expect(screen.getByTestId("product-card-buy")).toBeDisabled();
  });
});

describe("MessageBubble order_card (FE-151)", () => {
  it("receipt mode shows items + status but NO amount / no PII", () => {
    renderBubble(
      {
        ...base,
        kind: "order_card",
        order_id: "ord-9",
        mode: "receipt",
        status: "shipped",
        currency: "USD",
        item_count: 2,
        // amount_cents intentionally absent for receipt mode (choke point strips it)
        items: [
          { name: "Blue Widget", quantity: 2 },
          { name: "Red Gadget", quantity: 1 },
        ],
      } as unknown as Message,
      true,
    );

    const card = screen.getByTestId("order-share-card");
    expect(card).toHaveAttribute("data-mode", "receipt");
    expect(screen.getByTestId("order-share-mode")).toHaveTextContent("Receipt");
    expect(screen.getByTestId("order-share-status")).toHaveTextContent("shipped");
    expect(screen.getByTestId("order-share-items")).toHaveTextContent("Blue Widget");
    // No amount surfaced in receipt mode.
    expect(screen.queryByTestId("order-share-amount")).toBeNull();
    // No buyer PII anywhere in the rendered card.
    expect(card.textContent ?? "").not.toContain("Jane");
    expect(card.textContent ?? "").not.toContain("Street");
  });

  it("gift mode surfaces the amount", () => {
    renderBubble(
      {
        ...base,
        kind: "order_card",
        order_id: "ord-10",
        mode: "gift",
        status: "delivered",
        currency: "USD",
        amount_cents: 4599,
        item_count: 1,
        items: [{ name: "Blue Widget", quantity: 1 }],
      } as unknown as Message,
      true,
    );
    expect(screen.getByTestId("order-share-mode")).toHaveTextContent("Gift");
    expect(screen.getByTestId("order-share-amount")).toHaveTextContent("$45.99");
  });
});
