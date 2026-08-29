import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MessageBubble } from "./MessageBubble";
import type { Message } from "@/api/types";

// MessageBubble pulls in a large messaging surface; stub the API + side modules.
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

// MarketCard reads live md via these hooks -- return a stable candle window.
vi.mock("@/hooks/useMarketData", () => ({
  useSymbols: () => ({
    data: { symbols: [{ symbol_id: 1, symbol: "BTCUSDC", price_scaler: 1 }] },
    isLoading: false,
  }),
  useCandles: () => ({
    data: {
      bars: [
        { open: 100, high: 105, low: 99, close: 100, volume: 1, trades: 1, ts_start_ns: 1 },
        { open: 100, high: 115, low: 100, close: 110, volume: 1, trades: 1, ts_start_ns: 2 },
      ],
    },
    isLoading: false,
  }),
}));

function renderBubble(message: Message) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <MessageBubble conversationId="c1" isOwn={false} message={message} />
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

describe("MessageBubble trading cards", () => {
  it("renders a market_card with ticker, live price, change% and a Trade button", () => {
    renderBubble({
      ...base,
      kind: "market_card",
      symbol_id: 1,
      symbol: "BTCUSDC",
    } as Message);

    expect(screen.getByTestId("market-card")).toBeInTheDocument();
    expect(screen.getByTestId("market-card-ticker")).toHaveTextContent("BTCUSDC");
    // last close = 110
    expect(screen.getByTestId("market-card-price")).toHaveTextContent("110");
    // change = (110-100)/100 = +10%
    expect(screen.getByTestId("market-card-change")).toHaveTextContent("+10.00%");
    expect(screen.getByTestId("market-card-trade")).toBeInTheDocument();
  });

  it("renders a full-disclosure position_card with ROI, side and notionals", () => {
    renderBubble({
      ...base,
      kind: "position_card",
      symbol_id: 1,
      symbol: "BTCUSDC",
      side: "Long",
      disclosure: "full",
      roi_pct: 12.5,
      entry: 100000,
      mark: 112500,
      size: 3,
      price_scaler: 1,
    } as Message);

    expect(screen.getByTestId("position-card")).toBeInTheDocument();
    expect(screen.getByTestId("position-card-ticker")).toHaveTextContent("BTCUSDC");
    expect(screen.getByTestId("position-card-side")).toHaveTextContent("Long");
    expect(screen.getByTestId("position-card-roi")).toHaveTextContent("+12.50%");
    expect(screen.getByTestId("position-card-full-metrics")).toBeInTheDocument();
  });

  it("renders a reduced-disclosure position_card WITHOUT notionals", () => {
    renderBubble({
      ...base,
      kind: "position_card",
      symbol_id: 1,
      symbol: "BTCUSDC",
      side: "Short",
      disclosure: "roi",
      roi_pct: -4.2,
    } as Message);

    expect(screen.getByTestId("position-card-roi")).toHaveTextContent("-4.20%");
    expect(screen.queryByTestId("position-card-full-metrics")).not.toBeInTheDocument();
  });
});
