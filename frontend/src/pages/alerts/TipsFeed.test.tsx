import { describe, expect, it, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";

import { TipsFeed } from "@/pages/alerts/TipsFeed";
import { TipsSentFeed } from "@/pages/alerts/TipsSentFeed";
import { getTipsReceivedSummary, getTipsSent, getTipsSentSummary } from "@/api/endpoints/tips";

vi.mock("@/api/endpoints/tips", () => ({
  getTipsReceivedSummary: vi.fn(),
  getTipsSent: vi.fn(),
  getTipsSentSummary: vi.fn(),
}));

function renderWithClient(node: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{node}</QueryClientProvider>);
}

describe("TipsFeed (TIPX-D1 — ledger-backed, reconciled)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("labels the total 'Net tips received' (not 'Total Earned') and renders all-surface breakdown", async () => {
    // Ledger-backed net summary: 800 + 1600 + 240 net across 3 surfaces.
    vi.mocked(getTipsReceivedSummary).mockResolvedValue({
      total_tips_cents: 2640,
      tip_count: 3,
      unique_tippers: 2,
      net: true,
      source: "ledger",
      top_tippers: [
        { user_id: "t2", display_name: "Tipper Two", total_cents: 1840, tip_count: 2 },
        { user_id: "t1", display_name: "Tipper One", total_cents: 800, tip_count: 1 },
      ],
      by_type: {
        post_tip: { count: 1, total_cents: 800 },
        message_tip: { count: 0, total_cents: 0 },
      },
      by_surface: {
        post: { count: 1, total_cents: 800 },
        comment: { count: 1, total_cents: 1600 },
        video: { count: 1, total_cents: 240 },
      },
    });

    renderWithClient(<TipsFeed />);

    await waitFor(() => expect(screen.getByText("$26.40")).toBeInTheDocument());
    // Honest label — no "Total Earned" anywhere.
    expect(screen.getByText("Net tips received")).toBeInTheDocument();
    expect(screen.queryByText("Total Earned")).not.toBeInTheDocument();
    // All 3 seeded surfaces show (comment/video were dropped by the old 2-surface total).
    expect(screen.getByText("Comment tips")).toBeInTheDocument();
    expect(screen.getByText("Video tips")).toBeInTheDocument();
    expect(screen.getByText("Post tips")).toBeInTheDocument();
    // Top supporter names come through.
    expect(screen.getByText("Tipper Two")).toBeInTheDocument();
  });

  it("shows the empty state when there are no tips", async () => {
    vi.mocked(getTipsReceivedSummary).mockResolvedValue({
      total_tips_cents: 0,
      tip_count: 0,
      unique_tippers: 0,
      net: true,
      source: "ledger",
      top_tippers: [],
      by_type: { post_tip: { count: 0, total_cents: 0 }, message_tip: { count: 0, total_cents: 0 } },
      by_surface: {},
    });
    renderWithClient(<TipsFeed />);
    await waitFor(() => expect(screen.getByText("No tips yet")).toBeInTheDocument());
  });
});

describe("TipsSentFeed (TIPX-D4 — tipper receipts)", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders sent-tip receipts with recipient, amount, and fee", async () => {
    vi.mocked(getTipsSentSummary).mockResolvedValue({
      period: "all",
      total_sent_cents: 3000,
      tip_count: 2,
      unique_recipients: 1,
      source: "ledger",
    });
    vi.mocked(getTipsSent).mockResolvedValue({
      items: [
        {
          entry_id: "e1",
          ts: 1784200000,
          amount_cents: 1000,
          reason: "Tip: post",
          content_type: "post",
          content_id: "post_A",
          counterparty_user_id: "creator1",
          counterparty_display_name: "Cool Creator",
          platform_fee_cents: 200,
          tip_payment_id: "tip_1",
          currency: "USD",
        },
      ],
      next_cursor: null,
    });

    renderWithClient(<TipsSentFeed />);

    await waitFor(() => expect(screen.getByText("Cool Creator")).toBeInTheDocument());
    expect(screen.getByText("$30.00")).toBeInTheDocument(); // total sent
    expect(screen.getByText("$10.00")).toBeInTheDocument(); // receipt amount
    expect(screen.getByText("fee $2.00")).toBeInTheDocument();
  });
});
