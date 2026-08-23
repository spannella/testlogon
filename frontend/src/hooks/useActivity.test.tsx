import type { ReactNode } from "react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import { ApiError } from "@/api/client";
import { useActivityEvents } from "./useActivity";

const getFillsFees = vi.fn();
const getLiquidations = vi.fn();
const getFundingPayments = vi.fn();
const getSymbols = vi.fn();

vi.mock("@/api/endpoints/trading", () => ({
  getFillsFees: (...a: unknown[]) => getFillsFees(...a),
  getLiquidations: (...a: unknown[]) => getLiquidations(...a),
  getFundingPayments: (...a: unknown[]) => getFundingPayments(...a),
}));

vi.mock("@/api/endpoints/marketData", () => ({
  getSymbols: (...a: unknown[]) => getSymbols(...a),
  getOrderBook: vi.fn(),
  getCandles: vi.fn(),
  getTrades: vi.fn(),
}));

function wrapper(client: QueryClient) {
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
}
function newClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
}

const SYMBOLS = {
  symbols: [{ symbol_id: 1, symbol: "BTC-USD", price_scaler: 100 }],
};

describe("useActivityEvents aggregation", () => {
  beforeEach(() => {
    getFillsFees.mockReset();
    getLiquidations.mockReset();
    getFundingPayments.mockReset();
    getSymbols.mockReset();
    getSymbols.mockResolvedValue(SYMBOLS);
  });

  it("degrades independently: every feed 404 -> empty events, all sources marked unavailable, no throw", async () => {
    getFillsFees.mockRejectedValue(new ApiError(404, "Not found"));
    getFundingPayments.mockRejectedValue(new ApiError(404, "Not found"));
    getLiquidations.mockRejectedValue(new ApiError(404, "Not found"));

    const { result } = renderHook(() => useActivityEvents(), { wrapper: wrapper(newClient()) });

    await waitFor(() => {
      expect(result.current.sources.fills).toBe(false);
      expect(result.current.sources.funding).toBe(false);
      expect(result.current.sources.liquidations).toBe(false);
    });
    expect(result.current.events).toEqual([]);
  });

  it("happy path: merges fills + funding + liquidations into one newest-first timeline", async () => {
    getFillsFees.mockResolvedValue({
      fills: [
        { symbolid: 1, ts: 3000, side: "buy", qty: 1, price: 10000, fee: 5 },
      ],
    });
    getFundingPayments.mockResolvedValue({
      funding: [{ symbolid: 1, ts: 2000, payment: 12, funding_rate_bps: 3, received: true }],
    });
    getLiquidations.mockResolvedValue({
      liquidations: [{ symbolid: 1, ts: 1000, qty: 1, mark_price: 9000, realized_pnl: -50 }],
    });

    const { result } = renderHook(() => useActivityEvents(), { wrapper: wrapper(newClient()) });

    await waitFor(() => expect(result.current.events.length).toBeGreaterThan(0));
    // All three sources available; merged into a single, newest-first list.
    expect(result.current.sources).toEqual({ fills: true, funding: true, liquidations: true });
    const tsList = result.current.events.map((e) => e.ts);
    const sorted = [...tsList].sort((a, b) => b - a);
    expect(tsList).toEqual(sorted);
  });

  it("one feed available while another 404s -> partial timeline, only the failed source is unavailable", async () => {
    getFillsFees.mockResolvedValue({
      fills: [
        { symbolid: 1, ts: 3000, side: "buy", qty: 1, price: 10000, fee: 5 },
      ],
    });
    getFundingPayments.mockRejectedValue(new ApiError(404, "Not found"));
    getLiquidations.mockRejectedValue(new ApiError(404, "Not found"));

    const { result } = renderHook(() => useActivityEvents(), { wrapper: wrapper(newClient()) });

    await waitFor(() => expect(result.current.events.length).toBeGreaterThan(0));
    expect(result.current.sources.fills).toBe(true);
    expect(result.current.sources.funding).toBe(false);
    expect(result.current.sources.liquidations).toBe(false);
  });
});
