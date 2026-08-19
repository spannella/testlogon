import { useQuery } from "@tanstack/react-query";
import {
  getSymbols,
  getOrderBook,
  getCandles,
  getTrades,
} from "@/api/endpoints/marketData";

const LIVE_REFETCH_MS = 2000;

export function useSymbols() {
  return useQuery({
    queryKey: ["md", "symbols"],
    queryFn: getSymbols,
    staleTime: 30_000,
  });
}

/**
 * Order book. `refetchMs` defaults to the live 2s poll; pass `false` (or a
 * larger value) to disable/relax polling when SSE drives the book.
 */
export function useOrderBook(
  symbolId: number,
  depth = 20,
  enabled = true,
  refetchMs: number | false = LIVE_REFETCH_MS
) {
  return useQuery({
    queryKey: ["md", "book", symbolId, depth],
    queryFn: () => getOrderBook(symbolId, depth),
    enabled: enabled && Number.isFinite(symbolId) && symbolId > 0,
    refetchInterval: refetchMs,
  });
}

export function useCandles(symbolId: number, interval = 60, enabled = true, limit = 200) {
  return useQuery({
    queryKey: ["md", "candles", symbolId, interval, limit],
    queryFn: () => getCandles(symbolId, interval, limit),
    enabled: enabled && Number.isFinite(symbolId) && symbolId > 0,
    refetchInterval: LIVE_REFETCH_MS,
  });
}

/**
 * Recent trades. SSE carries no trades, so this stays on a poll; the caller
 * may relax `refetchMs` (e.g. 4s) when the book/candles are streamed live.
 */
export function useTrades(
  symbolId: number,
  enabled = true,
  refetchMs: number | false = LIVE_REFETCH_MS
) {
  return useQuery({
    queryKey: ["md", "trades", symbolId],
    queryFn: () => getTrades(symbolId),
    enabled: enabled && Number.isFinite(symbolId) && symbolId > 0,
    refetchInterval: refetchMs,
  });
}
