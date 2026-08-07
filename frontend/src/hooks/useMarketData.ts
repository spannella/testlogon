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

export function useOrderBook(symbolId: number, depth = 20, enabled = true) {
  return useQuery({
    queryKey: ["md", "book", symbolId, depth],
    queryFn: () => getOrderBook(symbolId, depth),
    enabled: enabled && Number.isFinite(symbolId) && symbolId > 0,
    refetchInterval: LIVE_REFETCH_MS,
  });
}

export function useCandles(symbolId: number, interval = 60, enabled = true) {
  return useQuery({
    queryKey: ["md", "candles", symbolId, interval],
    queryFn: () => getCandles(symbolId, interval),
    enabled: enabled && Number.isFinite(symbolId) && symbolId > 0,
    refetchInterval: LIVE_REFETCH_MS,
  });
}

export function useTrades(symbolId: number, enabled = true) {
  return useQuery({
    queryKey: ["md", "trades", symbolId],
    queryFn: () => getTrades(symbolId),
    enabled: enabled && Number.isFinite(symbolId) && symbolId > 0,
    refetchInterval: LIVE_REFETCH_MS,
  });
}
