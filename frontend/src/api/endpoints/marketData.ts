import { api } from "@/api/client";

// ── Types ──────────────────────────────────────────────────────────

export interface MarketSymbol {
  symbol: string;
  symbol_id: number;
  instrument_id: number;
  price_scaler: number;
  lot_size: number;
  reference_price: number;
  matching_algo: string;
  is_perpetual: boolean;
  funding_interval_s: number;
}

export interface SymbolsResponse {
  count: number;
  symbols: MarketSymbol[];
}

/** A price level as an integer [price, qty] tuple. */
export type BookLevel = [number, number];

export interface OrderBookResponse {
  symbol: number;
  depth: number;
  bid_levels: number;
  ask_levels: number;
  bid_px: number;
  ask_px: number;
  bids: BookLevel[];
  asks: BookLevel[];
}

export interface Candle {
  open: number;
  high: number;
  low: number;
  close: number;
  volume: number;
  trades: number;
  ts_start_ns: number;
}

export interface CandlesResponse {
  symbol: number;
  interval_sec: number;
  durable: boolean;
  from: number;
  to: number;
  count: number;
  bars: Candle[];
}

export interface Trade {
  aggressor: "buy" | "sell";
  price: number;
  qty: number;
  ts_ns: number;
}

export interface TradesResponse {
  symbol: number;
  count: number;
  trades: Trade[];
}

// ── API calls ──────────────────────────────────────────────────────

export const getSymbols = () => api.get<SymbolsResponse>("/md/symbols");

export const getOrderBook = (symbolId: number, depth = 20) =>
  api.get<OrderBookResponse>(`/md/book/${symbolId}`, { depth: String(depth) });

export const getCandles = (symbolId: number, interval = 60, limit = 200) =>
  api.get<CandlesResponse>(`/md/candles/${symbolId}`, {
    interval: String(interval),
    limit: String(limit),
  });

export const getTrades = (symbolId: number) =>
  api.get<TradesResponse>(`/md/trades/${symbolId}`);
