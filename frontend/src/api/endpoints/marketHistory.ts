import { api, ApiError } from "@/api/client";
import { getCandles, type CandlesResponse } from "@/api/endpoints/marketData";

/**
 * Long-range historical market data.
 *
 * The backend endpoint (`GET /md/history/{symbolId}`) does NOT exist yet. When
 * it 404s (or otherwise reports absent), {@link getHistory} DEGRADES to the
 * existing recent-window `/md/candles` feed so the Analysis workbench still
 * works on whatever window it can pull, flagging the degrade via `stub: true`
 * so the UI can show the "recent window only" banner.
 *
 * Prices in `bars` are RAW integers (scaled by the symbol's `price_scaler`),
 * exactly as `/md/candles` returns them; callers de-scale for display/stats.
 */

/** One OHLCV bar. `ts` is epoch-ms. Prices/volume are raw (unscaled) values. */
export interface HistoryBar {
  ts: number;
  o: number;
  h: number;
  l: number;
  c: number;
  v: number;
}

export interface HistoryResponse {
  symbol_id: number;
  interval: string;
  bars: HistoryBar[];
  next_cursor?: string | null;
  /** True when this came from the recent-window fallback, not real history. */
  stub?: boolean;
}

/** Raw shape of the (not-yet-existing) history endpoint. */
interface RawHistoryResponse {
  symbol_id: number;
  interval: string;
  bars: { ts: number; o: number; h: number; l: number; c: number; v: number }[];
  next_cursor?: string | null;
  stub?: boolean;
}

export interface HistoryParams {
  /** Interval token, e.g. "1m", "5m", "1h", "1d". */
  interval: string;
  /** Inclusive lower bound, epoch-ms. */
  from?: number;
  /** Inclusive upper bound, epoch-ms. */
  to?: number;
  /** Opaque pagination cursor from a prior `next_cursor`. */
  cursor?: string;
}

/** Map an interval token to the candle-endpoint's second granularity. */
const INTERVAL_SECONDS: Record<string, number> = {
  "1m": 60,
  "5m": 300,
  "15m": 900,
  "1h": 3600,
  "4h": 14400,
  "1d": 86400,
};

export function intervalToSeconds(interval: string): number {
  return INTERVAL_SECONDS[interval] ?? 60;
}

/** Convert a recent-window candle response into the history bar shape. */
function candlesToHistory(symbolId: number, interval: string, res: CandlesResponse): HistoryResponse {
  const bars: HistoryBar[] = (res.bars ?? []).map((b) => ({
    ts: Math.floor(b.ts_start_ns / 1_000_000),
    o: b.open,
    h: b.high,
    l: b.low,
    c: b.close,
    v: b.volume,
  }));
  return { symbol_id: symbolId, interval, bars, next_cursor: null, stub: true };
}

/** Cap on the recent-window fallback fetch (candles endpoint hard-limits anyway). */
const FALLBACK_LIMIT = 1000;

/**
 * Fetch historical bars for a symbol. Tries the real long-range endpoint first;
 * on a 404 (endpoint absent) falls back to the recent-window candle feed and
 * marks the result `stub: true`.
 */
export async function getHistory(symbolId: number, params: HistoryParams): Promise<HistoryResponse> {
  const query: Record<string, string> = { interval: params.interval };
  if (params.from != null) query.from = String(params.from);
  if (params.to != null) query.to = String(params.to);
  if (params.cursor) query.cursor = params.cursor;

  try {
    const raw = await api.get<RawHistoryResponse>(`/md/history/${symbolId}`, query);
    return {
      symbol_id: raw.symbol_id ?? symbolId,
      interval: raw.interval ?? params.interval,
      bars: Array.isArray(raw.bars) ? raw.bars : [],
      next_cursor: raw.next_cursor ?? null,
      stub: raw.stub ?? false,
    };
  } catch (err) {
    // Endpoint absent (404) or unimplemented (501): degrade to the recent window.
    if (err instanceof ApiError && (err.status === 404 || err.status === 501 || err.status === 0)) {
      const sec = intervalToSeconds(params.interval);
      const res = await getCandles(symbolId, sec, FALLBACK_LIMIT);
      return candlesToHistory(symbolId, params.interval, res);
    }
    throw err;
  }
}
