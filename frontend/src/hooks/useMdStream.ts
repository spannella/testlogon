import * as React from "react";
import { withApiBase } from "@/api/client";
import type { Candle, OrderBookResponse } from "@/api/endpoints/marketData";

/** Reconnect backoff ceiling (ms). */
const MAX_RETRY_DELAY = 15_000;

/** Shape of the `data:` JSON carried by each `event: md` SSE frame. */
interface MarketDataFrame {
  symbol: number;
  book: OrderBookResponse;
  bars: {
    bars: Candle[];
    count: number;
    interval_sec: number;
    symbol: number;
  };
}

export interface MdStreamState {
  /** Latest streamed order book, or null until the first frame arrives. */
  book: OrderBookResponse | null;
  /** Candle series from the most recent frame, or null until the first frame. */
  bars: Candle[] | null;
  /** Latest price derived from the newest bar close, else best bid/ask mid. */
  lastPrice: number | null;
  /** True while the EventSource is open (a frame has been received / open). */
  connected: boolean;
}

function derivePrice(book: OrderBookResponse | null, bars: Candle[] | null): number | null {
  const last = bars && bars.length ? bars[bars.length - 1] : undefined;
  if (last && Number.isFinite(last.close)) return last.close;
  const bid = book?.bid_px;
  const ask = book?.ask_px;
  if (bid != null && ask != null) return (bid + ask) / 2;
  return ask ?? bid ?? null;
}

/** The subset of {@link MdStreamState} carried by a single parsed frame. */
export interface ParsedMdFrame {
  book: OrderBookResponse | null;
  bars: Candle[] | null;
  lastPrice: number | null;
}

/**
 * Pure parser for a single SSE `md` frame payload. Returns the merged
 * book/bars/lastPrice (falling back to the previous values for anything the
 * frame omits), or `null` for malformed / non-JSON payloads (heartbeats,
 * comments) so callers can ignore them without mutating state.
 */
export function parseMdData(
  raw: string,
  prev: { book: OrderBookResponse | null; bars: Candle[] | null } = { book: null, bars: null },
): ParsedMdFrame | null {
  let frame: MarketDataFrame;
  try {
    frame = JSON.parse(raw) as MarketDataFrame;
  } catch {
    return null; // ignore non-JSON frames (heartbeats / comments)
  }
  if (frame == null || typeof frame !== "object") return null;
  const book = frame.book ?? prev.book;
  const bars = frame.bars?.bars ?? prev.bars;
  return { book, bars, lastPrice: derivePrice(book, bars) };
}

/**
 * SSE hook for real-time market data (order book + candles).
 *
 * Opens an EventSource to `/md/stream/{symbolId}?interval=<n>` (resolved
 * through `withApiBase`, same-origin, cookie-authed via `withCredentials`),
 * parses the named `md` event, and exposes the live book, bar series, a
 * derived `lastPrice`, and a `connected` flag.
 *
 * The endpoint auto-closes the stream after ~300s, so we reconnect with a
 * small exponential backoff on `error`/close (native EventSource retry is not
 * relied upon). The connection is torn down on unmount / symbol change.
 */
export function useMdStream(symbolId: number, interval = 1): MdStreamState {
  const [state, setState] = React.useState<MdStreamState>({
    book: null,
    bars: null,
    lastPrice: null,
    connected: false,
  });

  React.useEffect(() => {
    if (!Number.isFinite(symbolId) || symbolId <= 0) return;

    // Reset when switching symbols.
    setState({ book: null, bars: null, lastPrice: null, connected: false });

    let mounted = true;
    let es: EventSource | null = null;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let retryCount = 0;

    function handleFrame(event: MessageEvent) {
      if (!mounted) return;
      setState((prev) => {
        const parsed = parseMdData(event.data, prev);
        if (!parsed) return prev;
        return { ...parsed, connected: true };
      });
    }

    function connect() {
      const url = withApiBase(`/md/stream/${symbolId}?interval=${interval}`);
      es = new EventSource(url, { withCredentials: true });

      es.onopen = () => {
        retryCount = 0;
        if (mounted) setState((prev) => ({ ...prev, connected: true }));
      };

      es.addEventListener("md", handleFrame as EventListener);
      es.onmessage = handleFrame;

      es.onerror = () => {
        // Server ends the stream (~300s) or a transient drop: reconnect with backoff.
        es?.close();
        es = null;
        if (mounted) setState((prev) => ({ ...prev, connected: false }));
        const delay = Math.min(1000 * Math.pow(2, retryCount), MAX_RETRY_DELAY);
        retryCount += 1;
        retryTimer = setTimeout(connect, delay);
      };
    }

    connect();

    return () => {
      mounted = false;
      if (retryTimer) clearTimeout(retryTimer);
      es?.removeEventListener("md", handleFrame as EventListener);
      es?.close();
    };
  }, [symbolId, interval]);

  return state;
}
