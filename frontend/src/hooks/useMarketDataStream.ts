import * as React from "react";
import type { OrderBookResponse, Candle } from "@/api/endpoints/marketData";

/** Shape of the `data:` JSON in each `event: md` SSE frame. */
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

export interface MarketDataStreamState {
  /** Latest streamed order book, or null until the first frame arrives. */
  book: OrderBookResponse | null;
  /** Most recent candle from the stream, or null until the first frame. */
  latestCandle: Candle | null;
  /** True once at least one `md` frame has been received. */
  live: boolean;
}

/**
 * SSE hook for real-time market data (order book + candles).
 *
 * Opens an EventSource to `/md/stream/{symbolId}?interval=1` (same-origin,
 * cookie-authed via withCredentials). Listens for the named `md` event
 * (and falls back to onmessage), JSON-parses the frame, and exposes the
 * live book plus the most recent streamed candle.
 *
 * The browser EventSource auto-reconnects when the server ends the stream
 * (~5 min), so no manual reconnect logic is needed. We only guard against
 * setState-after-unmount and close the connection on unmount / symbol change.
 */
export function useMarketDataStream(symbolId: number, interval = 1) {
  const [state, setState] = React.useState<MarketDataStreamState>({
    book: null,
    latestCandle: null,
    live: false,
  });

  React.useEffect(() => {
    if (!Number.isFinite(symbolId) || symbolId <= 0) return;

    // Reset live state when switching symbols.
    setState({ book: null, latestCandle: null, live: false });

    let mounted = true;
    const url = `/md/stream/${symbolId}?interval=${interval}`;
    const es = new EventSource(url, { withCredentials: true });

    function handleFrame(event: MessageEvent) {
      if (!mounted) return;
      try {
        const frame = JSON.parse(event.data) as MarketDataFrame;
        const bars = frame.bars?.bars ?? [];
        const latestCandle = bars.length ? bars[bars.length - 1]! : null;
        setState((prev) => ({
          book: frame.book ?? prev.book,
          latestCandle: latestCandle ?? prev.latestCandle,
          live: true,
        }));
      } catch {
        // Ignore non-JSON frames (heartbeats / comments).
      }
    }

    es.addEventListener("md", handleFrame as EventListener);
    es.onmessage = handleFrame;

    return () => {
      mounted = false;
      es.removeEventListener("md", handleFrame as EventListener);
      es.close();
    };
  }, [symbolId, interval]);

  return state;
}
