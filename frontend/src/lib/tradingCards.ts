// Pure helpers for the trading-in-chat cards (EPIC A: FE-101 market card,
// FE-102 position card). Kept dependency-light so the disclosure-field
// selection is unit-testable without React.

export type PositionDisclosure = "full" | "pnl_pct" | "roi";

export interface PositionSource {
  symbol_id: number;
  symbol: string;
  side: "Long" | "Short";
  /** Return-on-investment percent (signed). Always shareable. */
  roi_pct: number;
  /** Average entry price in display units. Full disclosure only. */
  entry?: number;
  /** Current mark price in display units. Full disclosure only. */
  mark?: number;
  /** Absolute (unsigned) net position size. Full disclosure only. */
  size?: number;
  /** Price scaler for the symbol (display formatting). */
  price_scaler?: number;
}

// The wire/payload shape carried on a position_card message. Only the fields
// permitted by the chosen disclosure level are populated -- the composer must
// never leak entry/mark/size at a reduced disclosure level.
export interface PositionCardPayload {
  symbol_id: number;
  symbol: string;
  side: "Long" | "Short";
  disclosure: PositionDisclosure;
  roi_pct: number;
  entry?: number;
  mark?: number;
  size?: number;
  price_scaler?: number;
}

export interface MarketCardPayload {
  symbol_id: number;
  symbol: string;
}

/**
 * Project a caller-owned position into the payload permitted by `disclosure`.
 * Contract (per FE-102): symbol + side + roi% are ALWAYS included; entry, mark
 * and size are included ONLY at "full". "pnl_pct" and "roi" reveal just the
 * percentage -- never the notionals. This is the single choke point that
 * enforces the privacy selector, so it is unit-tested directly.
 */
export function buildPositionCardPayload(
  src: PositionSource,
  disclosure: PositionDisclosure,
): PositionCardPayload {
  const base: PositionCardPayload = {
    symbol_id: src.symbol_id,
    symbol: src.symbol,
    side: src.side,
    disclosure,
    roi_pct: src.roi_pct,
    price_scaler: src.price_scaler,
  };
  if (disclosure === "full") {
    base.entry = src.entry;
    base.mark = src.mark;
    base.size = src.size != null ? Math.abs(src.size) : undefined;
  }
  return base;
}

export function buildMarketCardPayload(symbolId: number, symbol: string): MarketCardPayload {
  return { symbol_id: symbolId, symbol };
}

export const DISCLOSURE_LABEL: Record<PositionDisclosure, string> = {
  full: "Full (entry, mark, size & ROI)",
  pnl_pct: "P&L % only",
  roi: "ROI % only",
};

/** Compute % change between the first and last close of a candle window. */
export function changePctFromCloses(closes: number[]): number | undefined {
  if (closes.length < 1) return undefined;
  const first = closes[0];
  const last = closes[closes.length - 1];
  if (first == null || last == null || first === 0) return undefined;
  return ((last - first) / first) * 100;
}
