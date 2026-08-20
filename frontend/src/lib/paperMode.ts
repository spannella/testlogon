// Shared PAPER-MODE flag for the real trade ticket. When ON, order submits on
// the full ticket are routed to the isolated client-side paper engine
// (paperEngine.ts) instead of the live /me/orders endpoints, and share the SAME
// `paper.account.v1` account the dedicated Paper Trading page uses.
//
// Framework-free + event-based, mirroring the price-alerts store pattern: writes
// persist to localStorage under `paper.mode.v1` and dispatch a same-tab event so
// every mounted `usePaperMode()` re-reads. Cross-tab sync rides the native
// `storage` event.

import { useCallback, useEffect, useState } from "react";
import type { PaperOrderType, PaperSide } from "./paperEngine";

export const PAPER_MODE_KEY = "paper.mode.v1";

/** Fired (same-tab) whenever the paper-mode flag flips. */
export const PAPER_MODE_EVENT = "tl:paperModeChanged";

/** Read the persisted paper-mode flag (defaults to OFF). */
export function loadPaperMode(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return window.localStorage.getItem(PAPER_MODE_KEY) === "1";
  } catch {
    return false;
  }
}

/** Persist the flag and notify same-tab listeners. */
export function savePaperMode(enabled: boolean): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(PAPER_MODE_KEY, enabled ? "1" : "0");
  } catch {
    /* quota / private-mode — degrade to no-op */
  }
  try {
    window.dispatchEvent(new Event(PAPER_MODE_EVENT));
  } catch {
    /* SSR — no-op */
  }
}

/**
 * React hook exposing the shared paper-mode flag. `setEnabled` persists + fans
 * the change out to every other `usePaperMode()` consumer in the tab.
 */
export function usePaperMode(): { enabled: boolean; setEnabled: (v: boolean) => void } {
  const [enabled, setEnabledState] = useState<boolean>(() => loadPaperMode());

  useEffect(() => {
    const reload = () => setEnabledState(loadPaperMode());
    window.addEventListener("storage", reload);
    window.addEventListener(PAPER_MODE_EVENT, reload);
    return () => {
      window.removeEventListener("storage", reload);
      window.removeEventListener(PAPER_MODE_EVENT, reload);
    };
  }, []);

  const setEnabled = useCallback((v: boolean) => {
    savePaperMode(v);
    setEnabledState(v);
  }, []);

  return { enabled, setEnabled };
}

// ── Pure routing helpers (unit-tested in paperMode.test.ts) ──────────

/** Order types the paper engine supports; the ticket restricts to these in paper mode. */
export const PAPER_ORDER_TYPES: readonly PaperOrderType[] = ["market", "limit"];

/** True when `type` can be simulated by the paper engine (market & limit only). */
export function isPaperOrderType(type: string): type is PaperOrderType {
  return type === "market" || type === "limit";
}

/**
 * Pick the marketPrice to fill a paper order against: a BUY lifts the ask, a SELL
 * hits the bid; fall back to last trade, then a bid/ask mid, then the entered
 * reference price. Ignores non-positive quotes. Returns undefined when nothing
 * usable is available (the engine then cancels a market order / rests a limit).
 */
export function selectMarketPrice(
  side: PaperSide,
  quotes: { bestBid?: number; bestAsk?: number; lastPrice?: number; refPrice?: number },
): number | undefined {
  const pos = (n?: number): number | undefined =>
    n != null && Number.isFinite(n) && n > 0 ? n : undefined;
  const bid = pos(quotes.bestBid);
  const ask = pos(quotes.bestAsk);
  const primary = side === "buy" ? ask : bid;
  // Mid is a fallback for the rare case the NEAR-side quote is missing but the
  // far side is present (e.g. one-sided book): buy with no ask but a bid, or
  // sell with no bid but an ask.
  const mid = bid != null && ask != null ? Math.round((bid + ask) / 2) : (bid ?? ask);
  return primary ?? pos(quotes.lastPrice) ?? mid ?? pos(quotes.refPrice);
}
