// Pure, dependency-free order-entry math for the markets trade ticket. Every
// value stays in the engine's int64 "tick" space (prices/qtys are integer
// ticks scaled by the symbol's price_scaler for display). Kept framework-free
// so it is unit-testable in isolation (see orderMath.test.ts). None of these
// place orders — they only compute the numbers the ticket previews.

/** Order notional in quote units: price * qty. Returns 0 for non-positive inputs. */
export function notional(price: number, qty: number): number {
  if (!(price > 0) || !(qty > 0)) return 0;
  return price * qty;
}

/**
 * Max whole-lot qty affordable for `balance` at `price` (buying power / price),
 * floored to an integer lot. Returns 0 when price/balance are non-positive.
 */
export function maxQtyForBalance(balance: number, price: number): number {
  if (!(price > 0) || !(balance > 0)) return 0;
  return Math.floor(balance / price);
}

/**
 * Position size from a fixed risk budget and a stop distance:
 *   qty = riskAmount / |entryPrice - stopPrice|
 * floored to a whole lot. Guards divide-by-zero (equal entry/stop or a
 * non-positive risk budget) by returning 0.
 */
export function riskSizedQty(
  riskAmount: number,
  entryPrice: number,
  stopPrice: number,
): number {
  if (!(riskAmount > 0)) return 0;
  const dist = Math.abs(entryPrice - stopPrice);
  if (!(dist > 0)) return 0;
  return Math.floor(riskAmount / dist);
}

/**
 * A percentage (0-100) of buying power expressed as a whole-lot qty at `price`.
 * pct is clamped to [0, 100]. Returns 0 when it can't be sized.
 */
export function pctOfBuyingPowerQty(
  balance: number,
  price: number,
  pct: number,
): number {
  const max = maxQtyForBalance(balance, price);
  if (max <= 0) return 0;
  const p = Math.min(100, Math.max(0, pct));
  return Math.floor((max * p) / 100);
}

/**
 * A ROUGH, clearly-labeled estimated liquidation price for a fresh position,
 * used ONLY when the exchange's real maintenance-margin bps are not readable
 * client-side (the fee schedule exposes maker/taker/liq-fee bps, not
 * initial/maintenance margin). Callers MUST surface this as "(est.)" with the
 * assumed bps shown — never as an authoritative number.
 *
 * Model: with maintenance margin fraction m = maintenanceBps / 10000, a long
 * liquidates roughly where price has fallen by (1 - m) of the entry from the
 * collateral-per-unit cushion. We approximate the simple isolated-margin case
 * where the trader posts `initialBps` of notional as margin:
 *   long  liq = entry * (1 - initialFrac + maintFrac)
 *   short liq = entry * (1 + initialFrac - maintFrac)
 * Returns null when inputs are unusable.
 */
export function estLiquidationPrice(
  entryPrice: number,
  side: "buy" | "sell",
  initialBps: number,
  maintenanceBps: number,
): number | null {
  if (!(entryPrice > 0)) return null;
  if (!(initialBps > 0) || !(maintenanceBps >= 0)) return null;
  const initialFrac = initialBps / 10000;
  const maintFrac = maintenanceBps / 10000;
  const px =
    side === "buy"
      ? entryPrice * (1 - initialFrac + maintFrac)
      : entryPrice * (1 + initialFrac - maintFrac);
  if (!Number.isFinite(px) || px <= 0) return null;
  return px;
}
