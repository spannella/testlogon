// Pure, framework-free ORDER-ENTRY DEPTH math for the markets trade ticket:
// risk-based position sizing, risk/reward, a rough (clearly-labelled) liquidation
// preview, breakeven, and the client-side TWAP / Iceberg algo schedulers.
//
// Everything stays in the engine's int64 "tick" space (prices/qtys/money are
// integer ticks; the UI scales for display via the markets format helpers). None
// of these place orders — they only compute numbers/schedules the ticket then
// drives through the SAME submit path. Kept pure so it is unit-testable in
// isolation (see orderCalc.test.ts). Every function guards zero / negative /
// degenerate inputs.

export type Side = "buy" | "sell";

/**
 * Risk-based position size:
 *   qty = (equity * riskPct/100) / |entry - stop|
 * floored to a whole lot. `equityCents` is account equity in ticks, `riskPct` is
 * the percent of equity to risk (clamped to [0, 100]). Guards divide-by-zero
 * (equal entry/stop) and non-positive inputs by returning 0.
 */
export function positionSizeQty({
  equityCents,
  riskPct,
  entryPrice,
  stopPrice,
}: {
  equityCents: number;
  riskPct: number;
  entryPrice: number;
  stopPrice: number;
}): number {
  if (!(equityCents > 0)) return 0;
  const pct = Math.min(100, Math.max(0, riskPct));
  if (!(pct > 0)) return 0;
  const dist = Math.abs(entryPrice - stopPrice);
  if (!(dist > 0)) return 0;
  const riskBudget = (equityCents * pct) / 100;
  const qty = Math.floor(riskBudget / dist);
  return qty > 0 ? qty : 0;
}

/**
 * Risk / reward for a bracket: risk is the loss to the stop, reward the gain to
 * the target, both in ticks over `qty`; `rr` is reward/risk. For a BUY the stop
 * sits below entry and the target above; for a SELL it is inverted. Returns zeros
 * (and rr=0) for degenerate inputs.
 */
export function riskReward({
  side,
  entry,
  stop,
  target,
  qty,
}: {
  side: Side;
  entry: number;
  stop: number;
  target: number;
  qty: number;
}): { riskCents: number; rewardCents: number; rr: number } {
  const zero = { riskCents: 0, rewardCents: 0, rr: 0 };
  if (!(entry > 0) || !(qty > 0)) return zero;
  const riskPerUnit = side === "buy" ? entry - stop : stop - entry;
  const rewardPerUnit = side === "buy" ? target - entry : entry - target;
  const riskCents = stop > 0 && riskPerUnit > 0 ? Math.round(riskPerUnit * qty) : 0;
  const rewardCents = target > 0 && rewardPerUnit > 0 ? Math.round(rewardPerUnit * qty) : 0;
  const rr = riskCents > 0 && rewardCents > 0 ? rewardCents / riskCents : 0;
  return { riskCents, rewardCents, rr };
}

/**
 * A ROUGH, clearly-labelled estimated liquidation price + margin required for a
 * fresh isolated position at `leverage`. margin = notional / leverage; the
 * liquidation offset is where equity erodes to the maintenance fraction:
 *   long  liq = entry * (1 - 1/lev + m)
 *   short liq = entry * (1 + 1/lev - m)   where m = maintenanceMarginBps/10000.
 * Callers MUST surface liqPrice as "(est.)" — it is not authoritative. Returns
 * null liqPrice / 0 margin for unusable inputs.
 */
export function liquidationPreview({
  side,
  entry,
  qty,
  leverage,
  maintenanceMarginBps,
}: {
  side: Side;
  entry: number;
  qty: number;
  leverage: number;
  maintenanceMarginBps: number;
}): { liqPrice: number | null; marginRequiredCents: number } {
  if (!(entry > 0) || !(qty > 0) || !(leverage > 0)) {
    return { liqPrice: null, marginRequiredCents: 0 };
  }
  const notional = entry * qty;
  const marginRequiredCents = Math.ceil(notional / leverage);
  const maintFrac = maintenanceMarginBps > 0 ? maintenanceMarginBps / 10000 : 0;
  const invLev = 1 / leverage;
  const px =
    side === "buy"
      ? entry * (1 - invLev + maintFrac)
      : entry * (1 + invLev - maintFrac);
  const liqPrice = Number.isFinite(px) && px > 0 ? px : null;
  return { liqPrice, marginRequiredCents };
}

/**
 * Breakeven price after round-trip fees at `feeBps` per side (entry + exit).
 * A BUY must sell above cost, a SELL must buy back below cost:
 *   buy  be = entry * (1 + 2*feeFrac)
 *   sell be = entry * (1 - 2*feeFrac)
 * Returns 0 for unusable inputs. Fees below 0 are treated as 0.
 */
export function breakevenPrice({
  side,
  entry,
  feeBps,
}: {
  side: Side;
  entry: number;
  feeBps: number;
}): number {
  if (!(entry > 0)) return 0;
  const feeFrac = feeBps > 0 ? feeBps / 10000 : 0;
  const roundTrip = 2 * feeFrac;
  const px = side === "buy" ? entry * (1 + roundTrip) : entry * (1 - roundTrip);
  if (!Number.isFinite(px) || px <= 0) return 0;
  return Math.round(px);
}

/** One scheduled TWAP child slice. */
export interface TwapSlice {
  seq: number;
  qty: number;
  atMs: number;
}

/**
 * Even-split TWAP schedule: `totalQty` across `slices` child orders spread over
 * `durationMs` starting at `startMs`. Base qty is floor(total/slices); any
 * remainder is added to the LAST slice, so quantities always sum to the total.
 * Slice `seq` s (0-based) fires at startMs + s * (durationMs / slices) — one at
 * the start and the rest evenly through the window. Guards: <1 slice becomes 1;
 * non-positive total/duration return []; slices is capped at totalQty so no slice
 * ever gets 0 qty (min-1-qty-per-slice).
 */
export function twapSchedule({
  totalQty,
  slices,
  durationMs,
  startMs,
}: {
  totalQty: number;
  slices: number;
  durationMs: number;
  startMs: number;
}): TwapSlice[] {
  const total = Math.floor(totalQty);
  if (!(total > 0)) return [];
  if (!(durationMs > 0)) return [];
  let n = Math.max(1, Math.floor(slices));
  // Never schedule a zero-qty slice — cap slice count at the total qty.
  if (n > total) n = total;
  const base = Math.floor(total / n);
  const remainder = total - base * n;
  const step = durationMs / n;
  const out: TwapSlice[] = [];
  for (let s = 0; s < n; s++) {
    const qty = s === n - 1 ? base + remainder : base;
    out.push({ seq: s, qty, atMs: Math.round(startMs + s * step) });
  }
  return out;
}

/**
 * Iceberg clip breakdown: how many `visibleQty`-sized clips cover `totalQty`, and
 * the (possibly smaller) size of the final clip. Guards: non-positive total or
 * visible returns a single zero-clip descriptor. When visible >= total it is one
 * clip of the whole size.
 */
export function icebergClips({
  totalQty,
  visibleQty,
}: {
  totalQty: number;
  visibleQty: number;
}): { clips: number; clipQty: number; lastClipQty: number } {
  const total = Math.floor(totalQty);
  const visible = Math.floor(visibleQty);
  if (!(total > 0) || !(visible > 0)) {
    return { clips: 0, clipQty: 0, lastClipQty: 0 };
  }
  if (visible >= total) {
    return { clips: 1, clipQty: total, lastClipQty: total };
  }
  const clips = Math.ceil(total / visible);
  const rem = total - visible * (clips - 1);
  const lastClipQty = rem > 0 ? rem : visible;
  return { clips, clipQty: visible, lastClipQty };
}
