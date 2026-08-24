// Pure, dependency-free MAKER/TAKER FEE-TIER (VIP schedule) engine computed
// CLIENT-SIDE from a normalized executed-fill list. NO framework, NO I/O, NO
// DOM — every monetary value is an INTEGER in USD cents and every rate is an
// integer basis-point (bps), so the arithmetic is exact and the module is
// trivially unit-testable (see feeTiers.test.ts).
//
// A trader's fee tier is a function of their 30-day rolling trading VOLUME
// (sum of executed-fill NOTIONAL = price*qty). Higher volume → lower maker &
// taker rates. The FEE_TIERS table below is CANONICAL and shared with the
// Android client — do NOT change the thresholds/rates without changing both.

// ── canonical schedule ───────────────────────────────────────────────
// thresholds are 30-day rolling volume in USD CENTS; fees are in BPS (1bp =
// 0.01% = 0.0001). Ordered ascending by threshold (Standard first).

export interface FeeTier {
  /** Stable id shared with the backend authoritative read. */
  id: string;
  /** Human label. */
  name: string;
  /** Minimum 30-day volume (USD cents, inclusive) to qualify for this tier. */
  minVolumeCents: number;
  /** Maker fee, basis points. */
  makerBps: number;
  /** Taker fee, basis points. */
  takerBps: number;
}

/** Canonical maker/taker VIP schedule (ascending by threshold). */
export const FEE_TIERS: readonly FeeTier[] = [
  { id: "standard", name: "Standard", minVolumeCents: 0, makerBps: 10, takerBps: 15 },
  { id: "bronze", name: "Bronze", minVolumeCents: 50_000_00, makerBps: 9, takerBps: 14 },
  { id: "silver", name: "Silver", minVolumeCents: 250_000_00, makerBps: 8, takerBps: 12 },
  { id: "gold", name: "Gold", minVolumeCents: 1_000_000_00, makerBps: 6, takerBps: 10 },
  { id: "platinum", name: "Platinum", minVolumeCents: 5_000_000_00, makerBps: 4, takerBps: 8 },
  { id: "diamond", name: "Diamond (VIP)", minVolumeCents: 25_000_000_00, makerBps: 2, takerBps: 6 },
] as const;

// ── input shape ──────────────────────────────────────────────────────

/** One normalized executed fill. Integer cents; `ts` is unix sec OR ms. */
export interface VolumeFill {
  /** unix timestamp — seconds OR milliseconds (engine-native). */
  ts: number;
  /** Per-unit executed price, integer minor units (cents). */
  priceCents: number;
  /** Executed quantity (treated as a positive magnitude). */
  qty: number;
}

// ── helpers ──────────────────────────────────────────────────────────

const DAY_MS = 24 * 60 * 60 * 1000;
// A ts below this is assumed to be seconds; at/above, milliseconds. (~2001 in
// ms / ~33k AD in s — the same heuristic the tax report uses.)
const MS_THRESHOLD = 1e12;

function toMs(ts: number): number {
  return ts < MS_THRESHOLD ? ts * 1000 : ts;
}

// ── volume ───────────────────────────────────────────────────────────

/**
 * Sum of executed-fill NOTIONAL (priceCents * qty, floored to whole cents)
 * within the trailing `windowDays` window ending at `nowMs`. Fills outside the
 * window, or with non-positive price/qty, are ignored. Never negative.
 */
export function volume30dCents(
  fills: readonly VolumeFill[],
  nowMs: number,
  windowDays = 30,
): number {
  if (!Array.isArray(fills) || fills.length === 0) return 0;
  const window = Math.max(0, windowDays) * DAY_MS;
  const cutoff = nowMs - window;
  let total = 0;
  for (const f of fills) {
    if (!f) continue;
    const price = Number(f.priceCents);
    const qty = Number(f.qty);
    if (!Number.isFinite(price) || !Number.isFinite(qty)) continue;
    if (price <= 0 || qty <= 0) continue;
    const ms = toMs(Number(f.ts));
    if (!Number.isFinite(ms)) continue;
    if (ms < cutoff || ms > nowMs) continue;
    // notional in cents; floor to keep integer cents.
    total += Math.floor(price * qty);
  }
  return total < 0 ? 0 : total;
}

// ── tier lookup ──────────────────────────────────────────────────────

/**
 * The highest tier whose `minVolumeCents` is <= `volumeCents`. Negative /
 * empty volume → Standard (the first tier). Always returns a tier.
 */
export function tierForVolume(volumeCents: number): FeeTier {
  const v = Number.isFinite(volumeCents) && volumeCents > 0 ? volumeCents : 0;
  let match: FeeTier = FEE_TIERS[0] as FeeTier;
  for (const t of FEE_TIERS) {
    if (v >= t.minVolumeCents) match = t;
    else break;
  }
  return match;
}

/** Look up a tier by its stable id (e.g. from the authoritative backend read). */
export function tierById(id: string): FeeTier | undefined {
  return FEE_TIERS.find((t) => t.id === id);
}

/** The next-higher tier above `tier`, or `null` when already at the top. */
export function nextTier(tier: FeeTier): FeeTier | null {
  const i = FEE_TIERS.findIndex((t) => t.id === tier.id);
  if (i < 0 || i >= FEE_TIERS.length - 1) return null;
  return FEE_TIERS[i + 1] as FeeTier;
}

/**
 * Progress (0..1) toward the NEXT tier's threshold, measured from the CURRENT
 * tier's threshold. Returns 1.0 when already at the top tier. Clamped to [0,1].
 */
export function progressToNextFraction(volumeCents: number): number {
  const v = Number.isFinite(volumeCents) && volumeCents > 0 ? volumeCents : 0;
  const current = tierForVolume(v);
  const next = nextTier(current);
  if (!next) return 1;
  const span = next.minVolumeCents - current.minVolumeCents;
  if (span <= 0) return 1;
  const gained = v - current.minVolumeCents;
  const frac = gained / span;
  if (frac <= 0) return 0;
  if (frac >= 1) return 1;
  return frac;
}

/** USD cents of additional volume needed to reach the next tier (0 at top). */
export function volumeToNextTierCents(volumeCents: number): number {
  const v = Number.isFinite(volumeCents) && volumeCents > 0 ? volumeCents : 0;
  const next = nextTier(tierForVolume(v));
  if (!next) return 0;
  const remaining = next.minVolumeCents - v;
  return remaining > 0 ? remaining : 0;
}

// ── fee math ─────────────────────────────────────────────────────────

/**
 * Fee (integer cents, rounded half-up) charged on `notionalCents` at `bps`
 * basis points. bps of 15 = 0.15%. Guards non-positive inputs → 0.
 */
export function makerTakerFeeCents(notionalCents: number, bps: number): number {
  const n = Number(notionalCents);
  const b = Number(bps);
  if (!Number.isFinite(n) || !Number.isFinite(b) || n <= 0 || b <= 0) return 0;
  // fee = notional * bps / 10_000. Round half-up for a deterministic result.
  return Math.round((n * b) / 10_000);
}


// ── order-time fee estimate (taker vs maker by order type) ───────────────

/** Order-entry type union understood by {@link isTakerOrderType}. */
export type FeeOrderType =
  | "limit"
  | "market"
  | "stop"
  | "stop_limit"
  | "take_profit"
  | (string & {});

/**
 * Whether an order of `type` is expected to pay the TAKER fee. Market and
 * stop / take-profit orders trigger into a market fill and CROSS the book →
 * taker. A resting `limit` ADDS liquidity → maker; at entry time a plain limit
 * is treated as a maker (the typical/optimistic case), and `postOnly` forces
 * maker. `stop_limit` triggers into a resting LIMIT, so it is a maker too.
 * Unknown types default to taker (the conservative, higher estimate) unless
 * `postOnly` is set.
 */
export function isTakerOrderType(type: FeeOrderType, postOnly = false): boolean {
  if (postOnly) return false;
  switch (type) {
    case "limit":
      return false; // resting maker
    case "stop_limit":
      return false; // triggers into a resting limit -> maker
    case "market":
    case "stop":
    case "take_profit":
      return true; // crosses the book -> taker
    default:
      return true; // unknown -> conservative taker estimate
  }
}

/**
 * Estimated order fee (integer USD cents, rounded half-up) for `notionalCents`
 * at the caller's `makerBps` / `takerBps`, choosing the applicable rate from
 * the order `type` (see {@link isTakerOrderType}). A `postOnly` limit is forced
 * to the maker rate. Guards non-positive notional -> 0.
 */
export function orderFeeEstimateCents(
  notionalCents: number,
  makerBps: number,
  takerBps: number,
  type: FeeOrderType,
  postOnly = false,
): number {
  const taker = isTakerOrderType(type, postOnly);
  const bps = taker ? takerBps : makerBps;
  return makerTakerFeeCents(notionalCents, bps);
}
