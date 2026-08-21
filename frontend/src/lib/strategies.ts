/**
 * Pure, framework-free math for the USER-CREATED STRATEGIES / BASKETS surface.
 *
 * A "strategy" is an investable fund: a basket of target weights (optionally
 * following a simple rule set) that investors subscribe to at NAV. We model it
 * (LABELLED assumption, flippable) as a POOLED NAV FUND — investors own units,
 * subscribe/redeem at the current net-asset-value-per-unit; this is NOT copy /
 * replication trading.
 *
 * CONVENTIONS (locked): every monetary amount is INTEGER CENTS; every `_bps`
 * field is BASIS POINTS (1% = 100 bps, 100% = 10_000 bps). Nothing here touches
 * React, the network, or the DOM — deterministic and unit-tested in
 * `strategies.test.ts`. NAV-per-unit is carried in cents (a $12.34 unit = 1234).
 */

import { computeStats, type Bar, type SeriesStats } from "./marketStats";

/** Full basis-points denominator (100%). */
export const BPS_DENOM = 10_000;

/** Days in a year used for the management-fee day-count accrual. */
export const DAYS_PER_YEAR = 365;

/** Clamp a number into [lo, hi]; non-finite -> lo. */
export function clamp(n: number, lo: number, hi: number): number {
  if (!Number.isFinite(n)) return lo;
  return Math.min(hi, Math.max(lo, n));
}

/** Basis points -> fraction (0..1). 10_000 -> 1. Non-finite -> 0. */
export function bpsToFraction(bps: number | undefined | null): number {
  if (bps == null || !Number.isFinite(bps)) return 0;
  return bps / BPS_DENOM;
}

/** Basis points -> a human percent number (e.g. 250 -> 2.5). */
export function bpsToPct(bps: number | undefined | null): number {
  return bpsToFraction(bps) * 100;
}

/** A human percent number -> basis points, floored to an int (2.5 -> 250). */
export function pctToBps(pct: number | undefined | null, maxPct = 100): number {
  if (pct == null || !Number.isFinite(pct)) return 0;
  return Math.round(clamp(pct, 0, maxPct) * 100);
}

/** Format basis points as a percent string, e.g. 250 -> "2.5%". */
export function formatBps(bps: number | undefined | null, maxFrac = 2): string {
  const pct = bpsToPct(bps);
  return `${pct.toLocaleString(undefined, { minimumFractionDigits: 0, maximumFractionDigits: maxFrac })}%`;
}

/** Integer cents -> "$1,234.56". Non-finite -> "—". */
export function formatCents(cents: number | undefined | null): string {
  if (cents == null || !Number.isFinite(cents)) return "—";
  return `$${(cents / 100).toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}

// -- NAV / units math --------------------------------------------------

/**
 * Units minted for an investment. `amountCents` invested at `navPerUnitCents`
 * yields amount / nav units (NOT floored — pooled funds mint fractional units).
 * Guards non-positive NAV / amount by returning 0.
 */
export function unitsForInvestment(amountCents: number, navPerUnitCents: number): number {
  if (!(amountCents > 0) || !(navPerUnitCents > 0)) return 0;
  return amountCents / navPerUnitCents;
}

/**
 * Redemption proceeds (cents) for redeeming `units` at `navPerUnitCents`,
 * rounded to a whole cent. Guards non-positive inputs by returning 0.
 */
export function proceedsForUnits(units: number, navPerUnitCents: number): number {
  if (!(units > 0) || !(navPerUnitCents > 0)) return 0;
  return Math.round(units * navPerUnitCents);
}

// -- Fee accrual -------------------------------------------------------

/**
 * Management-fee accrual (cents) over `days` on `aumCents` at an ANNUAL rate of
 * `mgmtFeeBps`. accrual = aum * (bps/10_000) * (days/365), rounded to a whole
 * cent. Guards non-positive inputs by returning 0.
 */
export function mgmtFeeAccrual(aumCents: number, mgmtFeeBps: number, days: number): number {
  if (!(aumCents > 0) || !(mgmtFeeBps > 0) || !(days > 0)) return 0;
  return Math.round(aumCents * bpsToFraction(mgmtFeeBps) * (days / DAYS_PER_YEAR));
}

/**
 * Performance fee (cents) on PROFIT ABOVE the high-water mark. `currentValueCents`
 * is the position value now; `highWaterMarkCents` is the prior peak value the fee
 * was last taken at (or the invested cost basis when no HWM is enforced). Fee =
 * max(0, current - hwm) * (perfFeeBps/10_000), rounded. Only charges on gains;
 * returns 0 when at/below the mark.
 */
export function perfFee(
  currentValueCents: number,
  highWaterMarkCents: number,
  perfFeeBps: number,
): number {
  if (!(perfFeeBps > 0)) return 0;
  const profit = currentValueCents - highWaterMarkCents;
  if (!(profit > 0)) return 0;
  return Math.round(profit * bpsToFraction(perfFeeBps));
}

// -- Weight validation -------------------------------------------------

/** One basket leg: a symbol and its target weight in bps. */
export interface StrategyLeg {
  symbol_id: number;
  weight_bps: number;
}

/** Sum of leg weights in bps (ignores non-finite / non-positive). */
export function totalWeightBps(legs: StrategyLeg[]): number {
  return (legs ?? []).reduce(
    (sum, l) => sum + (Number.isFinite(l?.weight_bps) && l.weight_bps > 0 ? l.weight_bps : 0),
    0,
  );
}

export interface WeightValidation {
  totalBps: number;
  /** Signed distance from 100% (10_000 bps): +over / -under. */
  driftBps: number;
  valid: boolean;
  /** True when there is at least one leg with a positive weight. */
  hasLegs: boolean;
  /** True when any two legs reference the same symbol. */
  hasDuplicateSymbol: boolean;
}

/**
 * Validate that basket legs sum to exactly 100% (10_000 bps) with no duplicate
 * symbols and at least one leg. `toleranceBps` allows small rounding slack.
 */
export function validateWeights(legs: StrategyLeg[], toleranceBps = 0): WeightValidation {
  const total = totalWeightBps(legs);
  const seen = new Set<number>();
  let dup = false;
  let count = 0;
  for (const l of legs ?? []) {
    if (l && l.weight_bps > 0) {
      count += 1;
      if (seen.has(l.symbol_id)) dup = true;
      seen.add(l.symbol_id);
    }
  }
  const drift = total - BPS_DENOM;
  return {
    totalBps: total,
    driftBps: drift,
    hasLegs: count > 0,
    hasDuplicateSymbol: dup,
    valid: count > 0 && !dup && Math.abs(drift) <= toleranceBps,
  };
}

// -- Min-size + capacity checks ----------------------------------------

export type InvestBlockReason = "amount_non_positive" | "below_min" | "over_capacity";

export interface InvestCheck {
  ok: boolean;
  reason?: InvestBlockReason;
  /** Remaining room under the AUM cap, in cents (Infinity when uncapped). */
  capacityRemainingCents: number;
}

/**
 * Can `amountCents` be invested given a `minInvestmentCents` floor and a
 * `maxAumCents` capacity cap against the fund's current `currentAumCents`?
 * A `maxAumCents` <= 0 means UNCAPPED. Returns the first blocking reason.
 */
export function canInvest(
  amountCents: number,
  minInvestmentCents: number,
  currentAumCents: number,
  maxAumCents: number,
): InvestCheck {
  const capped = maxAumCents > 0;
  const capacityRemaining = capped
    ? Math.max(0, maxAumCents - Math.max(0, currentAumCents))
    : Number.POSITIVE_INFINITY;

  if (!(amountCents > 0)) {
    return { ok: false, reason: "amount_non_positive", capacityRemainingCents: capacityRemaining };
  }
  if (minInvestmentCents > 0 && amountCents < minInvestmentCents) {
    return { ok: false, reason: "below_min", capacityRemainingCents: capacityRemaining };
  }
  if (capped && amountCents > capacityRemaining) {
    return { ok: false, reason: "over_capacity", capacityRemainingCents: capacityRemaining };
  }
  return { ok: true, capacityRemainingCents: capacityRemaining };
}

/** Fraction (0..1) of the AUM cap already filled, for a capacity gauge. */
export function capacityFilledFraction(currentAumCents: number, maxAumCents: number): number {
  if (!(maxAumCents > 0)) return 0;
  return clamp(Math.max(0, currentAumCents) / maxAumCents, 0, 1);
}

// -- Basket backtest ---------------------------------------------------

/** A per-leg historical return series aligned to weights, for the backtest. */
export interface LegSeries {
  symbol_id: number;
  weight_bps: number;
  /** Bars for this leg, de-scaled closes, ascending by ts. */
  bars: Bar[];
}

export interface BasketBacktestResult {
  /** Equity curve of the weighted basket, base 1.0, one point per aligned step. */
  equity: number[];
  /** Timestamps aligned to the equity points. */
  ts: number[];
  /** Portfolio-level stats over the synthesized equity bar series. */
  stats: SeriesStats;
  /** Number of aligned time steps used (equity.length). */
  steps: number;
  /** True when at least two legs had overlapping timestamps. */
  aligned: boolean;
}

/**
 * Client-side basket backtest: given each leg's historical bar series and its
 * weight, synthesize the pooled fund's equity curve as a fixed-weight
 * combination of the legs' PER-STEP simple returns, aligned on the timestamps
 * ALL legs share. The portfolio return each step is the weight-normalized sum
 * of the legs' returns; equity compounds from 1.0.
 *
 * Weights are normalized by their own sum, so the backtest is meaningful even
 * if the draft's weights do not yet total exactly 100%.
 *
 * Reuses {@link computeStats} to derive returns/vol/drawdown over the resulting
 * synthetic equity series (treated as closes on a flat OHLCV bar).
 */
export function basketBacktest(legs: LegSeries[], intervalSec: number): BasketBacktestResult {
  const active = (legs ?? []).filter((l) => l && l.weight_bps > 0 && l.bars && l.bars.length > 1);
  const weightSum = active.reduce((s, l) => s + l.weight_bps, 0);

  const emptyStats = computeStats([], intervalSec);
  if (active.length === 0 || weightSum <= 0) {
    return { equity: [], ts: [], stats: emptyStats, steps: 0, aligned: false };
  }

  // Timestamps common to EVERY active leg.
  const tsSets = active.map((l) => new Set(l.bars.map((b) => b.ts)));
  let common = active[0]!.bars.map((b) => b.ts);
  for (let i = 1; i < tsSets.length; i++) {
    common = common.filter((t) => tsSets[i]!.has(t));
  }
  common.sort((a, b) => a - b);
  const aligned = active.length >= 2;
  if (common.length < 2) {
    return {
      equity: common.length ? [1] : [],
      ts: common.slice(),
      stats: emptyStats,
      steps: common.length,
      aligned,
    };
  }

  // Close lookup per leg for O(1) access at each common timestamp.
  const closeMaps = active.map((l) => {
    const m = new Map<number, number>();
    for (const b of l.bars) m.set(b.ts, b.c);
    return m;
  });
  const weights = active.map((l) => l.weight_bps / weightSum);

  const equity: number[] = [1];
  let eq = 1;
  for (let i = 1; i < common.length; i++) {
    const tPrev = common[i - 1]!;
    const tCur = common[i]!;
    let portRet = 0;
    for (let j = 0; j < active.length; j++) {
      const prev = closeMaps[j]!.get(tPrev)!;
      const cur = closeMaps[j]!.get(tCur)!;
      const legRet = prev !== 0 ? cur / prev - 1 : 0;
      portRet += weights[j]! * legRet;
    }
    eq *= 1 + portRet;
    equity.push(eq);
  }

  // Build a synthetic bar series (equity as closes) to reuse the stat pack.
  const equityBars: Bar[] = common.map((t, i) => {
    const c = equity[i]!;
    return { ts: t, o: c, h: c, l: c, c, v: 0 };
  });

  return {
    equity,
    ts: common.slice(),
    stats: computeStats(equityBars, intervalSec),
    steps: common.length,
    aligned,
  };
}
