/**
 * Pure, framework-free PORTFOLIO ANALYTICS — allocation, concentration,
 * exposure & risk math over a normalized cross-venue position list.
 *
 * Nothing here touches React, the network, or the DOM. All monetary inputs are
 * INTEGER CENTS; all weight outputs are BASIS POINTS (100% = 10_000). Everything
 * is deterministic and unit-tested in `portfolioAnalytics.test.ts`.
 *
 * Every function guards the degenerate edges the analytics page actually hits at
 * runtime: an empty book, a single position, and zero equity.
 */

/** A LONG position adds to gross+net; a SHORT adds to gross but subtracts net. */
export type PositionSide = "long" | "short";

/** How allocation buckets a normalized position. */
export type AllocationBy = "asset" | "class" | "product";

/**
 * One normalized holding, valued in USD cents (indicative). `valueCents` is the
 * ABSOLUTE market value of the leg (always >= 0); `side` carries direction.
 */
export interface NormalizedPosition {
  /** Stable de-dupe key (venue+asset). */
  key: string;
  /** Human label shown in the UI. */
  label: string;
  /** Product/venue bucket, e.g. "Custody", "Spot", "Margin", "Tokens". */
  group: string;
  /** Asset-class bucket, e.g. "Crypto", "Stablecoin", "Fund", "Token". */
  assetClass: string;
  /** Absolute USD value of the leg, in integer cents (>= 0). */
  valueCents: number;
  /** Direction; defaults to "long" when omitted by the caller. */
  side?: PositionSide;
  /** Optional underlying quantity (informational; not used by the math). */
  qty?: number;
}

/** One allocation slice: a bucket, its summed value, and its weight in bps. */
export interface AllocationSlice {
  label: string;
  valueCents: number;
  /** Share of total ABSOLUTE value, in basis points (sums to ~10_000). */
  weightBps: number;
}

/** Concentration summary: Herfindahl index + the heaviest slices. */
export interface Concentration {
  /**
   * Herfindahl-Hirschman index on fractional weights, scaled to 0..10_000.
   * 10_000 = a single position; -> 0 as holdings become many & even.
   */
  hhi: number;
  /** The top-N slices by weight (descending). */
  top: { label: string; weightBps: number }[];
}

/** Directional exposure across the book. */
export interface Exposure {
  /** Sum of ALL leg values (long + short), in cents. */
  grossCents: number;
  /** Long minus short, in cents (signed). */
  netCents: number;
  longCents: number;
  shortCents: number;
  /** gross / equity, in basis points (10_000 = 1.0x). 0 when equity <= 0. */
  leverageBps: number;
}

const BPS = 10_000;

function isNum(n: unknown): n is number {
  return typeof n === "number" && Number.isFinite(n);
}

/** Absolute, finite cents value of a leg (defensive; clamps junk to 0). */
function legValue(p: NormalizedPosition): number {
  return isNum(p.valueCents) ? Math.abs(p.valueCents) : 0;
}

/**
 * Allocation by asset / class / product. Buckets the book, sums absolute value
 * per bucket, and assigns each a weight in bps of the total absolute value.
 * Empty in -> empty out. Sorted by value descending.
 */
export function allocation(
  positions: NormalizedPosition[],
  by: AllocationBy,
): AllocationSlice[] {
  const keyOf = (p: NormalizedPosition): string =>
    by === "asset" ? p.label : by === "class" ? p.assetClass : p.group;

  const sums = new Map<string, number>();
  let total = 0;
  for (const p of positions) {
    const v = legValue(p);
    if (v <= 0) continue;
    const k = keyOf(p) || "—";
    sums.set(k, (sums.get(k) ?? 0) + v);
    total += v;
  }

  const slices: AllocationSlice[] = [];
  for (const [label, valueCents] of sums) {
    slices.push({
      label,
      valueCents,
      weightBps: total > 0 ? Math.round((valueCents / total) * BPS) : 0,
    });
  }
  slices.sort((a, b) => b.valueCents - a.valueCents);
  return slices;
}

/**
 * Concentration from a set of weights (bps). HHI = sum(fraction^2) scaled to
 * 0..10_000; `top` is the heaviest `topN` slices. Empty in -> hhi 0, top [].
 */
export function concentration(
  weights: { label: string; weightBps: number }[],
  topN = 5,
): Concentration {
  if (weights.length === 0) return { hhi: 0, top: [] };
  let hhi = 0;
  for (const w of weights) {
    const frac = (isNum(w.weightBps) ? w.weightBps : 0) / BPS;
    hhi += frac * frac;
  }
  const top = [...weights]
    .sort((a, b) => b.weightBps - a.weightBps)
    .slice(0, Math.max(0, topN))
    .map((w) => ({ label: w.label, weightBps: w.weightBps }));
  return { hhi: Math.round(hhi * BPS), top };
}

/**
 * Directional exposure. Gross = sum |value|; long/short split by side; net =
 * long - short; leverage = gross / equity in bps. `equityCents` is the account
 * equity to lever against (typically total value); leverage is 0 when it's <= 0.
 */
export function exposure(
  positions: NormalizedPosition[],
  equityCents?: number,
): Exposure {
  let longCents = 0;
  let shortCents = 0;
  for (const p of positions) {
    const v = legValue(p);
    if (v <= 0) continue;
    if (p.side === "short") shortCents += v;
    else longCents += v;
  }
  const grossCents = longCents + shortCents;
  const netCents = longCents - shortCents;
  const equity = isNum(equityCents) && equityCents > 0 ? equityCents : grossCents;
  const leverageBps = equity > 0 ? Math.round((grossCents / equity) * BPS) : 0;
  return { grossCents, netCents, longCents, shortCents, leverageBps };
}

/**
 * Portfolio volatility (bps) from per-asset vols (bps) + a correlation matrix,
 * combined via the standard quadratic form sqrt(w' * Sigma * w) where
 * Sigma_ij = corr_ij * vol_i * vol_j. `weights` are fractional or bps — they are
 * NORMALIZED internally so only their relative sizes matter. Missing correlation
 * entries default to 0 (diagonal to 1). Returns 0 for an empty / all-zero book.
 */
export function portfolioVolatilityBps(
  weights: number[],
  perAssetVolBps: number[],
  correlationMatrix: number[][],
): number {
  const n = Math.min(weights.length, perAssetVolBps.length);
  if (n === 0) return 0;

  // Normalize weights to sum 1 (by absolute magnitude; tolerate junk).
  let wSum = 0;
  const w: number[] = [];
  for (let i = 0; i < n; i++) {
    const x = isNum(weights[i]) ? Math.abs(weights[i]!) : 0;
    w.push(x);
    wSum += x;
  }
  if (wSum <= 0) return 0;
  for (let i = 0; i < n; i++) w[i]! /= wSum;

  const vol = (i: number): number =>
    isNum(perAssetVolBps[i]) && perAssetVolBps[i]! > 0 ? perAssetVolBps[i]! : 0;

  const corr = (i: number, j: number): number => {
    if (i === j) return 1;
    const row = correlationMatrix[i];
    const c = row ? row[j] : undefined;
    if (!isNum(c)) return 0;
    return Math.max(-1, Math.min(1, c));
  };

  let variance = 0;
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      variance += w[i]! * w[j]! * vol(i) * vol(j) * corr(i, j);
    }
  }
  if (variance <= 0) return 0;
  return Math.round(Math.sqrt(variance));
}

/** Standard-normal z for a common confidence (fallback 1.645 = 95%). */
export function zForConfidence(confidence: number): number {
  if (confidence >= 0.99) return 2.326;
  if (confidence >= 0.975) return 1.96;
  if (confidence >= 0.95) return 1.645;
  if (confidence >= 0.9) return 1.282;
  return 1.645;
}

/**
 * Parametric (variance-covariance) Value-at-Risk in cents:
 * VaR = portfolioValue * (volBps/10_000) * z. Guards non-positive inputs to 0.
 */
export function parametricVarCents(
  portfolioValueCents: number,
  volBps: number,
  z: number,
): number {
  if (!isNum(portfolioValueCents) || portfolioValueCents <= 0) return 0;
  if (!isNum(volBps) || volBps <= 0) return 0;
  if (!isNum(z) || z <= 0) return 0;
  return Math.round(portfolioValueCents * (volBps / BPS) * z);
}

/**
 * Historical VaR in cents: the loss at the (1 - confidence) percentile of a
 * per-period portfolio-return distribution, applied to the portfolio value.
 * `portfolioReturns` are fractional per-period returns (e.g. -0.03 = -3%).
 * Returned as a POSITIVE cents loss (0 when there is no loss at that quantile or
 * the series is empty). Uses linear interpolation between order statistics.
 */
export function historicalVarCents(
  portfolioValueCents: number,
  portfolioReturns: number[],
  confidence: number,
): number {
  if (!isNum(portfolioValueCents) || portfolioValueCents <= 0) return 0;
  const rs = portfolioReturns.filter((r) => isNum(r));
  if (rs.length === 0) return 0;

  const sorted = [...rs].sort((a, b) => a - b);
  const conf = isNum(confidence) ? Math.min(0.9999, Math.max(0.5, confidence)) : 0.95;
  const alpha = 1 - conf; // lower-tail probability

  // Linear-interpolated quantile at probability alpha.
  const idx = alpha * (sorted.length - 1);
  const lo = Math.floor(idx);
  const hi = Math.ceil(idx);
  const frac = idx - lo;
  const q = sorted[lo]! + (sorted[hi]! - sorted[lo]!) * frac;

  // A loss is a negative return; VaR is the magnitude of that loss in cents.
  if (q >= 0) return 0;
  return Math.round(portfolioValueCents * -q);
}

/**
 * Diversification score 0..100. Higher = better diversified: rewards LOW average
 * pairwise correlation and EVEN weights (low concentration). Combines two 0..1
 * sub-scores equally:
 *   - corrScore  = (1 - avgAbsPairwiseCorr), clamped
 *   - evenScore  = 1 - (HHI - 1/n) / (1 - 1/n)   [1 = perfectly even, 0 = all in one]
 * Single position -> 0 (undiversifiable). Empty -> 0.
 */
export function diversificationScore(
  weights: { label: string; weightBps: number }[],
  correlationMatrix: number[][],
): number {
  const n = weights.length;
  if (n <= 1) return 0;

  // Even-ness from HHI on fractional weights.
  let hhi = 0;
  let wSum = 0;
  const fr: number[] = [];
  for (const w of weights) {
    const x = (isNum(w.weightBps) ? Math.max(0, w.weightBps) : 0) / BPS;
    fr.push(x);
    wSum += x;
  }
  if (wSum > 0) for (let i = 0; i < n; i++) fr[i]! /= wSum;
  for (const f of fr) hhi += f * f;
  const minHhi = 1 / n;
  const evenScore = 1 - Math.max(0, (hhi - minHhi) / (1 - minHhi));

  // Average absolute pairwise correlation over the upper triangle.
  let cSum = 0;
  let cCount = 0;
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      const row = correlationMatrix[i];
      const c = row ? row[j] : undefined;
      cSum += isNum(c) ? Math.abs(Math.max(-1, Math.min(1, c))) : 0;
      cCount++;
    }
  }
  const avgCorr = cCount > 0 ? cSum / cCount : 0;
  const corrScore = Math.max(0, Math.min(1, 1 - avgCorr));

  const score = 0.5 * corrScore + 0.5 * evenScore;
  return Math.round(Math.max(0, Math.min(1, score)) * 100);
}
