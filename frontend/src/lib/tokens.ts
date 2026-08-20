// Pure, dependency-free math for the CREATOR REVENUE-SHARE TOKEN surface.
// Framework-free so it is unit-testable in isolation (see tokens.test.ts).
// CONVENTIONS (locked): all monetary amounts are INTEGER CENTS; every `_bps`
// value is BASIS POINTS (1% = 100 bps, 100% = 10_000 bps). None of these
// functions perform I/O — they only compute the numbers the screens preview.

/** One cent-denominated dollar figure: the flat book-upkeep threshold ($100). */
export const UPKEEP_THRESHOLD_CENTS = 100_00;

/** The flat token-creation ("mint") fee: $100. */
export const CREATION_FEE_CENTS = 100_00;

/** Full basis-points denominator (100%). */
export const BPS_DENOM = 10_000;

/** Clamp a number into [lo, hi]. */
export function clamp(n: number, lo: number, hi: number): number {
  if (!Number.isFinite(n)) return lo;
  return Math.min(hi, Math.max(lo, n));
}

/** Basis points -> fraction (0..1). 10_000 bps -> 1. Non-finite -> 0. */
export function bpsToFraction(bps: number | undefined | null): number {
  if (bps == null || !Number.isFinite(bps)) return 0;
  return bps / BPS_DENOM;
}

/** Basis points -> a human percent number (e.g. 250 -> 2.5). */
export function bpsToPct(bps: number | undefined | null): number {
  return bpsToFraction(bps) * 100;
}

/** A human percent number -> basis points, floored to an int (2.5 -> 250). */
export function pctToBps(pct: number | undefined | null): number {
  if (pct == null || !Number.isFinite(pct)) return 0;
  return Math.round(clamp(pct, 0, 100) * 100);
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

/**
 * Token quantity implied by a basis-points slice of total supply.
 *   qty = totalSupply * bps / 10_000  (floored to a whole token)
 * Guards non-positive supply / bps by returning 0.
 */
export function bpsToQty(totalSupply: number, bps: number): number {
  if (!(totalSupply > 0) || !(bps > 0)) return 0;
  return Math.floor((totalSupply * clamp(bps, 0, BPS_DENOM)) / BPS_DENOM);
}

/**
 * Basis-points slice of total supply implied by a raw token quantity.
 *   bps = qty / totalSupply * 10_000  (rounded to a whole bp)
 * Guards non-positive supply by returning 0; clamps to [0, 10_000].
 */
export function qtyToBps(qty: number, totalSupply: number): number {
  if (!(totalSupply > 0) || !(qty > 0)) return 0;
  return clamp(Math.round((qty / totalSupply) * BPS_DENOM), 0, BPS_DENOM);
}

/**
 * A holder's PRO-RATA share (in cents) of a total upkeep bill, by holding.
 *   share = amountDueCents * (myQty / totalSupply)   (rounded to a whole cent)
 * Guards non-positive supply / due by returning 0; a holder with 0 qty owes 0.
 */
export function proRataShareCents(
  amountDueCents: number,
  myQty: number,
  totalSupply: number,
): number {
  if (!(amountDueCents > 0) || !(myQty > 0) || !(totalSupply > 0)) return 0;
  const frac = clamp(myQty / totalSupply, 0, 1);
  return Math.round(amountDueCents * frac);
}

/**
 * SHORTFALL top-up upkeep model (LABELLED assumption, flippable later):
 *   amount_due = max(0, threshold - feesThisMonth)
 * $0 once the book's monthly trading fees meet/exceed the threshold.
 */
export function upkeepAmountDueCents(
  feesThisMonthCents: number,
  thresholdCents: number = UPKEEP_THRESHOLD_CENTS,
): number {
  const fees = Number.isFinite(feesThisMonthCents) ? feesThisMonthCents : 0;
  const thr = Number.isFinite(thresholdCents) ? thresholdCents : 0;
  return Math.max(0, thr - Math.max(0, fees));
}

/**
 * Fraction (0..1) of the upkeep threshold already covered by trading fees, for
 * a progress gauge. 1 = fully covered (nothing due).
 */
export function upkeepCoverageFraction(
  feesThisMonthCents: number,
  thresholdCents: number = UPKEEP_THRESHOLD_CENTS,
): number {
  if (!(thresholdCents > 0)) return 1;
  const fees = Math.max(0, Number.isFinite(feesThisMonthCents) ? feesThisMonthCents : 0);
  return clamp(fees / thresholdCents, 0, 1);
}

/** One sealed bid in the single-clearing-price IPO auction. */
export interface ClearingBid {
  qty: number;
  limit_price: number;
}

/** The computed outcome of clearing a sealed-bid auction. */
export interface ClearingSummary {
  /** The single price at which all fills execute; null when nothing clears. */
  clearingPrice: number | null;
  /** Total quantity filled at the clearing price (<= offeredQty). */
  filledQty: number;
  /** Gross proceeds in the price*qty unit (clearingPrice * filledQty). */
  proceeds: number;
  /** True when demand at/above the clearing price met the reserve + offered. */
  cleared: boolean;
}

/**
 * Single-clearing-price (uniform-price) auction summary. Bids are sealed with a
 * per-bid limit price; we find the HIGHEST price P such that the cumulative
 * demand from bids willing to pay >= P is at least as large as it can be while
 * still selling into `offeredQty`. All fills execute at that one price P; P must
 * be >= reserve. Returns a not-cleared summary when nothing meets the reserve.
 *
 * Algorithm: sort candidate prices (distinct bid limits) descending; for each
 * candidate P >= reserve, demand(P) = sum of qty of bids with limit >= P. The
 * clearing price is the LOWEST candidate P where demand(P) >= offeredQty (book
 * fully sells) — else, if no price fully fills, the HIGHEST P>=reserve with any
 * demand (partial fill of demand(P), capped at offeredQty).
 */
export function clearingSummary(
  bids: ClearingBid[],
  offeredQty: number,
  reservePrice: number,
): ClearingSummary {
  const empty: ClearingSummary = { clearingPrice: null, filledQty: 0, proceeds: 0, cleared: false };
  if (!(offeredQty > 0)) return empty;
  const valid = (bids ?? []).filter((b) => b && b.qty > 0 && b.limit_price >= reservePrice);
  if (valid.length === 0) return empty;

  const demandAt = (p: number) =>
    valid.reduce((sum, b) => (b.limit_price >= p ? sum + b.qty : sum), 0);

  // Distinct candidate prices (the eligible bid limits), descending.
  const prices = Array.from(new Set(valid.map((b) => b.limit_price))).sort((a, b) => b - a);

  // Prefer the LOWEST price that still fully sells the offered book (maximizes
  // qty sold while giving every filled bid the best single clearing price).
  let clearing: number | null = null;
  for (const p of prices) {
    if (demandAt(p) >= offeredQty) clearing = p; // keep lowering while it still fills
  }
  if (clearing != null) {
    const filledQty = offeredQty;
    return { clearingPrice: clearing, filledQty, proceeds: clearing * filledQty, cleared: true };
  }

  // Nothing fully fills: partial fill at the highest eligible price.
  const top = prices[0]!;
  const filledQty = Math.min(offeredQty, demandAt(top));
  if (!(filledQty > 0)) return empty;
  return { clearingPrice: top, filledQty, proceeds: top * filledQty, cleared: false };
}
