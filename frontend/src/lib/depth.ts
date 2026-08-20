/**
 * Pure cumulative-depth math for the depth chart.
 *
 * Book levels are integer [price, qty] tuples (int64 ticks). All functions
 * here are unit-scaled-agnostic: they operate on the raw integers and leave
 * display scaling to the caller (markets `formatPrice`/`formatQty`).
 */

export type Level = [number, number];

export interface DepthPoint {
  /** Price at this level (raw integer tick). */
  price: number;
  /** Size resting at exactly this level. */
  qty: number;
  /** Cumulative size from the best price out to (and including) this level. */
  cum: number;
}

export interface DepthSeries {
  /** Bids, cumulated from best (highest) price outward to lower prices. */
  bids: DepthPoint[];
  /** Asks, cumulated from best (lowest) price outward to higher prices. */
  asks: DepthPoint[];
  /** Best bid price, or undefined if no bids. */
  bestBid?: number;
  /** Best ask price, or undefined if no asks. */
  bestAsk?: number;
  /** Mid price ((bestBid+bestAsk)/2), or undefined if either side is empty. */
  mid?: number;
  /** Spread (bestAsk-bestBid), or undefined if either side is empty. */
  spread?: number;
  /** Largest cumulative size across both sides (for y-axis scaling). */
  maxCum: number;
  /** Lowest price plotted across both sides (for x-axis scaling). */
  minPrice?: number;
  /** Highest price plotted across both sides (for x-axis scaling). */
  maxPrice?: number;
}

/** Drop null/NaN/negative levels; coerce to finite integer-ish tuples. */
function sanitize(levels: readonly Level[] | undefined): Level[] {
  if (!levels) return [];
  const out: Level[] = [];
  for (const lvl of levels) {
    if (!lvl) continue;
    const price = lvl[0];
    const qty = lvl[1];
    if (
      !Number.isFinite(price) ||
      !Number.isFinite(qty) ||
      price <= 0 ||
      qty <= 0
    ) {
      continue;
    }
    out.push([price, qty]);
  }
  return out;
}

/**
 * Merge levels that share a price (defensive against a book that lists a
 * price more than once) and sum their sizes.
 */
function coalesce(levels: Level[]): Level[] {
  const byPrice = new Map<number, number>();
  for (const [price, qty] of levels) {
    byPrice.set(price, (byPrice.get(price) ?? 0) + qty);
  }
  return [...byPrice.entries()].map(([price, qty]) => [price, qty] as Level);
}

/**
 * Build a cumulative-depth curve for one side of the book.
 *
 * `descending` = bids (cumulate from the highest price down); otherwise asks
 * (cumulate from the lowest price up). The returned points are ordered from
 * the best price outward, each carrying the running cumulative size.
 */
export function cumulativeSide(
  levels: readonly Level[] | undefined,
  descending: boolean
): DepthPoint[] {
  const clean = coalesce(sanitize(levels));
  clean.sort((a, b) => (descending ? b[0] - a[0] : a[0] - b[0]));
  let cum = 0;
  const out: DepthPoint[] = [];
  for (const [price, qty] of clean) {
    cum += qty;
    out.push({ price, qty, cum });
  }
  return out;
}

/**
 * Compute the full cumulative-depth series for both sides plus the mid/spread
 * and the axis bounds needed to render a mirrored depth chart.
 */
export function computeDepth(
  bids: readonly Level[] | undefined,
  asks: readonly Level[] | undefined
): DepthSeries {
  const bidPts = cumulativeSide(bids, true);
  const askPts = cumulativeSide(asks, false);

  const bestBid = bidPts.length ? bidPts[0]!.price : undefined;
  const bestAsk = askPts.length ? askPts[0]!.price : undefined;

  const mid =
    bestBid != null && bestAsk != null ? (bestBid + bestAsk) / 2 : undefined;
  const spread =
    bestBid != null && bestAsk != null ? bestAsk - bestBid : undefined;

  const maxCum = Math.max(
    bidPts.length ? bidPts[bidPts.length - 1]!.cum : 0,
    askPts.length ? askPts[askPts.length - 1]!.cum : 0
  );

  const prices: number[] = [];
  for (const p of bidPts) prices.push(p.price);
  for (const p of askPts) prices.push(p.price);
  const minPrice = prices.length ? Math.min(...prices) : undefined;
  const maxPrice = prices.length ? Math.max(...prices) : undefined;

  return {
    bids: bidPts,
    asks: askPts,
    bestBid,
    bestAsk,
    mid,
    spread,
    maxCum,
    minPrice,
    maxPrice,
  };
}
