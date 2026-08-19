// Pure, dependency-free PnL / performance analytics computed CLIENT-SIDE from
// the exchange account feeds (fills-fees / funding / liquidations). Every value
// stays in the engine's int64 "tick" space — the UI scales for display with the
// markets `formatPrice`/`formatQty` helpers. Kept pure + framework-free so it is
// unit-testable in isolation (see pnl.test.ts).

/** One executed fill (subset of the `/me/fills/fees` feed shape used here). */
export interface PnlFill {
  symbolid: number;
  /** int64 engine tick. */
  price: number;
  /** int64 engine tick. */
  qty: number;
  side: "buy" | "sell";
  /** int64 engine tick — the REAL fee charged for this fill. */
  fee: number;
  /** unix ts (seconds or ms). */
  ts: number;
}

/** One funding payment (subset of `/me/funding/payments`). */
export interface PnlFunding {
  symbolid: number;
  /** int64 engine tick, SIGNED — negative = paid, positive = received. */
  payment: number;
  ts: number;
}

/** One forced-liquidation event (subset of `/me/liquidations`). */
export interface PnlLiquidation {
  symbolid: number;
  /** int64 engine tick, SIGNED. */
  realized_pnl: number;
  /** int64 engine tick — the liquidation fee. */
  fee: number;
  ts: number;
}

/** Per-symbol realized-PnL rollup. All amounts are engine int64 ticks. */
export interface SymbolPnl {
  symbolid: number;
  /** Realized PnL from average-cost round-trips (fills only, pre-fee). */
  realized: number;
  /** Sum of fees paid on this symbol's fills. */
  fees: number;
  /** Sum of signed funding payments for this symbol. */
  funding: number;
  /** Sum of liquidation realized_pnl for this symbol. */
  liquidationPnl: number;
  /** Sum of liquidation fees for this symbol. */
  liquidationFees: number;
  /** Net realized = realized - fees + funding + liquidationPnl - liquidationFees. */
  net: number;
  /** Traded notional = sum of |price*qty| over fills (magnitude only). */
  volume: number;
  /** Number of fills on this symbol. */
  tradeCount: number;
  /** Number of position-reducing/closing fills that realized PnL. */
  closes: number;
  /** Of those closes, how many realized a strictly-positive PnL. */
  wins: number;
}

/** Everything the PnL page renders, derived from the three feeds + current unrealized. */
export interface PnlSummary {
  perSymbol: SymbolPnl[];
  /** Sum of average-cost realized (pre-fee, fills only). */
  totalRealized: number;
  /** Sum of fees across all fills. */
  totalFees: number;
  /** Sum of signed funding. */
  totalFunding: number;
  /** Sum of liquidation realized_pnl. */
  totalLiquidationPnl: number;
  /** Sum of liquidation fees. */
  totalLiquidationFees: number;
  /**
   * Net realized across everything:
   *   realized - fees + funding + liq.realized - liq.fees.
   */
  netRealized: number;
  /** Total traded notional magnitude across all fills. */
  totalVolume: number;
  /** Total number of fills. */
  tradeCount: number;
  /** Number of position-closing fills. */
  closeCount: number;
  /** Number of winning (positive-realized) closing fills. */
  winCount: number;
  /** winCount / closeCount in [0,1]; 0 when there are no closes. */
  winRate: number;
  /** Time-ordered cumulative equity curve (realized + funding - fees, by ts). */
  equityCurve: EquityPoint[];
}

/** One point on the cumulative equity curve. */
export interface EquityPoint {
  ts: number;
  /** Cumulative net (realized + funding - fees + liq.realized - liq.fees) up to ts. */
  value: number;
}

/**
 * Walk one symbol's fills oldest to newest with an average-cost running
 * position (netQty, avgEntry) and return the realized PnL plus win/close/volume
 * stats.
 *
 * - A fill on the SAME side as the current net position (or opening from flat)
 *   INCREASES the position and updates the weighted-average entry price.
 * - A fill on the OPPOSITE side REDUCES/closes: it realizes
 *     (fillPrice - avgEntry) * closedQty * dir
 *   where dir = +1 if the closed position was long, -1 if short, and closedQty
 *   is the min of the fill qty and the open size. Any residual qty beyond the
 *   close flips the position and opens a new leg at the fill price.
 *
 * `realizedPerClose` records the realized PnL of every position-reducing event
 * so callers can compute a win rate over discrete closes.
 */
export function walkSymbolFills(fills: PnlFill[]): {
  realized: number;
  volume: number;
  realizedPerClose: number[];
} {
  // Oldest to newest.
  const ordered = [...fills].sort((a, b) => a.ts - b.ts);

  let netQty = 0; // signed: >0 long, <0 short
  let avgEntry = 0;
  let realized = 0;
  let volume = 0;
  const realizedPerClose: number[] = [];

  for (const f of ordered) {
    const signed = f.side === "buy" ? f.qty : -f.qty;
    volume += Math.abs(f.price * f.qty);

    if (netQty === 0 || Math.sign(signed) === Math.sign(netQty)) {
      // Opening or adding in the same direction — weighted-average the entry.
      const newQty = netQty + signed;
      const totalCost = avgEntry * Math.abs(netQty) + f.price * Math.abs(signed);
      avgEntry = Math.abs(newQty) === 0 ? 0 : totalCost / Math.abs(newQty);
      netQty = newQty;
      continue;
    }

    // Opposite side — reduce/close (and maybe flip).
    const dir = netQty > 0 ? 1 : -1; // direction of the position being closed
    const closedQty = Math.min(Math.abs(signed), Math.abs(netQty));
    const pnl = (f.price - avgEntry) * closedQty * dir;
    realized += pnl;
    realizedPerClose.push(pnl);

    const residual = Math.abs(signed) - Math.abs(netQty);
    if (residual > 0) {
      // Fully closed then flipped — open a fresh leg at the fill price.
      netQty = Math.sign(signed) * residual;
      avgEntry = f.price;
    } else {
      netQty = netQty + signed; // shrink toward / to zero
      if (netQty === 0) avgEntry = 0;
    }
  }

  return { realized, volume, realizedPerClose };
}

/** Group an array by a numeric key. */
function groupBy<T>(items: T[], key: (t: T) => number): Map<number, T[]> {
  const m = new Map<number, T[]>();
  for (const it of items) {
    const k = key(it);
    const arr = m.get(k);
    if (arr) arr.push(it);
    else m.set(k, [it]);
  }
  return m;
}

/**
 * Compute the full PnL summary from the three account feeds.
 * All inputs are optional (a feed may 404 -> treat as empty).
 */
export function computePnl(
  fills: PnlFill[] = [],
  funding: PnlFunding[] = [],
  liquidations: PnlLiquidation[] = [],
): PnlSummary {
  const bySymbol = groupBy(fills, (f) => f.symbolid);
  const fundingBySymbol = groupBy(funding, (f) => f.symbolid);
  const liqBySymbol = groupBy(liquidations, (l) => l.symbolid);

  const symbolIds = new Set<number>([
    ...bySymbol.keys(),
    ...fundingBySymbol.keys(),
    ...liqBySymbol.keys(),
  ]);

  const perSymbol: SymbolPnl[] = [];

  for (const symbolid of symbolIds) {
    const sFills = bySymbol.get(symbolid) ?? [];
    const sFunding = fundingBySymbol.get(symbolid) ?? [];
    const sLiq = liqBySymbol.get(symbolid) ?? [];

    const { realized, volume, realizedPerClose } = walkSymbolFills(sFills);
    const fees = sFills.reduce((a, f) => a + (f.fee || 0), 0);
    const fundingSum = sFunding.reduce((a, f) => a + (f.payment || 0), 0);
    const liquidationPnl = sLiq.reduce((a, l) => a + (l.realized_pnl || 0), 0);
    const liquidationFees = sLiq.reduce((a, l) => a + (l.fee || 0), 0);
    const wins = realizedPerClose.filter((p) => p > 0).length;

    perSymbol.push({
      symbolid,
      realized,
      fees,
      funding: fundingSum,
      liquidationPnl,
      liquidationFees,
      net: realized - fees + fundingSum + liquidationPnl - liquidationFees,
      volume,
      tradeCount: sFills.length,
      closes: realizedPerClose.length,
      wins,
    });
  }

  // Stable order: biggest traded volume first.
  perSymbol.sort((a, b) => b.volume - a.volume);

  const totalRealized = perSymbol.reduce((a, s) => a + s.realized, 0);
  const totalFees = perSymbol.reduce((a, s) => a + s.fees, 0);
  const totalFunding = perSymbol.reduce((a, s) => a + s.funding, 0);
  const totalLiquidationPnl = perSymbol.reduce((a, s) => a + s.liquidationPnl, 0);
  const totalLiquidationFees = perSymbol.reduce((a, s) => a + s.liquidationFees, 0);
  const totalVolume = perSymbol.reduce((a, s) => a + s.volume, 0);
  const tradeCount = perSymbol.reduce((a, s) => a + s.tradeCount, 0);
  const closeCount = perSymbol.reduce((a, s) => a + s.closes, 0);
  const winCount = perSymbol.reduce((a, s) => a + s.wins, 0);

  return {
    perSymbol,
    totalRealized,
    totalFees,
    totalFunding,
    totalLiquidationPnl,
    totalLiquidationFees,
    netRealized:
      totalRealized - totalFees + totalFunding + totalLiquidationPnl - totalLiquidationFees,
    totalVolume,
    tradeCount,
    closeCount,
    winCount,
    winRate: closeCount === 0 ? 0 : winCount / closeCount,
    equityCurve: buildEquityCurve(fills, funding, liquidations),
  };
}

/**
 * A time-ordered cumulative running total of realized+funding-fees across ALL
 * events. Fills contribute their per-fill realized delta (from the average-cost
 * walk) minus their fee; funding contributes its signed payment; liquidations
 * contribute realized_pnl - fee. Events are merged and sorted by ts, then the
 * running sum is emitted as one point per event.
 */
export function buildEquityCurve(
  fills: PnlFill[] = [],
  funding: PnlFunding[] = [],
  liquidations: PnlLiquidation[] = [],
): EquityPoint[] {
  interface Ev {
    ts: number;
    delta: number;
  }
  const events: Ev[] = [];

  // Per-symbol average-cost walk to attribute a realized delta to each fill.
  const bySymbol = groupBy(fills, (f) => f.symbolid);
  for (const sFills of bySymbol.values()) {
    const ordered = [...sFills].sort((a, b) => a.ts - b.ts);
    let netQty = 0;
    let avgEntry = 0;
    for (const f of ordered) {
      const signed = f.side === "buy" ? f.qty : -f.qty;
      let realizedDelta = 0;
      if (netQty !== 0 && Math.sign(signed) !== Math.sign(netQty)) {
        const dir = netQty > 0 ? 1 : -1;
        const closedQty = Math.min(Math.abs(signed), Math.abs(netQty));
        realizedDelta = (f.price - avgEntry) * closedQty * dir;
        const residual = Math.abs(signed) - Math.abs(netQty);
        if (residual > 0) {
          netQty = Math.sign(signed) * residual;
          avgEntry = f.price;
        } else {
          netQty = netQty + signed;
          if (netQty === 0) avgEntry = 0;
        }
      } else {
        const newQty = netQty + signed;
        const totalCost = avgEntry * Math.abs(netQty) + f.price * Math.abs(signed);
        avgEntry = Math.abs(newQty) === 0 ? 0 : totalCost / Math.abs(newQty);
        netQty = newQty;
      }
      events.push({ ts: f.ts, delta: realizedDelta - (f.fee || 0) });
    }
  }

  for (const f of funding) events.push({ ts: f.ts, delta: f.payment || 0 });
  for (const l of liquidations)
    events.push({ ts: l.ts, delta: (l.realized_pnl || 0) - (l.fee || 0) });

  events.sort((a, b) => a.ts - b.ts);

  const curve: EquityPoint[] = [];
  let running = 0;
  for (const e of events) {
    running += e.delta;
    curve.push({ ts: e.ts, value: running });
  }
  return curve;
}
