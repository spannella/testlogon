// Pure, dependency-free TAX-LOT / realized-gains engine computed CLIENT-SIDE
// from a normalized trade-fill list. NO framework, NO I/O, NO DOM — every value
// is an INTEGER (cents / whole share-qty) so the arithmetic is exact and the
// module is trivially unit-testable (see taxLots.test.ts).
//
// The caller (TaxReportPage) normalizes the raw exchange `/me/fills/fees` feed
// (int64 engine ticks scaled per-symbol) into the `TaxFill` shape below —
// `priceCents` = per-unit price in integer minor units, `feeCents` = fee in the
// same minor units, `qty` = signed-agnostic positive quantity, `side` = buy|sell.
//
// A BUY opens a cost lot (basis = qty*price + fee folded in). A SELL closes open
// lots per the chosen accounting method (FIFO / LIFO / average-cost). Realized
// gain = proceeds - matched cost basis - sell fee. Holding term is LONG when the
// closed lot was held > 365 days, else SHORT. Sell-before-buy / oversell is
// handled gracefully: the unmatched sell qty is skipped and flagged (never
// throws, never produces a negative-qty lot).

// ── input / output shapes ────────────────────────────────────────────

export type Side = "buy" | "sell";
export type Method = "fifo" | "lifo" | "avg";
export type Term = "short" | "long";

/** One normalized executed fill. All amounts are INTEGER minor units (cents). */
export interface TaxFill {
  /** unix timestamp — seconds OR milliseconds (engine-native); used only for
   *  ordering + holding-period math, so the unit only needs to be consistent. */
  ts: number;
  symbol: string;
  side: Side;
  /** Executed quantity (always treated as a positive magnitude). */
  qty: number;
  /** Per-unit executed price, integer minor units (cents). */
  priceCents: number;
  /** Fee charged on this fill, integer minor units (cents). Folded into basis
   *  (buys) or netted out of proceeds (sells). */
  feeCents: number;
}

/** A still-open cost lot (a buy, or the residual of a partially-closed buy). */
export interface OpenLot {
  symbol: string;
  /** Timestamp of the opening buy. */
  openTs: number;
  /** Remaining open quantity. */
  qty: number;
  /** Remaining cost basis (integer cents) for the remaining `qty`, fee-inclusive. */
  costBasisCents: number;
}

/** One realized (closed) tax lot produced by matching a sell against buy lots. */
export interface RealizedLot {
  symbol: string;
  /** Timestamp of the closing sell. */
  closeTs: number;
  /** Timestamp of the opening buy the closed qty came from (avg: earliest open). */
  openTs: number;
  /** Quantity closed in this realized row. */
  qty: number;
  /** Proceeds = qty*sellPrice minus the pro-rated sell fee (fee-inclusive). */
  proceedsCents: number;
  /** Matched cost basis for `qty` (fee-inclusive from the buy side). */
  costBasisCents: number;
  /** The sell-side fee attributed to this realized row (already netted into proceeds). */
  feeCents: number;
  /** proceedsCents - costBasisCents (fees already folded into both sides). */
  gainCents: number;
  /** Whole days the closed lot was held (closeTs - openTs). */
  holdingDays: number;
  term: Term;
}

export interface ComputeResult {
  openLots: OpenLot[];
  realized: RealizedLot[];
  /** Non-fatal issues (oversell / zero-qty / sell-before-buy) for UI flagging. */
  warnings: string[];
}

// ── helpers ──────────────────────────────────────────────────────────

const MS_THRESHOLD = 1e12;
/** Normalize a seconds-or-ms timestamp to milliseconds. */
function toMs(ts: number): number {
  if (!Number.isFinite(ts)) return 0;
  return ts < MS_THRESHOLD ? ts * 1000 : ts;
}

const DAY_MS = 86_400_000;
/** Whole days between two timestamps (each seconds-or-ms). Never negative. */
export function holdingDaysBetween(openTs: number, closeTs: number): number {
  const d = Math.floor((toMs(closeTs) - toMs(openTs)) / DAY_MS);
  return d > 0 ? d : 0;
}

/** LONG-term when held strictly MORE than 365 days, else SHORT. */
function termFor(days: number): Term {
  return days > 365 ? "long" : "short";
}

/** Integer-round a possibly-fractional cents value (pro-rated allocations). */
const rc = (v: number): number => Math.round(v);

// A mutable open-lot used internally (average-cost tracks a running pool).
interface MutLot {
  symbol: string;
  openTs: number;
  qty: number;
  costBasisCents: number;
}

// ── the engine ───────────────────────────────────────────────────────

/**
 * Compute open + realized tax lots from a fill list under `method`.
 * Fills are processed OLDEST-first (stable). Buys open lots; sells close lots.
 * Handles oversell / sell-before-buy / zero-qty gracefully (skip + warn).
 */
export function computeLots(fills: TaxFill[], method: Method): ComputeResult {
  const warnings: string[] = [];
  const realized: RealizedLot[] = [];

  // Per-symbol queue of open lots (FIFO/LIFO) or a single running pool (avg).
  const bySymbol = new Map<string, MutLot[]>();
  const lotsFor = (sym: string): MutLot[] => {
    let a = bySymbol.get(sym);
    if (!a) bySymbol.set(sym, (a = []));
    return a;
  };

  const ordered = [...fills].sort((a, b) => toMs(a.ts) - toMs(b.ts));

  for (const f of ordered) {
    const qty = Math.abs(f.qty);
    if (!qty || !Number.isFinite(qty)) {
      warnings.push(`Skipped zero/invalid-qty ${f.side} on ${f.symbol}`);
      continue;
    }
    const price = Number.isFinite(f.priceCents) ? f.priceCents : 0;
    const fee = Number.isFinite(f.feeCents) ? Math.abs(f.feeCents) : 0;

    if (f.side === "buy") {
      // Open a cost lot: basis = qty*price + fee folded in.
      const lots = lotsFor(f.symbol);
      if (method === "avg") {
        // Average-cost: collapse into a single running pool per symbol.
        const pool = lots[0];
        const addBasis = qty * price + fee;
        if (pool) {
          pool.qty += qty;
          pool.costBasisCents += addBasis;
          // openTs stays the EARLIEST buy in the pool (conservative holding term).
        } else {
          lots.push({ symbol: f.symbol, openTs: f.ts, qty, costBasisCents: addBasis });
        }
      } else {
        lots.push({ symbol: f.symbol, openTs: f.ts, qty, costBasisCents: qty * price + fee });
      }
      continue;
    }

    // ── SELL: close open lots per method ──
    const lots = lotsFor(f.symbol);
    let remaining = qty;
    const grossProceeds = qty * price; // pre-fee
    let feeLeft = fee; // sell fee pro-rated across matched qty

    // Guard: nothing (or not enough) to close → oversell / sell-before-buy.
    const available = lots.reduce((s, l) => s + l.qty, 0);
    if (available <= 0) {
      warnings.push(`Sell of ${qty} ${f.symbol} with no open position — skipped`);
      continue;
    }

    while (remaining > 0 && lots.length > 0) {
      // FIFO takes the front (oldest); LIFO + avg-pool take from either end.
      const idx = method === "lifo" ? lots.length - 1 : 0;
      const lot = lots[idx];
      if (!lot) break; // defensive (loop guard already ensures lots.length > 0)
      const take = Math.min(remaining, lot.qty);

      // Matched cost basis (pro-rated within the lot).
      const lotUnitBasis = lot.qty > 0 ? lot.costBasisCents / lot.qty : 0;
      const matchedCost = rc(lotUnitBasis * take);

      // Pro-rate proceeds + sell fee to this slice by qty share of the sell.
      const proceedsSlice = rc((grossProceeds * take) / qty);
      const feeSlice = remaining - take <= 0 ? feeLeft : rc((fee * take) / qty);
      feeLeft -= feeSlice;
      const netProceeds = proceedsSlice - feeSlice;

      const days = holdingDaysBetween(lot.openTs, f.ts);
      realized.push({
        symbol: f.symbol,
        closeTs: f.ts,
        openTs: lot.openTs,
        qty: take,
        proceedsCents: netProceeds,
        costBasisCents: matchedCost,
        feeCents: feeSlice,
        gainCents: netProceeds - matchedCost,
        holdingDays: days,
        term: termFor(days),
      });

      // Shrink / drop the lot.
      lot.qty -= take;
      lot.costBasisCents -= matchedCost;
      if (lot.qty <= 0) lots.splice(idx, 1);
      remaining -= take;
    }

    if (remaining > 0) {
      warnings.push(`Oversell: ${remaining} ${f.symbol} sold beyond open position — skipped`);
    }
  }

  // Flatten remaining open lots (drop zero/negative residuals).
  const openLots: OpenLot[] = [];
  for (const lots of bySymbol.values()) {
    for (const l of lots) {
      if (l.qty > 0) {
        openLots.push({
          symbol: l.symbol,
          openTs: l.openTs,
          qty: l.qty,
          costBasisCents: l.costBasisCents,
        });
      }
    }
  }
  openLots.sort((a, b) => a.symbol.localeCompare(b.symbol) || toMs(a.openTs) - toMs(b.openTs));

  return { openLots, realized, warnings };
}

// ── summaries ────────────────────────────────────────────────────────

export interface RealizedSummary {
  bySymbol: { symbol: string; gainCents: number; proceedsCents: number }[];
  byTerm: { shortCents: number; longCents: number };
  totalGainCents: number;
}

/** Aggregate realized rows: per-symbol gain/proceeds, short-vs-long split, total. */
export function realizedSummary(realized: RealizedLot[]): RealizedSummary {
  const bySym = new Map<string, { gainCents: number; proceedsCents: number }>();
  let shortCents = 0;
  let longCents = 0;
  let totalGainCents = 0;

  for (const r of realized) {
    const cur = bySym.get(r.symbol) ?? { gainCents: 0, proceedsCents: 0 };
    cur.gainCents += r.gainCents;
    cur.proceedsCents += r.proceedsCents;
    bySym.set(r.symbol, cur);

    if (r.term === "long") longCents += r.gainCents;
    else shortCents += r.gainCents;
    totalGainCents += r.gainCents;
  }

  const bySymbol = [...bySym.entries()]
    .map(([symbol, v]) => ({ symbol, gainCents: v.gainCents, proceedsCents: v.proceedsCents }))
    .sort((a, b) => a.symbol.localeCompare(b.symbol));

  return { bySymbol, byTerm: { shortCents, longCents }, totalGainCents };
}

// ── unrealized (open lots vs mark) ───────────────────────────────────

/** A mark map: symbol -> per-unit mark price in integer minor units (cents). */
export type Marks = Record<string, number | undefined>;

export interface UnrealizedRow {
  symbol: string;
  qty: number;
  costBasisCents: number;
  /** qty * mark (integer cents); 0 when no mark is available. */
  marketValueCents: number;
  /** marketValueCents - costBasisCents; 0 when no mark. */
  unrealizedCents: number;
  /** True when no mark was found for the symbol (value/unrealized are 0). */
  noMark: boolean;
}

/**
 * Unrealized P&L for the open lots, aggregated per symbol, valued at `marks`.
 * A symbol with no mark reports marketValue/unrealized = 0 and `noMark:true`.
 */
export function unrealized(openLots: OpenLot[], marks: Marks): UnrealizedRow[] {
  const bySym = new Map<string, { qty: number; costBasisCents: number }>();
  for (const l of openLots) {
    const cur = bySym.get(l.symbol) ?? { qty: 0, costBasisCents: 0 };
    cur.qty += l.qty;
    cur.costBasisCents += l.costBasisCents;
    bySym.set(l.symbol, cur);
  }

  const rows: UnrealizedRow[] = [];
  for (const [symbol, v] of bySym.entries()) {
    const mark = marks[symbol];
    const hasMark = mark != null && Number.isFinite(mark);
    const marketValueCents = hasMark ? rc(mark! * v.qty) : 0;
    rows.push({
      symbol,
      qty: v.qty,
      costBasisCents: v.costBasisCents,
      marketValueCents,
      unrealizedCents: hasMark ? marketValueCents - v.costBasisCents : 0,
      noMark: !hasMark,
    });
  }
  rows.sort((a, b) => a.symbol.localeCompare(b.symbol));
  return rows;
}

// ── CSV export (pure string builder, no DOM) ─────────────────────────

const CSV_NEEDS_QUOTE = /[",\r\n]/;
function csvEscape(value: unknown): string {
  const s = value == null ? "" : String(value);
  return CSV_NEEDS_QUOTE.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

/** Cents integer -> plain decimal string (2 dp, no grouping — delimiter-safe). */
function centsToStr(cents: number): string {
  if (!Number.isFinite(cents)) return "";
  return (cents / 100).toFixed(2);
}

const REALIZED_CSV_HEADER = [
  "Close Time (ISO)",
  "Open Time (ISO)",
  "Symbol",
  "Qty",
  "Proceeds",
  "Cost Basis",
  "Fee",
  "Gain/Loss",
  "Holding Days",
  "Term",
];

function tsToIso(ts: number): string {
  const ms = toMs(ts);
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString();
}

/** Build a realized-lots CSV (one row per closed lot, oldest close first). */
export function lotsToCsv(realized: RealizedLot[]): string {
  const ordered = [...realized].sort((a, b) => toMs(a.closeTs) - toMs(b.closeTs));
  const lines: string[] = [REALIZED_CSV_HEADER.map(csvEscape).join(",")];
  for (const r of ordered) {
    lines.push(
      [
        tsToIso(r.closeTs),
        tsToIso(r.openTs),
        r.symbol,
        r.qty,
        centsToStr(r.proceedsCents),
        centsToStr(r.costBasisCents),
        centsToStr(r.feeCents),
        centsToStr(r.gainCents),
        r.holdingDays,
        r.term,
      ]
        .map(csvEscape)
        .join(","),
    );
  }
  return lines.join("\n");
}
