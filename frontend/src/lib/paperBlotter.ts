// Pure, framework-free adapters that project the shared PAPER account
// (paperEngine.ts) into the shapes the read-only trading views already render:
//   - the Blotter grid `Order` rows (Orders + Fills panels),
//   - position rows with live-mark MTM / uPnL (Positions panel + Portfolio),
//   - a PnL summary (realized / unrealized / equity) for the PnL view.
//
// Kept pure + dependency-light (only the paperEngine types + its unrealized/
// equity helpers) so it is unit-testable in isolation (see paperBlotter.test.ts).
// NOTHING here touches the network — callers pass in the live marks they already
// source from the market-data hooks.
import type { Order, Side } from "@/components/blotter/types";
import {
  unrealized as calcUnrealized,
  equity as calcEquity,
  type PaperAccount,
  type PaperOrder,
  type PaperFill,
} from "./paperEngine";

/** Resolve a symbolId to its display name (e.g. 1 -> "BTCUSDC"). */
export type SymName = (symbolId: number) => string;

/** Paper marks keyed by symbolId — the price each position/order marks against. */
export type PaperMarks = Record<number, number | undefined>;

const sideOf = (s: "buy" | "sell"): Side => (s === "buy" ? "B" : "S");
const nsOf = (ms: number): number => ms * 1_000_000; // ms epoch -> ns epoch (blotter ts unit)

/**
 * Project the account's WORKING (resting) orders into blotter `Order` rows so the
 * existing `orderColumns` grid (grouping / filter / column-chooser / export) works
 * unchanged. Working paper orders are limit orders with no fills yet, so cumQty=0,
 * leaves=qty, status='live'.
 */
export function paperOrdersToBlotter(acct: PaperAccount, symName: SymName): Order[] {
  return acct.orders
    .filter((o) => o.status === "working")
    .map((o) => paperOrderRow(o, symName));
}

function paperOrderRow(o: PaperOrder, symName: SymName): Order {
  const px = o.price ?? 0;
  return {
    clord: o.id,
    sym: symName(o.symbolId),
    side: sideOf(o.side),
    venue: "IEX", // synthetic — the paper engine has no venue; a stable placeholder
    px,
    qty: o.qty,
    cumQty: 0,
    leaves: o.qty,
    avgPx: 0,
    status: "live",
    tif: "DAY",
    tRcv: nsOf(o.createdAt),
    tLastUpd: nsOf(o.createdAt),
    subacct: 0,
    lots: [],
    source: "PAPR",
  };
}

/**
 * Project the account's fills into blotter `Order` rows for the Fills panel — one
 * row per fill. cumQty = the filled qty, avgPx = the fill price, status='filled'.
 */
export function paperFillsToBlotter(acct: PaperAccount, symName: SymName): Order[] {
  // Newest first, mirroring the Paper page fill-history ordering.
  return acct.fills
    .slice()
    .reverse()
    .map((f) => paperFillRow(f, symName));
}

function paperFillRow(f: PaperFill, symName: SymName): Order {
  return {
    clord: f.id,
    sym: symName(f.symbolId),
    side: sideOf(f.side),
    venue: "IEX",
    px: f.price,
    qty: f.qty,
    cumQty: f.qty,
    leaves: 0,
    avgPx: f.price,
    status: "filled",
    tif: "DAY",
    tRcv: nsOf(f.ts),
    tLastUpd: nsOf(f.ts),
    subacct: 0,
    lots: [{ ts: nsOf(f.ts), qty: f.qty, px: f.price, liq: "R" }],
    source: "PAPR",
  };
}

/** A position row for the Positions grid / Portfolio table, MTM at a live mark. */
export interface PaperPositionRow {
  sym: string;
  symbolId: number;
  netQty: number;
  side: "Long" | "Short";
  avgCost: number;
  markPx: number | undefined;
  unrealized: number;
}

/**
 * Project the account's open positions into position rows with live-mark MTM.
 * uPnL = (mark - avgEntry) * qty, matching paperEngine.unrealized per-symbol;
 * a position with no mark contributes 0 uPnL (markPx undefined).
 */
export function paperPositionsToBlotter(
  acct: PaperAccount,
  marks: PaperMarks,
  symName: SymName,
): PaperPositionRow[] {
  const rows: PaperPositionRow[] = [];
  for (const [k, pos] of Object.entries(acct.positions)) {
    const id = Number(k);
    if (pos.qty === 0) continue;
    const mark = marks[id];
    const hasMark = mark != null && Number.isFinite(mark);
    const u = hasMark ? (mark! - pos.avgEntry) * pos.qty : 0;
    rows.push({
      sym: symName(id),
      symbolId: id,
      netQty: pos.qty,
      side: pos.qty > 0 ? "Long" : "Short",
      avgCost: pos.avgEntry,
      markPx: hasMark ? mark! : undefined,
      unrealized: u,
    });
  }
  // Stable order: largest absolute exposure first.
  rows.sort((a, b) => Math.abs(b.netQty) - Math.abs(a.netQty));
  return rows;
}

/** Everything the PnL view needs from the paper account, at the given marks. */
export interface PaperPnlSummary {
  realized: number;
  unrealized: number;
  equity: number;
  cash: number;
  startingCash: number;
  returnPct: number;
  perSymbol: PaperPositionRow[];
}

/**
 * Compute realized / unrealized / equity from the paper account at `marks`.
 * realized = account cumulative realized PnL; unrealized + equity reuse the
 * paperEngine helpers so the numbers match the Paper page exactly.
 */
export function buildPnlSummaryFromPaper(
  acct: PaperAccount,
  marks: PaperMarks,
  symName: SymName,
): PaperPnlSummary {
  const unreal = calcUnrealized(acct, marks);
  const eq = calcEquity(acct, marks);
  const returnPct =
    acct.startingCash > 0 ? ((eq - acct.startingCash) / acct.startingCash) * 100 : 0;
  return {
    realized: acct.realizedPnl,
    unrealized: unreal,
    equity: eq,
    cash: acct.cash,
    startingCash: acct.startingCash,
    returnPct,
    perSymbol: paperPositionsToBlotter(acct, marks, symName),
  };
}
