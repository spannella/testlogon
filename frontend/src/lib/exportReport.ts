// Pure, dependency-free CSV report builders for the EXPORT & REPORTING surface.
// Every builder takes already-computed analytics (fills / PnL summary / balance
// snapshot) and returns a CSV STRING — no DOM, no I/O — so they are trivially
// unit-testable (see exportReport.test.ts). Engine int64 "tick" values are
// scaled to human-readable decimals with the SAME scaler the UI uses; timestamps
// are emitted as ISO-8601. `downloadCsv` is the only impure helper (blob + <a>).

// ── scalar formatting ────────────────────────────────────────────────

/** Scale an engine int64 tick to a plain decimal string (no thousands grouping,
 *  up to `maxFrac` fraction digits). Grouping is deliberately OFF so the CSV
 *  never embeds locale commas that would collide with the delimiter. */
export function scaleTick(value: number | undefined | null, scaler = 1, maxFrac = 8): string {
  if (value == null || !Number.isFinite(value)) return "";
  const scaled = value / (scaler || 1);
  // toLocaleString with useGrouping:false gives a clean, delimiter-safe decimal.
  return scaled.toLocaleString("en-US", {
    useGrouping: false,
    minimumFractionDigits: 0,
    maximumFractionDigits: maxFrac,
  });
}

/** `ts` may be seconds OR milliseconds — below ~year-2001-in-ms treat as seconds. */
const MS_THRESHOLD = 1e12;
export function tsToIso(ts: number | undefined | null): string {
  if (ts == null || !Number.isFinite(ts)) return "";
  const ms = ts < MS_THRESHOLD ? ts * 1000 : ts;
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString();
}

// ── CSV serialization ────────────────────────────────────────────────

const CSV_NEEDS_QUOTE = /[",\r\n]/;
/** RFC-4180 field escaping: wrap in quotes + double any embedded quote. */
export function csvEscape(value: unknown): string {
  const s = value == null ? "" : String(value);
  if (!CSV_NEEDS_QUOTE.test(s)) return s;
  return '"' + s.replace(/"/g, '""') + '"';
}

/** Join a header + rows of cells into a single CSV string (\n line endings). */
export function toCsv(header: string[], rows: (string | number)[][]): string {
  const lines: string[] = [header.map(csvEscape).join(",")];
  for (const row of rows) lines.push(row.map(csvEscape).join(","));
  return lines.join("\n");
}

// ── shared input shapes ──────────────────────────────────────────────

/** A symbol name + price scaler resolver, keyed by engine symbolid. */
export type SymbolResolver = (symbolid: number) => { name: string; scaler: number };

/** One executed fill (mirror of the /me/fills/fees feed subset we export). */
export interface ReportFill {
  symbolid: number;
  price: number;
  qty: number;
  side: string;
  liquidity?: string;
  fee: number;
  ts: number;
}

/** Per-symbol PnL rollup (mirror of pnl.ts SymbolPnl, only the exported fields). */
export interface ReportSymbolPnl {
  symbolid: number;
  net: number;
  realized: number;
  fees: number;
  funding: number;
  volume: number;
  tradeCount: number;
  closes: number;
  wins: number;
}

/** Aggregate PnL totals (mirror of pnl.ts PnlSummary, only the exported fields). */
export interface ReportPnlTotals {
  netRealized: number;
  totalRealized: number;
  totalFees: number;
  totalFunding: number;
  totalVolume: number;
  tradeCount: number;
  closeCount: number;
  winCount: number;
  winRate: number;
}

/** One balance / position line for the account statement. */
export interface StatementLine {
  /** e.g. "Spot", "Margin", "Position". */
  section: string;
  /** Asset or symbol label. */
  label: string;
  /** Engine tick value; scaled by `scaler` on export. */
  amount: number;
  scaler: number;
  note?: string;
}

// ── (a) trade history ────────────────────────────────────────────────

export const TRADE_HISTORY_HEADER = [
  "Time (ISO)",
  "Symbol",
  "Side",
  "Liquidity",
  "Price",
  "Qty",
  "Fee",
  "Notional",
];

/** Build a trade-history CSV: one row per fill, oldest-first. */
export function buildTradeHistoryCsv(fills: ReportFill[], resolve: SymbolResolver): string {
  const ordered = [...fills].sort((a, b) => a.ts - b.ts);
  const rows: (string | number)[][] = ordered.map((f) => {
    const { name, scaler } = resolve(f.symbolid);
    const notional = Math.abs(f.price * f.qty);
    return [
      tsToIso(f.ts),
      name,
      String(f.side ?? "").toUpperCase(),
      f.liquidity ?? "",
      scaleTick(f.price, scaler, 2),
      scaleTick(f.qty, scaler, 4),
      scaleTick(f.fee, scaler, 8),
      // notional is price*qty i.e. scaled by scaler^2 back to a single scaler.
      scaleTick(notional, scaler * (scaler || 1), 2),
    ];
  });
  return toCsv(TRADE_HISTORY_HEADER, rows);
}

// ── (b) PnL summary ──────────────────────────────────────────────────

export const PNL_SUMMARY_HEADER = [
  "Symbol",
  "Net PnL",
  "Realized",
  "Fees",
  "Funding",
  "Volume",
  "Trades",
  "Closes",
  "Wins",
  "Win %",
];

/** Build a per-symbol PnL CSV with a trailing TOTAL row. `quoteScaler` scales
 *  the aggregate TOTAL line (the feeds share one quote asset). */
export function buildPnlSummaryCsv(
  perSymbol: ReportSymbolPnl[],
  totals: ReportPnlTotals,
  resolve: SymbolResolver,
  quoteScaler = 1,
): string {
  const rows: (string | number)[][] = perSymbol.map((s) => {
    const { name, scaler } = resolve(s.symbolid);
    const winPct = s.closes > 0 ? ((s.wins / s.closes) * 100).toFixed(1) : "";
    return [
      name,
      scaleTick(s.net, scaler, 2),
      scaleTick(s.realized, scaler, 2),
      scaleTick(s.fees, scaler, 8),
      scaleTick(s.funding, scaler, 8),
      scaleTick(s.volume, scaler * (scaler || 1), 2),
      s.tradeCount,
      s.closes,
      s.wins,
      winPct,
    ];
  });
  // TOTAL row (aggregate values scaled by the quote scaler).
  rows.push([
    "TOTAL",
    scaleTick(totals.netRealized, quoteScaler, 2),
    scaleTick(totals.totalRealized, quoteScaler, 2),
    scaleTick(totals.totalFees, quoteScaler, 8),
    scaleTick(totals.totalFunding, quoteScaler, 8),
    scaleTick(totals.totalVolume, quoteScaler * (quoteScaler || 1), 2),
    totals.tradeCount,
    totals.closeCount,
    totals.winCount,
    (totals.winRate * 100).toFixed(1),
  ]);
  return toCsv(PNL_SUMMARY_HEADER, rows);
}

// ── (c) account statement ────────────────────────────────────────────

export const STATEMENT_HEADER = ["Section", "Account / Asset", "Amount", "Note"];

/** Build an account-statement CSV (a point-in-time balance/position snapshot).
 *  A period label + generated-at line are emitted as leading comment rows so the
 *  file is self-describing; the table header follows. */
export function buildStatementCsv(
  lines: StatementLine[],
  meta: { period: string; generatedAt?: number },
): string {
  const gen = tsToIso(meta.generatedAt ?? Date.now());
  const preamble: string[] = [
    csvEscape(`# Account statement — ${meta.period}`),
    csvEscape(`# Generated ${gen}`),
    "",
    STATEMENT_HEADER.map(csvEscape).join(","),
  ];
  const rows = lines.map((l) =>
    [l.section, l.label, scaleTick(l.amount, l.scaler, 8), l.note ?? ""].map(csvEscape).join(","),
  );
  return [...preamble, ...rows].join("\n");
}

// ── download helper (only impure fn) ─────────────────────────────────

/** Trigger a client-side CSV file download (UTF-8 BOM so Excel reads it right). */
export function downloadCsv(filename: string, content: string): void {
  const blob = new Blob(["﻿" + content], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 5_000);
}
