// EXPORT & REPORTING — a READ-ONLY reporting surface built CLIENT-SIDE from the
// same exchange account feeds the PnL page uses (fills-fees / funding /
// liquidations) plus the margin + spot balance snapshots. Pick a period, preview
// the headline stats over the scoped fills, then export CSV (trades / PnL /
// statement) or open a print-optimized view and Save-as-PDF via window.print().
// No new deps, no new backend: every feed degrades independently (a 404 feed
// just contributes nothing), and each value stays in engine int64 ticks scaled
// for display by the markets formatters.
import { useMemo, useState } from "react";
import {
  FileSpreadsheet,
  Download,
  Printer,
  RefreshCw,
  TrendingUp,
  TrendingDown,
  Receipt,
  Target,
  Hash,
  BarChart2,
  Info,
} from "lucide-react";
import { ApiError } from "@/api/client";
import { cn } from "@/lib/utils";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { Input } from "@/components/ui/input";

import {
  useFillsFees,
  useLiquidations,
  useFundingPayments,
  useMarginAccount,
  useSpotBalance,
} from "@/hooks/useTrading";
import { useSymbols } from "@/hooks/useMarketData";
import { formatPrice } from "@/pages/markets/format";
import type { MarketSymbol } from "@/api/endpoints/marketData";
import {
  computePnl,
  type PnlFill,
  type PnlFunding,
  type PnlLiquidation,
} from "@/lib/pnl";
import {
  buildTradeHistoryCsv,
  buildPnlSummaryCsv,
  buildStatementCsv,
  downloadCsv,
  type ReportFill,
  type StatementLine,
  type SymbolResolver,
} from "@/lib/exportReport";
import {
  presetRange,
  customRange,
  filterByPeriod,
  periodLabel,
  periodSlug,
  PERIOD_LABELS,
  type PeriodPreset,
  type PeriodRange,
} from "@/lib/reportPeriod";
import StatementsReportsCard from "./StatementsReportsCard";

// --- helpers ----------------------------------------------------

function isUnavailable(err: unknown): boolean {
  if (err instanceof ApiError) return err.status === 404 || err.status === 403;
  const msg = (err as Error)?.message ?? "";
  return /\b40[34]\b/.test(msg);
}

const signColor = (v: number): string | undefined =>
  v > 0 ? "rgb(16 185 129)" : v < 0 ? "rgb(239 68 68)" : undefined;

const PRESETS: PeriodPreset[] = ["24h", "7d", "30d", "all", "custom"];

// --- period selector --------------------------------------------

export function PeriodSelector({
  range,
  onChange,
}: {
  range: PeriodRange;
  onChange: (r: PeriodRange) => void;
}) {
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");

  const pick = (p: PeriodPreset) => {
    if (p === "custom") onChange(customRange(from, to));
    else onChange(presetRange(p));
  };

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap gap-1.5">
        {PRESETS.map((p) => (
          <Button
            key={p}
            size="sm"
            variant={range.preset === p ? "default" : "outline"}
            onClick={() => pick(p)}
            className="h-8"
          >
            {p === "custom" ? "Custom" : PERIOD_LABELS[p].replace("Last ", "")}
          </Button>
        ))}
      </div>
      {range.preset === "custom" && (
        <div className="flex flex-wrap items-center gap-2 print:hidden">
          <Input
            type="date"
            value={from}
            onChange={(e) => setFrom(e.target.value)}
            onBlur={() => onChange(customRange(from, to))}
            className="h-8 w-[9.5rem]"
            aria-label="From date"
          />
          <span className="text-xs text-muted-foreground">to</span>
          <Input
            type="date"
            value={to}
            onChange={(e) => setTo(e.target.value)}
            onBlur={() => onChange(customRange(from, to))}
            className="h-8 w-[9.5rem]"
            aria-label="To date"
          />
        </div>
      )}
    </div>
  );
}

// --- stat card --------------------------------------------------

function StatCard({
  label,
  value,
  icon,
  valueColor,
  sub,
}: {
  label: string;
  value: string;
  icon: React.ReactNode;
  valueColor?: string;
  sub?: string;
}) {
  return (
    <Card>
      <CardContent className="flex flex-col gap-1 py-4">
        <span className="flex items-center gap-1.5 text-[11px] uppercase tracking-wide text-muted-foreground">
          {icon}
          {label}
        </span>
        <span
          className="num text-xl font-semibold tabular-nums"
          style={valueColor ? { color: valueColor } : undefined}
        >
          {value}
        </span>
        {sub && <span className="text-[11px] text-muted-foreground">{sub}</span>}
      </CardContent>
    </Card>
  );
}

// --- page -------------------------------------------------------

export default function ReportsPage() {
  const fillsQ = useFillsFees();
  const fundingQ = useFundingPayments();
  const liqQ = useLiquidations();
  const marginQ = useMarginAccount();
  const spotQ = useSpotBalance();
  const symbolsQ = useSymbols();

  const [range, setRange] = useState<PeriodRange>(() => presetRange("7d"));

  const refetchAll = () => {
    fillsQ.refetch();
    fundingQ.refetch();
    liqQ.refetch();
    marginQ.refetch();
    spotQ.refetch();
    symbolsQ.refetch();
  };

  const anyFetching =
    fillsQ.isFetching ||
    fundingQ.isFetching ||
    liqQ.isFetching ||
    marginQ.isFetching ||
    spotQ.isFetching ||
    symbolsQ.isFetching;

  // symbolid -> {name, scaler}.
  const resolve: SymbolResolver = useMemo(() => {
    const map = new Map<number, MarketSymbol>();
    for (const s of symbolsQ.data?.symbols ?? []) map.set(s.symbol_id, s);
    return (id: number) => {
      const s = map.get(id);
      return { name: s?.symbol ?? `#${id}`, scaler: s?.price_scaler || 1 };
    };
  }, [symbolsQ.data]);

  const quoteScaler = useMemo(() => symbolsQ.data?.symbols?.[0]?.price_scaler || 1, [symbolsQ.data]);

  // Raw fills, then period-scoped.
  const allFills: ReportFill[] = useMemo(
    () =>
      (fillsQ.data?.fills ?? []).map((f) => ({
        symbolid: f.symbolid,
        price: f.price,
        qty: f.qty,
        side: f.side,
        liquidity: f.liquidity,
        fee: f.fee,
        ts: f.ts,
      })),
    [fillsQ.data],
  );
  const scopedFills = useMemo(() => filterByPeriod(allFills, range), [allFills, range]);

  const scopedFunding = useMemo(
    () => filterByPeriod(fundingQ.data?.funding ?? [], range),
    [fundingQ.data, range],
  );
  const scopedLiq = useMemo(
    () => filterByPeriod(liqQ.data?.liquidations ?? [], range),
    [liqQ.data, range],
  );

  // PnL over the scoped window.
  const summary = useMemo(() => {
    const fills: PnlFill[] = scopedFills.map((f) => ({
      symbolid: f.symbolid,
      price: f.price,
      qty: f.qty,
      side: f.side === "sell" ? "sell" : "buy",
      fee: f.fee,
      ts: f.ts,
    }));
    const funding: PnlFunding[] = scopedFunding.map((f) => ({
      symbolid: f.symbolid,
      payment: f.payment,
      ts: f.ts,
    }));
    const liquidations: PnlLiquidation[] = scopedLiq.map((l) => ({
      symbolid: l.symbolid,
      realized_pnl: l.realized_pnl,
      fee: l.fee,
      ts: l.ts,
    }));
    return computePnl(fills, funding, liquidations);
  }, [scopedFills, scopedFunding, scopedLiq]);

  // Account statement snapshot lines (point-in-time balances/positions).
  const statementLines: StatementLine[] = useMemo(() => {
    const lines: StatementLine[] = [];
    for (const b of spotQ.data?.balances ?? []) {
      const s = b.asset != null ? resolve(b.asset) : { name: b.symbol ?? "—", scaler: 1 };
      const label = b.symbol ?? s.name;
      if (b.balance != null) lines.push({ section: "Spot", label, amount: b.balance, scaler: s.scaler, note: "balance" });
      if (b.available != null)
        lines.push({ section: "Spot", label, amount: b.available, scaler: s.scaler, note: "available" });
    }
    const m = marginQ.data;
    if (m) {
      if (m.balance != null) lines.push({ section: "Margin", label: "Balance", amount: m.balance, scaler: quoteScaler });
      if (m.available_balance != null)
        lines.push({ section: "Margin", label: "Available", amount: m.available_balance, scaler: quoteScaler });
      if (m.reserved_margin != null)
        lines.push({ section: "Margin", label: "Reserved margin", amount: m.reserved_margin, scaler: quoteScaler });
      if (m.pos_symbol_idx != null && m.pos_qty) {
        const sym = resolve(m.pos_symbol_idx);
        lines.push({ section: "Position", label: sym.name, amount: m.pos_qty, scaler: sym.scaler, note: "qty" });
        if (m.pos_entry_price != null)
          lines.push({ section: "Position", label: sym.name, amount: m.pos_entry_price, scaler: sym.scaler, note: "entry" });
        if (m.pos_unrealized_pnl != null)
          lines.push({
            section: "Position",
            label: sym.name,
            amount: m.pos_unrealized_pnl,
            scaler: sym.scaler,
            note: "unrealized PnL",
          });
      }
    }
    return lines;
  }, [spotQ.data, marginQ.data, quoteScaler, resolve]);

  // --- export handlers ---
  const doExportTrades = () =>
    downloadCsv(`testlogon-trades-${periodSlug(range)}.csv`, buildTradeHistoryCsv(scopedFills, resolve));
  const doExportPnl = () =>
    downloadCsv(
      `testlogon-pnl-${periodSlug(range)}.csv`,
      buildPnlSummaryCsv(summary.perSymbol, summary, resolve, quoteScaler),
    );
  const doExportStatement = () =>
    downloadCsv(
      `testlogon-statement-${periodSlug(range)}.csv`,
      buildStatementCsv(statementLines, { period: periodLabel(range) }),
    );

  const fillsUnavailable = fillsQ.isError && isUnavailable(fillsQ.error);
  const fillsError = fillsQ.isError && !fillsUnavailable;
  const loading = fillsQ.isLoading || symbolsQ.isLoading;
  const hasData = summary.tradeCount > 0;

  const netColor = signColor(summary.netRealized);
  const winPct = (summary.winRate * 100).toFixed(summary.closeCount > 0 ? 1 : 0);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between print:hidden">
        <div className="flex items-center gap-2">
          <FileSpreadsheet className="h-6 w-6 text-primary" />
          <div>
            <h1 className="text-xl font-semibold leading-tight">Export &amp; reporting</h1>
            <p className="text-xs text-muted-foreground">
              Scope a period, preview headline stats, then export CSV or print / save as PDF.
            </p>
          </div>
        </div>
        <Button variant="outline" size="sm" className="gap-2 self-start sm:self-auto" onClick={refetchAll}>
          <RefreshCw className={cn("h-4 w-4", anyFetching && "animate-spin")} />
          Refresh
        </Button>
      </div>

      {/* Controls */}
      <Card className="print:hidden">
        <CardContent className="flex flex-col gap-4 py-4 lg:flex-row lg:items-end lg:justify-between">
          <div className="flex flex-col gap-1.5">
            <span className="text-[11px] uppercase tracking-wide text-muted-foreground">Period</span>
            <PeriodSelector range={range} onChange={setRange} />
          </div>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="outline" className="gap-1.5" onClick={doExportTrades} disabled={!hasData}>
              <Download className="h-4 w-4" /> Trades CSV
            </Button>
            <Button size="sm" variant="outline" className="gap-1.5" onClick={doExportPnl} disabled={!hasData}>
              <Download className="h-4 w-4" /> PnL CSV
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="gap-1.5"
              onClick={doExportStatement}
              disabled={statementLines.length === 0}
            >
              <Download className="h-4 w-4" /> Statement CSV
            </Button>
            <Button size="sm" className="gap-1.5" onClick={() => window.print()} disabled={!hasData}>
              <Printer className="h-4 w-4" /> Print / Save PDF
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Statements & reports (FE-171) — request PDF docs + download CSVs */}
      <div className="print:hidden">
        <StatementsReportsCard
          fills={allFills}
          resolve={resolve}
          quoteScaler={quoteScaler}
          fillsUnavailable={fillsUnavailable}
        />
      </div>

      {/* Print-only report heading */}
      <div className="hidden print:block">
        <h1 className="text-2xl font-semibold">TestLogon — trading report</h1>
        <p className="text-sm text-muted-foreground">
          {periodLabel(range)} · generated {new Date().toISOString().slice(0, 19).replace("T", " ")}Z
        </p>
        <Separator className="my-3" />
      </div>

      {loading ? (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-24 w-full" />
          ))}
        </div>
      ) : fillsUnavailable ? (
        <Card>
          <CardContent className="flex flex-col items-start gap-2 py-10">
            <p className="text-sm text-muted-foreground">
              The fills feed isn't available on this backend yet, so reports can't be computed. This
              page will populate once the exchange edge deploys the account feeds.
            </p>
            <Badge variant="outline" className="gap-1.5">
              <Info className="h-3 w-3" /> Not available on this backend
            </Badge>
          </CardContent>
        </Card>
      ) : fillsError ? (
        <Card>
          <CardContent className="py-10">
            <p className="text-sm text-muted-foreground">
              Could not load your fills: {(fillsQ.error as Error)?.message ?? "unknown error"}.
            </p>
          </CardContent>
        </Card>
      ) : !hasData ? (
        <Card>
          <CardContent className="flex flex-col items-start gap-2 py-10">
            <p className="text-sm text-muted-foreground">
              No trading activity in {periodLabel(range).toLowerCase()}. Pick a wider period or place
              some trades — your headline stats and exports will appear here.
            </p>
          </CardContent>
        </Card>
      ) : (
        <>
          {/* Headline stats */}
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-3">
            <StatCard
              label="Net realized PnL"
              value={formatPrice(summary.netRealized, quoteScaler)}
              valueColor={netColor}
              icon={
                summary.netRealized >= 0 ? (
                  <TrendingUp className="h-3.5 w-3.5" />
                ) : (
                  <TrendingDown className="h-3.5 w-3.5" />
                )
              }
              sub="Realized − fees + funding ± liquidations"
            />
            <StatCard
              label="Total fees paid"
              value={formatPrice(summary.totalFees + summary.totalLiquidationFees, quoteScaler)}
              icon={<Receipt className="h-3.5 w-3.5" />}
              sub="Engine + liquidation fees"
            />
            <StatCard
              label="Win rate"
              value={`${winPct}%`}
              icon={<Target className="h-3.5 w-3.5" />}
              sub={`${summary.winCount}/${summary.closeCount} closing trades positive`}
            />
            <StatCard
              label="Trades"
              value={String(summary.tradeCount)}
              icon={<Hash className="h-3.5 w-3.5" />}
              sub={`${summary.closeCount} position closes`}
            />
            <StatCard
              label="Total volume"
              value={formatPrice(summary.totalVolume, quoteScaler)}
              icon={<BarChart2 className="h-3.5 w-3.5" />}
              sub="Traded notional (magnitude)"
            />
            <StatCard
              label="Fills in period"
              value={String(scopedFills.length)}
              icon={<FileSpreadsheet className="h-3.5 w-3.5" />}
              sub={periodLabel(range)}
            />
          </div>

          {/* Per-symbol breakdown */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-sm font-medium">
                <TrendingUp className="h-4 w-4 text-muted-foreground" />
                Per-symbol breakdown
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[560px] text-sm">
                  <thead>
                    <tr className="border-b text-left text-xs text-muted-foreground">
                      <th className="py-2 pr-3 font-medium">Symbol</th>
                      <th className="py-2 pr-3 text-right font-medium">Net PnL</th>
                      <th className="py-2 pr-3 text-right font-medium">Volume</th>
                      <th className="py-2 pr-3 text-right font-medium">Fees</th>
                      <th className="py-2 text-right font-medium">Trades</th>
                    </tr>
                  </thead>
                  <tbody>
                    {summary.perSymbol.map((s) => {
                      const sym = resolve(s.symbolid);
                      return (
                        <tr key={s.symbolid} className="border-b last:border-0">
                          <td className="py-2 pr-3 font-medium">{sym.name}</td>
                          <td
                            className="num py-2 pr-3 text-right font-medium tabular-nums"
                            style={{ color: signColor(s.net) }}
                          >
                            {formatPrice(s.net, sym.scaler)}
                          </td>
                          <td className="num py-2 pr-3 text-right tabular-nums">
                            {formatPrice(s.volume, sym.scaler * sym.scaler)}
                          </td>
                          <td className="num py-2 pr-3 text-right tabular-nums">
                            {formatPrice(s.fees + s.liquidationFees, sym.scaler)}
                          </td>
                          <td className="num py-2 text-right tabular-nums">{s.tradeCount}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>

          {/* Account statement snapshot */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-sm font-medium">
                <Receipt className="h-4 w-4 text-muted-foreground" />
                Account statement (snapshot)
              </CardTitle>
            </CardHeader>
            <CardContent>
              {statementLines.length === 0 ? (
                <p className="py-4 text-sm text-muted-foreground">
                  No balance or position data available in this session.
                </p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[420px] text-sm">
                    <thead>
                      <tr className="border-b text-left text-xs text-muted-foreground">
                        <th className="py-2 pr-3 font-medium">Section</th>
                        <th className="py-2 pr-3 font-medium">Account / Asset</th>
                        <th className="py-2 pr-3 text-right font-medium">Amount</th>
                        <th className="py-2 font-medium">Note</th>
                      </tr>
                    </thead>
                    <tbody>
                      {statementLines.map((l, i) => (
                        <tr key={`${l.section}:${l.label}:${l.note ?? ""}:${i}`} className="border-b last:border-0">
                          <td className="py-2 pr-3">{l.section}</td>
                          <td className="py-2 pr-3 font-medium">{l.label}</td>
                          <td className="num py-2 pr-3 text-right tabular-nums">
                            {formatPrice(l.amount, l.scaler)}
                          </td>
                          <td className="py-2 text-muted-foreground">{l.note ?? ""}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <Separator className="my-3" />
              <p className="text-[11px] text-muted-foreground">
                A point-in-time snapshot of your spot + margin balances and open position. Engine int64
                ticks scaled per symbol.
              </p>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
