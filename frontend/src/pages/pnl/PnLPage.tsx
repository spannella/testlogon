// PnL & performance — a READ-ONLY analytics view computed CLIENT-SIDE from the
// exchange account feeds (fills-fees / funding / liquidations) via the pure
// `computePnl` helper. NO new backend: it reuses the existing typed feed hooks,
// and each feed DEGRADES INDEPENDENTLY — if the fills feed 404s (edge-undeployed)
// the page shows an honest "unavailable" state; a missing funding/liquidation
// feed just contributes nothing. Unrealized PnL comes from the margin account.
// All engine values are int64 ticks scaled for display by the symbol scaler.
import { useMemo } from "react";
import {
  LineChart,
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

import {
  useFillsFees,
  useLiquidations,
  useFundingPayments,
  useMarginAccount,
} from "@/hooks/useTrading";
import { useSymbols } from "@/hooks/useMarketData";
import { formatPrice, formatQty } from "@/pages/markets/format";
import type { MarketSymbol } from "@/api/endpoints/marketData";
import {
  computePnl,
  type PnlFill,
  type PnlFunding,
  type PnlLiquidation,
  type EquityPoint,
} from "@/lib/pnl";

// --- helpers ----------------------------------------------------

function num(v: number | undefined | null): number {
  if (v == null) return 0;
  return Number.isFinite(v) ? v : 0;
}

/** True when an error is a 404/403 — the "not available on this backend" case. */
function isUnavailable(err: unknown): boolean {
  if (err instanceof ApiError) return err.status === 404 || err.status === 403;
  const msg = (err as Error)?.message ?? "";
  return /\b40[34]\b/.test(msg);
}

const signColor = (v: number): string | undefined =>
  v > 0
    ? "rgb(16 185 129)" // emerald-500
    : v < 0
      ? "rgb(239 68 68)" // red-500
      : undefined;

// --- inline SVG equity curve ------------------------------------

function EquityCurve({ points }: { points: EquityPoint[] }) {
  const W = 640;
  const H = 160;
  const PAD = 6;

  const path = useMemo(() => {
    if (points.length === 0) return null;
    const xs = points.map((p) => p.ts);
    const ys = points.map((p) => p.value);
    // Include a 0 baseline so the sign is visually meaningful.
    const minY = Math.min(0, ...ys);
    const maxY = Math.max(0, ...ys);
    const minX = Math.min(...xs);
    const maxX = Math.max(...xs);
    const spanY = maxY - minY || 1;
    const spanX = maxX - minX || 1;

    const sx = (t: number) => PAD + ((t - minX) / spanX) * (W - 2 * PAD);
    const sy = (v: number) => H - PAD - ((v - minY) / spanY) * (H - 2 * PAD);

    const firstVal = ys[0] ?? 0;
    const pts: { x: number; y: number }[] =
      points.length === 1
        ? [
            { x: PAD, y: sy(firstVal) },
            { x: W - PAD, y: sy(firstVal) },
          ]
        : points.map((p) => ({ x: sx(p.ts), y: sy(p.value) }));

    const line = pts.map((p, i) => `${i === 0 ? "M" : "L"} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(" ");
    const start = pts[0]!;
    const end = pts[pts.length - 1]!;
    const area = `${line} L ${end.x.toFixed(1)} ${H - PAD} L ${start.x.toFixed(1)} ${H - PAD} Z`;
    const zeroY = sy(0);
    const last = ys[ys.length - 1] ?? 0;
    return { line, area, zeroY, last };
  }, [points]);

  if (!path) return null;
  const up = path.last >= 0;
  const stroke = up ? "rgb(16 185 129)" : "rgb(239 68 68)";

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      className="h-40 w-full"
      preserveAspectRatio="none"
      role="img"
      aria-label="Cumulative equity curve"
    >
      <defs>
        <linearGradient id="pnl-eq-fill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={stroke} stopOpacity="0.28" />
          <stop offset="100%" stopColor={stroke} stopOpacity="0" />
        </linearGradient>
      </defs>
      {/* zero baseline */}
      <line
        x1={PAD}
        x2={W - PAD}
        y1={path.zeroY}
        y2={path.zeroY}
        stroke="currentColor"
        strokeOpacity="0.18"
        strokeDasharray="4 4"
      />
      <path d={path.area} fill="url(#pnl-eq-fill)" stroke="none" />
      <path d={path.line} fill="none" stroke={stroke} strokeWidth="1.75" vectorEffect="non-scaling-stroke" />
    </svg>
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

export default function PnLPage() {
  const fillsQ = useFillsFees();
  const fundingQ = useFundingPayments();
  const liqQ = useLiquidations();
  const marginQ = useMarginAccount();
  const symbolsQ = useSymbols();

  const refetchAll = () => {
    fillsQ.refetch();
    fundingQ.refetch();
    liqQ.refetch();
    marginQ.refetch();
    symbolsQ.refetch();
  };

  const anyFetching =
    fillsQ.isFetching ||
    fundingQ.isFetching ||
    liqQ.isFetching ||
    marginQ.isFetching ||
    symbolsQ.isFetching;

  // symbolid -> {name, scaler}. Fills/funding/liq all key off the same symbolid.
  const symLookup = useMemo(() => {
    const map = new Map<number, MarketSymbol>();
    for (const s of symbolsQ.data?.symbols ?? []) map.set(s.symbol_id, s);
    return (id: number) => {
      const s = map.get(id);
      return { name: s?.symbol ?? `#${id}`, scaler: s?.price_scaler || 1 };
    };
  }, [symbolsQ.data]);

  // A single scaler for the aggregate (tick) totals. The feeds share one quote
  // asset so any traded symbol's price scaler is representative; fall back to 1.
  const quoteScaler = useMemo(() => {
    const first = symbolsQ.data?.symbols?.[0];
    return first?.price_scaler || 1;
  }, [symbolsQ.data]);

  const summary = useMemo(() => {
    const fills: PnlFill[] = (fillsQ.data?.fills ?? []).map((f) => ({
      symbolid: f.symbolid,
      price: f.price,
      qty: f.qty,
      side: f.side,
      fee: f.fee,
      ts: f.ts,
    }));
    const funding: PnlFunding[] = (fundingQ.data?.funding ?? []).map((f) => ({
      symbolid: f.symbolid,
      payment: f.payment,
      ts: f.ts,
    }));
    const liquidations: PnlLiquidation[] = (liqQ.data?.liquidations ?? []).map((l) => ({
      symbolid: l.symbolid,
      realized_pnl: l.realized_pnl,
      fee: l.fee,
      ts: l.ts,
    }));
    return computePnl(fills, funding, liquidations);
  }, [fillsQ.data, fundingQ.data, liqQ.data]);

  const unrealized = num(marginQ.data?.pos_unrealized_pnl);
  const unrealizedScaler = marginQ.data?.pos_symbol_idx != null
    ? symLookup(marginQ.data.pos_symbol_idx).scaler
    : quoteScaler;

  // The fills feed is the analytics backbone: if it's unavailable, the whole page
  // can't compute — show a single honest unavailable state.
  const fillsUnavailable = fillsQ.isError && isUnavailable(fillsQ.error);
  const fillsError = fillsQ.isError && !fillsUnavailable;
  const loading = fillsQ.isLoading || symbolsQ.isLoading;

  const netColor = signColor(summary.netRealized);
  const winPct = (summary.winRate * 100).toFixed(summary.closeCount > 0 ? 1 : 0);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2">
          <LineChart className="h-6 w-6 text-primary" />
          <div>
            <h1 className="text-xl font-semibold leading-tight">PnL &amp; performance</h1>
            <p className="text-xs text-muted-foreground">
              Realized PnL, fees, funding &amp; win rate — computed from your fills.
            </p>
          </div>
        </div>
        <Button variant="outline" size="sm" className="gap-2 self-start sm:self-auto" onClick={refetchAll}>
          <RefreshCw className={cn("h-4 w-4", anyFetching && "animate-spin")} />
          Refresh
        </Button>
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
              The fills feed isn't available on this backend yet, so performance analytics can't be
              computed. This page will populate once the exchange edge deploys the account feeds.
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
      ) : summary.tradeCount === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-start gap-2 py-10">
            <p className="text-sm text-muted-foreground">
              No trading activity yet. Once you have fills, your realized PnL, equity curve and win
              rate will appear here.
            </p>
          </CardContent>
        </Card>
      ) : (
        <>
          {/* Stat cards */}
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
              label="Unrealized PnL"
              value={
                marginQ.isError
                  ? "—"
                  : formatPrice(unrealized, unrealizedScaler)
              }
              valueColor={signColor(unrealized)}
              icon={<BarChart2 className="h-3.5 w-3.5" />}
              sub={marginQ.isError ? "Margin account unavailable" : "Open position (margin)"}
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
          </div>

          {/* Equity curve */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-sm font-medium">
                <LineChart className="h-4 w-4 text-muted-foreground" />
                Equity curve
                {(fundingQ.isError || liqQ.isError) && (
                  <Badge variant="outline" className="gap-1 text-[10px] font-normal">
                    <Info className="h-3 w-3" />
                    {fundingQ.isError && liqQ.isError
                      ? "funding & liquidations unavailable"
                      : fundingQ.isError
                        ? "funding unavailable"
                        : "liquidations unavailable"}
                  </Badge>
                )}
              </CardTitle>
            </CardHeader>
            <CardContent>
              {summary.equityCurve.length === 0 ? (
                <p className="py-8 text-center text-sm text-muted-foreground">
                  Not enough events to plot an equity curve.
                </p>
              ) : (
                <div className="text-muted-foreground">
                  <EquityCurve points={summary.equityCurve} />
                  <Separator className="my-3" />
                  <p className="text-[11px]">
                    Cumulative realized + funding − fees across{" "}
                    {summary.equityCurve.length} event
                    {summary.equityCurve.length === 1 ? "" : "s"}, oldest → newest. Values are engine
                    ticks scaled by the quote scaler.
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

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
                      const sym = symLookup(s.symbolid);
                      const net = s.net;
                      return (
                        <tr key={s.symbolid} className="border-b last:border-0">
                          <td className="py-2 pr-3 font-medium">{sym.name}</td>
                          <td
                            className="num py-2 pr-3 text-right font-medium tabular-nums"
                            style={{ color: signColor(net) }}
                          >
                            {formatPrice(net, sym.scaler)}
                          </td>
                          <td className="num py-2 pr-3 text-right tabular-nums">
                            {formatQty(s.volume, sym.scaler)}
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
                <Separator className="my-3" />
                <p className="text-[11px] text-muted-foreground">
                  Net PnL = average-cost realized − fees + funding ± liquidations, per symbol. All
                  values are engine int64 ticks scaled by the symbol's price scaler.
                </p>
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
