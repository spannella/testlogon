// Portfolio — a READ-ONLY consolidated overview aggregating the caller's
// holdings across every venue the account touches: custody vault balances,
// custody staking positions, trading spot balances, and the margin account
// (balance / available / reserved) with its open position. NO new backend —
// every card reuses an existing typed endpoint and DEGRADES INDEPENDENTLY:
// if one source 404s / 403s (edge-undeployed or custody-gated) that card shows
// an "unavailable" state while the rest still render. All reads, no mutations.
import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  PieChart,
  RefreshCw,
  Vault,
  Coins,
  Sprout,
  Landmark,
  TrendingUp,
  Info,
  Loader2,
} from "lucide-react";
import { ApiError } from "@/api/client";
import { cn } from "@/lib/utils";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";

import {
  getBalance,
  getStakingPositions,
  mergeBalances,
  type StakingPosition,
} from "@/api/endpoints/custody";
import {
  getSpotBalance,
  getMarginAccount,
  getPrices,
  type MarginAccount,
} from "@/api/endpoints/trading";
import { getSymbols, type MarketSymbol } from "@/api/endpoints/marketData";
import { formatPrice, formatQty } from "@/pages/markets/format";
import { usePaperMode } from "@/lib/paperMode";
import { buildPnlSummaryFromPaper } from "@/lib/paperBlotter";
import { usePaperAccount, usePaperMarks } from "@/hooks/usePaperMarks";

// --- helpers ----------------------------------------------------

function useIsMobile(bp = 767): boolean {
  const [m, setM] = useState(
    () =>
      typeof window !== "undefined" &&
      window.matchMedia(`(max-width: ${bp}px)`).matches,
  );
  useEffect(() => {
    const mq = window.matchMedia(`(max-width: ${bp}px)`);
    const h = () => setM(mq.matches);
    mq.addEventListener("change", h);
    return () => mq.removeEventListener("change", h);
  }, [bp]);
  return m;
}

function num(v: string | number | undefined | null): number {
  if (v == null) return 0;
  const n = typeof v === "number" ? v : parseFloat(v);
  return Number.isFinite(n) ? n : 0;
}

function fmtAmount(v: string | number | undefined | null): string {
  const n = num(v);
  if (n === 0) return "0";
  return n.toLocaleString(undefined, { maximumFractionDigits: 8 });
}

/** Format a USD value like "$1,234.56". */
function fmtUsd(n: number): string {
  return `$${n.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

/** Small muted USD sub-value shown next to an asset amount when a price exists. */
function UsdSub({ usd }: { usd: number | undefined }) {
  if (usd == null) return null;
  return (
    <span className="ml-2 text-[11px] text-muted-foreground tabular-nums">≈ {fmtUsd(usd)}</span>
  );
}

/** True when an error is a 404/403 — the "not available on this backend" case. */
function isUnavailable(err: unknown): boolean {
  if (err instanceof ApiError) return err.status === 404 || err.status === 403;
  const msg = (err as Error)?.message ?? "";
  return /\b40[34]\b/.test(msg);
}

function errLine(err: unknown, gated: string): string {
  if (isUnavailable(err)) return gated;
  const msg = (err as Error)?.message;
  return msg ? `Could not load: ${msg}` : "Could not load this source.";
}

const signColor = (v: number): string | undefined =>
  v > 0
    ? "rgb(16 185 129)" // emerald-500
    : v < 0
      ? "rgb(239 68 68)" // red-500
      : undefined;

// --- small building blocks --------------------------------------

function VenueCard({
  title,
  icon,
  refetch,
  isFetching,
  children,
}: {
  title: string;
  icon: React.ReactNode;
  refetch?: () => void;
  isFetching?: boolean;
  children: React.ReactNode;
}) {
  return (
    <Card className="flex flex-col">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm font-medium">
          {icon}
          {title}
        </CardTitle>
        {refetch && (
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7"
            onClick={() => refetch()}
            aria-label={`Refresh ${title}`}
          >
            <RefreshCw className={cn("h-3.5 w-3.5", isFetching && "animate-spin")} />
          </Button>
        )}
      </CardHeader>
      <CardContent className="flex-1 text-sm">{children}</CardContent>
    </Card>
  );
}

function Unavailable({ line }: { line: string }) {
  return (
    <div className="flex flex-col items-start gap-2 py-4">
      <p className="text-sm text-muted-foreground">{line}</p>
      <Badge variant="outline" className="gap-1.5">
        <Info className="h-3 w-3" /> Not available on this backend
      </Badge>
    </div>
  );
}

function RowsSkeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div className="space-y-2 py-1">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center justify-between">
          <Skeleton className="h-4 w-20" />
          <Skeleton className="h-4 w-24" />
        </div>
      ))}
    </div>
  );
}

function KV({ label, value, valueColor }: { label: string; value: string; valueColor?: string }) {
  return (
    <div className="flex items-center justify-between gap-3 py-1">
      <span className="text-muted-foreground">{label}</span>
      <span className="num font-medium tabular-nums" style={valueColor ? { color: valueColor } : undefined}>
        {value}
      </span>
    </div>
  );
}

// --- page -------------------------------------------------------

export default function PortfolioPage() {
  useIsMobile(767); // responsive grid is CSS-driven; hook kept for parity/future use

  const { enabled: paper } = usePaperMode();
  const paperAcct = usePaperAccount(paper);
  const { marks: paperMarks, symName: paperSymName } = usePaperMarks(paperAcct, paper);
  const paperSummary = useMemo(
    () => buildPnlSummaryFromPaper(paperAcct, paperMarks, paperSymName),
    [paperAcct, paperMarks, paperSymName],
  );
  const custodyQ = useQuery({
    queryKey: ["portfolio", "custody", "balance"],
    queryFn: getBalance,
    retry: false,
  });
  const stakingQ = useQuery({
    queryKey: ["portfolio", "staking", "positions"],
    queryFn: getStakingPositions,
    retry: false,
  });
  const spotQ = useQuery({
    queryKey: ["portfolio", "spot", "balance"],
    queryFn: getSpotBalance,
    retry: false,
  });
  const marginQ = useQuery({
    queryKey: ["portfolio", "margin", "account"],
    queryFn: getMarginAccount,
    retry: false,
  });
  const symbolsQ = useQuery({
    queryKey: ["portfolio", "md", "symbols"],
    queryFn: getSymbols,
    retry: false,
  });
  // USD valuation marks — STUB today; degrades on 404 (retry:false) so the total
  // falls back to a source-native (un-converted) sum.
  const pricesQ = useQuery({
    queryKey: ["portfolio", "me", "prices"],
    queryFn: getPrices,
    retry: false,
  });

  const refetchAll = () => {
    custodyQ.refetch();
    stakingQ.refetch();
    spotQ.refetch();
    marginQ.refetch();
    symbolsQ.refetch();
    pricesQ.refetch();
  };

  const anyFetching =
    custodyQ.isFetching ||
    stakingQ.isFetching ||
    spotQ.isFetching ||
    marginQ.isFetching ||
    symbolsQ.isFetching ||
    pricesQ.isFetching;

  // -- derived aggregates --
  const custodyRows = useMemo(
    () => mergeBalances(custodyQ.data?.balances).filter((r) => num(r.balance) !== 0),
    [custodyQ.data],
  );

  const stakingTotals = useMemo(() => {
    const positions: StakingPosition[] = stakingQ.data?.positions ?? [];
    let principal = 0;
    let rewards = 0;
    let total = 0;
    for (const p of positions) {
      principal += num(p.principal);
      rewards += num(p.rewards);
      total += num(p.total);
    }
    return { positions, principal, rewards, total };
  }, [stakingQ.data]);

  const spotRows = useMemo(
    () =>
      (spotQ.data?.balances ?? []).filter(
        (b) => num(b.balance) !== 0 || num(b.available) !== 0,
      ),
    [spotQ.data],
  );

  const margin: MarginAccount | undefined = marginQ.data;

  // symbolid -> {name, scaler} for the open position row
  const symLookup = useMemo(() => {
    const map = new Map<number, MarketSymbol>();
    for (const s of symbolsQ.data?.symbols ?? []) map.set(s.symbol_id, s);
    return (id: number | undefined) => {
      const s = id != null ? map.get(id) : undefined;
      return { name: s?.symbol ?? (id != null ? `#${id}` : "—"), scaler: s?.price_scaler || 1 };
    };
  }, [symbolsQ.data]);

  // USD price marks keyed by asset symbol (case-insensitive). Returns undefined
  // when no mark exists for the asset — callers then skip USD conversion for it.
  const priceOf = useMemo(() => {
    const map = new Map<string, number>();
    for (const [sym, px] of Object.entries(pricesQ.data?.prices ?? {})) {
      const n = num(px);
      if (Number.isFinite(n) && n > 0) map.set(sym.toUpperCase(), n);
    }
    return (symbol: string | undefined | null): number | undefined => {
      if (!symbol) return undefined;
      return map.get(String(symbol).toUpperCase());
    };
  }, [pricesQ.data]);

  const pricesOk = pricesQ.isSuccess;
  const pricesStub = pricesOk && (pricesQ.data?.stub === true || pricesQ.data?.source === "stub");
  const pricesUnavailable = pricesQ.isError; // 404 / edge-undeployed

  const hasPosition = !!margin && num(margin.num_positions) > 0 && num(margin.pos_qty) !== 0;

  // Cross-venue equity. When USD price marks are readable we FX-normalize every
  // readable balance (amount * asset USD price) into a REAL USD total equity,
  // summing only assets that HAVE a mark (others are excluded from the USD sum).
  // When /me/prices 404s (edge-undeployed) we fall back to the prior source-native
  // raw sum (no FX conversion). `usd` distinguishes the two modes for the label.
  const equity = useMemo(() => {
    // Source-native raw sum (the historical fallback — no FX conversion).
    let raw = 0;
    let sources = 0;
    if (custodyQ.isSuccess) {
      raw += custodyRows.reduce((a, r) => a + num(r.balance), 0);
      sources++;
    }
    if (spotQ.isSuccess) {
      raw += spotRows.reduce((a, b) => a + num(b.balance), 0);
      sources++;
    }
    if (marginQ.isSuccess) {
      raw += num(margin?.balance);
      sources++;
    }
    if (stakingQ.isSuccess) {
      raw += stakingTotals.total;
      sources++;
    }

    if (!pricesOk) {
      // No USD marks — degrade to the source-native raw sum.
      return { sum: raw, sources, usd: false, valued: 0, unpriced: 0 };
    }

    // USD-normalized total: sum amount * USD price for every asset with a mark.
    let usdSum = 0;
    let valued = 0; // assets contributing a USD value
    let unpriced = 0; // readable balances with no USD mark (excluded)

    const addAsset = (symbol: string | undefined | null, amount: number) => {
      if (amount === 0) return;
      const px = priceOf(symbol);
      if (px == null) {
        unpriced++;
        return;
      }
      usdSum += amount * px;
      valued++;
    };

    if (custodyQ.isSuccess) {
      for (const r of custodyRows) addAsset(r.symbol, num(r.balance));
    }
    if (spotQ.isSuccess) {
      for (const b of spotRows) addAsset(b.symbol, num(b.balance));
    }
    if (marginQ.isSuccess) {
      // Margin collateral balance is denominated in the quote currency (USD);
      // count it directly toward the USD total.
      const mb = num(margin?.balance);
      if (mb !== 0) {
        usdSum += mb;
        valued++;
      }
    }
    if (stakingQ.isSuccess) {
      for (const pos of stakingTotals.positions) addAsset(pos.asset, num(pos.total));
    }

    return { sum: usdSum, sources, usd: true, valued, unpriced };
  }, [
    custodyQ.isSuccess,
    spotQ.isSuccess,
    marginQ.isSuccess,
    stakingQ.isSuccess,
    custodyRows,
    spotRows,
    margin,
    stakingTotals.total,
    stakingTotals.positions,
    pricesOk,
    priceOf,
  ]);

  const anyLoading =
    custodyQ.isLoading || spotQ.isLoading || marginQ.isLoading || stakingQ.isLoading;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2">
          <PieChart className="h-6 w-6 text-primary" />
          <div>
            <h1 className="flex items-center gap-2 text-xl font-semibold leading-tight">
            Portfolio
            {paper && <Badge variant="secondary">PAPER</Badge>}
          </h1>
            <p className="text-xs text-muted-foreground">
              {paper
                ? "Simulated paper account — positions, cash & equity at live marks."
                : "Read-only overview across custody, trading, margin & staking."}
            </p>
          </div>
        </div>
        <Button variant="outline" size="sm" className="gap-2 self-start sm:self-auto" onClick={refetchAll}>
          <RefreshCw className={cn("h-4 w-4", anyFetching && "animate-spin")} />
          Refresh
        </Button>
      </div>

      {paper ? (
        <>
          <Card>
            <CardContent className="flex flex-col gap-1 py-6">
              <span className="flex items-center gap-2 text-xs uppercase tracking-wide text-muted-foreground">
                Paper equity — simulated
              </span>
              <div className="flex items-baseline gap-2">
                <span className="num text-3xl font-bold tabular-nums">{formatPrice(paperSummary.equity, 1)}</span>
              </div>
              <span className="text-[11px] text-muted-foreground">
                Cash {formatPrice(paperSummary.cash, 1)} + open positions at live marks. Return{" "}
                <span style={{ color: signColor(paperSummary.returnPct) }}>
                  {paperSummary.returnPct >= 0 ? "+" : ""}{paperSummary.returnPct.toFixed(2)}%
                </span>{" "}vs {formatPrice(paperSummary.startingCash, 1)} seed. No real funds.
              </span>
            </CardContent>
          </Card>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <Card><CardContent className="flex flex-col gap-1 py-4">
              <span className="text-[11px] uppercase tracking-wide text-muted-foreground">Cash</span>
              <span className="num text-xl font-semibold tabular-nums">{formatPrice(paperSummary.cash, 1)}</span>
            </CardContent></Card>
            <Card><CardContent className="flex flex-col gap-1 py-4">
              <span className="text-[11px] uppercase tracking-wide text-muted-foreground">Realized PnL</span>
              <span className="num text-xl font-semibold tabular-nums" style={{ color: signColor(paperSummary.realized) }}>{formatPrice(paperSummary.realized, 1)}</span>
            </CardContent></Card>
            <Card><CardContent className="flex flex-col gap-1 py-4">
              <span className="text-[11px] uppercase tracking-wide text-muted-foreground">Unrealized PnL</span>
              <span className="num text-xl font-semibold tabular-nums" style={{ color: signColor(paperSummary.unrealized) }}>{formatPrice(paperSummary.unrealized, 1)}</span>
            </CardContent></Card>
          </div>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-sm font-medium">
                <TrendingUp className="h-4 w-4 text-muted-foreground" />
                Paper positions
              </CardTitle>
            </CardHeader>
            <CardContent>
              {paperSummary.perSymbol.length === 0 ? (
                <p className="py-4 text-sm text-muted-foreground">No open paper positions.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[560px] text-sm">
                    <thead>
                      <tr className="border-b text-left text-xs text-muted-foreground">
                        <th className="py-2 pr-3 font-medium">Symbol</th>
                        <th className="py-2 pr-3 text-right font-medium">Side</th>
                        <th className="py-2 pr-3 text-right font-medium">Qty</th>
                        <th className="py-2 pr-3 text-right font-medium">Avg entry</th>
                        <th className="py-2 pr-3 text-right font-medium">Mark</th>
                        <th className="py-2 text-right font-medium">Unrealized PnL</th>
                      </tr>
                    </thead>
                    <tbody>
                      {paperSummary.perSymbol.map((p) => (
                        <tr key={p.symbolId} className="border-b last:border-0">
                          <td className="py-2 pr-3 font-medium">{p.sym}</td>
                          <td className="py-2 pr-3 text-right">{p.side}</td>
                          <td className="num py-2 pr-3 text-right tabular-nums">{formatQty(Math.abs(p.netQty), 1)}</td>
                          <td className="num py-2 pr-3 text-right tabular-nums">{formatPrice(p.avgCost, 1)}</td>
                          <td className="num py-2 pr-3 text-right tabular-nums">{p.markPx != null ? formatPrice(p.markPx, 1) : "\u2014"}</td>
                          <td className="num py-2 text-right font-medium tabular-nums" style={{ color: signColor(p.unrealized) }}>{formatPrice(p.unrealized, 1)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <Separator className="my-3" />
                  <p className="text-[11px] text-muted-foreground">
                    Simulated positions from your isolated paper account. Unrealized is marked to
                    the live market price for each held symbol — no real funds.
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </>
      ) : (
      <>
      {/* Total equity */}
      <Card>
        <CardContent className="flex flex-col gap-1 py-6">
          <span className="flex items-center gap-2 text-xs uppercase tracking-wide text-muted-foreground">
            Total equity — cross-venue{equity.usd ? " (USD)" : " snapshot"}
            {equity.usd && pricesStub && (
              <Badge variant="outline" className="gap-1 text-[10px] font-normal normal-case">
                <Info className="h-3 w-3" /> indicative (stub prices)
              </Badge>
            )}
          </span>
          {anyLoading ? (
            <Skeleton className="h-9 w-48" />
          ) : (
            <div className="flex items-baseline gap-2">
              {equity.usd && <span className="text-2xl font-semibold text-muted-foreground">$</span>}
              <span className="num text-3xl font-bold tabular-nums">
                {equity.sum.toLocaleString(undefined, {
                  minimumFractionDigits: equity.usd ? 2 : 0,
                  maximumFractionDigits: equity.usd ? 2 : 8,
                })}
              </span>
              {anyFetching && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
            </div>
          )}
          <span className="text-[11px] text-muted-foreground">
            {equity.usd ? (
              <>
                {pricesStub ? "Indicative " : "Real "}USD valuation ({equity.valued} priced asset
                {equity.valued === 1 ? "" : "s"}
                {equity.unpriced > 0
                  ? `, ${equity.unpriced} unpriced balance${equity.unpriced === 1 ? "" : "s"} excluded`
                  : ""}
                ) across {equity.sources} of 4 venue{equity.sources === 1 ? "" : "s"}
                {pricesStub
                  ? " — stub prices, not a live mark."
                  : "."}
                {" "}Unavailable sources are excluded.
              </>
            ) : (
              <>
                {pricesUnavailable ? "USD valuation unavailable on this backend — a" : "A"}pproximate
                raw sum of readable balances from {equity.sources} of 4 venue
                {equity.sources === 1 ? "" : "s"} — assets are NOT FX/price-converted; unavailable
                sources are excluded.
              </>
            )}
          </span>
        </CardContent>
      </Card>

      {/* Per-venue breakdown */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        {/* Custody vault */}
        <VenueCard
          title="Custody vault"
          icon={<Vault className="h-4 w-4 text-muted-foreground" />}
          refetch={custodyQ.refetch}
          isFetching={custodyQ.isFetching}
        >
          {custodyQ.isLoading ? (
            <RowsSkeleton />
          ) : custodyQ.isError ? (
            <Unavailable line={errLine(custodyQ.error, "Custody isn't enabled for this account or the edge isn't deployed here.")} />
          ) : custodyRows.length === 0 ? (
            <p className="py-4 text-sm text-muted-foreground">No vault balances.</p>
          ) : (
            <div className="divide-y divide-border/60">
              {custodyRows.map((r) => {
                const px = priceOf(r.symbol);
                const usd = px != null ? num(r.balance) * px : undefined;
                return (
                  <div key={r.symbol} className="flex items-center justify-between gap-3 py-1">
                    <span className="text-muted-foreground">{r.symbol}</span>
                    <span className="text-right">
                      <span className="num font-medium tabular-nums">{fmtAmount(r.balance)}</span>
                      <UsdSub usd={usd} />
                    </span>
                  </div>
                );
              })}
            </div>
          )}
          {custodyQ.data?.vault && (
            <p className="mt-3 truncate text-[11px] text-muted-foreground" title={custodyQ.data.vault}>
              Vault {custodyQ.data.vault} · tier {custodyQ.data.tier}
            </p>
          )}
        </VenueCard>

        {/* Trading spot */}
        <VenueCard
          title="Trading spot"
          icon={<Coins className="h-4 w-4 text-muted-foreground" />}
          refetch={spotQ.refetch}
          isFetching={spotQ.isFetching}
        >
          {spotQ.isLoading ? (
            <RowsSkeleton />
          ) : spotQ.isError ? (
            <Unavailable line={errLine(spotQ.error, "Spot balances aren't available on this backend yet.")} />
          ) : spotRows.length === 0 ? (
            <p className="py-4 text-sm text-muted-foreground">No spot balances.</p>
          ) : (
            <div className="divide-y divide-border/60">
              {spotRows.map((b, i) => {
                const px = priceOf(b.symbol);
                const usd = px != null ? num(b.balance) * px : undefined;
                return (
                  <div key={b.symbol ?? b.asset ?? i} className="flex items-center justify-between gap-3 py-1">
                    <span className="text-muted-foreground">{b.symbol ?? `asset ${b.asset ?? "?"}`}</span>
                    <span className="text-right">
                      <span className="num font-medium tabular-nums">{fmtAmount(b.balance)}</span>
                      <UsdSub usd={usd} />
                      {b.available != null && (
                        <span className="ml-2 text-[11px] text-muted-foreground">
                          ({fmtAmount(b.available)} avail)
                        </span>
                      )}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </VenueCard>

        {/* Margin account */}
        <VenueCard
          title="Margin account"
          icon={<Landmark className="h-4 w-4 text-muted-foreground" />}
          refetch={marginQ.refetch}
          isFetching={marginQ.isFetching}
        >
          {marginQ.isLoading ? (
            <RowsSkeleton />
          ) : marginQ.isError ? (
            <Unavailable line={errLine(marginQ.error, "The margin account isn't available on this backend yet.")} />
          ) : (
            <div className="divide-y divide-border/60">
              <div className="flex items-center justify-between gap-3 py-1">
                <span className="text-muted-foreground">Balance</span>
                <span className="text-right">
                  <span className="num font-medium tabular-nums">{fmtAmount(margin?.balance)}</span>
                  <UsdSub usd={pricesOk && num(margin?.balance) !== 0 ? num(margin?.balance) : undefined} />
                </span>
              </div>
              <KV label="Available" value={fmtAmount(margin?.available_balance)} />
              <KV label="Reserved margin" value={fmtAmount(margin?.reserved_margin)} />
              <KV label="Open positions" value={String(num(margin?.num_positions))} />
              {num(margin?.is_liquidating) > 0 && (
                <div className="pt-2">
                  <Badge variant="outline" className="border-red-500/40 text-red-600 dark:text-red-400">
                    Liquidating
                  </Badge>
                </div>
              )}
            </div>
          )}
        </VenueCard>

        {/* Staking */}
        <VenueCard
          title="Staking"
          icon={<Sprout className="h-4 w-4 text-muted-foreground" />}
          refetch={stakingQ.refetch}
          isFetching={stakingQ.isFetching}
        >
          {stakingQ.isLoading ? (
            <RowsSkeleton />
          ) : stakingQ.isError ? (
            <Unavailable line={errLine(stakingQ.error, "Staking isn't enabled for this account or the edge isn't deployed here.")} />
          ) : stakingTotals.positions.length === 0 ? (
            <p className="py-4 text-sm text-muted-foreground">No staking positions.</p>
          ) : (
            <div className="divide-y divide-border/60">
              {(() => {
                let usd = 0;
                let priced = 0;
                for (const pos of stakingTotals.positions) {
                  const px = priceOf(pos.asset);
                  if (px != null) {
                    usd += num(pos.total) * px;
                    priced++;
                  }
                }
                return (
                  <div className="flex items-center justify-between gap-3 py-1">
                    <span className="text-muted-foreground">Total staked</span>
                    <span className="text-right">
                      <span className="num font-medium tabular-nums">
                        {fmtAmount(stakingTotals.total)}
                      </span>
                      <UsdSub usd={priced > 0 ? usd : undefined} />
                    </span>
                  </div>
                );
              })()}
              <KV label="Principal" value={fmtAmount(stakingTotals.principal)} />
              <KV
                label="Rewards"
                value={fmtAmount(stakingTotals.rewards)}
                valueColor={stakingTotals.rewards > 0 ? signColor(1) : undefined}
              />
              <KV label="Positions" value={String(stakingTotals.positions.length)} />
            </div>
          )}
        </VenueCard>
      </div>

      {/* Open positions (margin) */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm font-medium">
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
            Open positions
          </CardTitle>
        </CardHeader>
        <CardContent>
          {marginQ.isLoading ? (
            <RowsSkeleton rows={2} />
          ) : marginQ.isError ? (
            <Unavailable line={errLine(marginQ.error, "The margin account isn't available on this backend yet.")} />
          ) : !hasPosition ? (
            <p className="py-4 text-sm text-muted-foreground">No open positions.</p>
          ) : (
            (() => {
              const sym = symLookup(margin?.pos_symbol_idx);
              const pnl = num(margin?.pos_unrealized_pnl);
              return (
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[560px] text-sm">
                    <thead>
                      <tr className="border-b text-left text-xs text-muted-foreground">
                        <th className="py-2 pr-3 font-medium">Symbol</th>
                        <th className="py-2 pr-3 text-right font-medium">Qty</th>
                        <th className="py-2 pr-3 text-right font-medium">Entry</th>
                        <th className="py-2 pr-3 text-right font-medium">Liq. price</th>
                        <th className="py-2 text-right font-medium">Unrealized PnL</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr className="border-b last:border-0">
                        <td className="py-2 pr-3 font-medium">{sym.name}</td>
                        <td className="num py-2 pr-3 text-right tabular-nums">
                          {formatQty(num(margin?.pos_qty), sym.scaler)}
                        </td>
                        <td className="num py-2 pr-3 text-right tabular-nums">
                          {formatPrice(num(margin?.pos_entry_price), sym.scaler)}
                        </td>
                        <td className="num py-2 pr-3 text-right tabular-nums">
                          {formatPrice(num(margin?.pos_liquidation_price), sym.scaler)}
                        </td>
                        <td
                          className="num py-2 text-right font-medium tabular-nums"
                          style={{ color: signColor(pnl) }}
                        >
                          {formatPrice(pnl, sym.scaler)}
                        </td>
                      </tr>
                    </tbody>
                  </table>
                  <Separator className="my-3" />
                  <p className="text-[11px] text-muted-foreground">
                    Position values are engine int64 ticks scaled by the symbol's price scaler.
                  </p>
                </div>
              );
            })()
          )}
        </CardContent>
      </Card>
      </>
      )}
    </div>
  );
}
