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
  type MarginAccount,
} from "@/api/endpoints/trading";
import { getSymbols, type MarketSymbol } from "@/api/endpoints/marketData";
import { formatPrice, formatQty } from "@/pages/markets/format";

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

  const refetchAll = () => {
    custodyQ.refetch();
    stakingQ.refetch();
    spotQ.refetch();
    marginQ.refetch();
    symbolsQ.refetch();
  };

  const anyFetching =
    custodyQ.isFetching ||
    stakingQ.isFetching ||
    spotQ.isFetching ||
    marginQ.isFetching ||
    symbolsQ.isFetching;

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

  const hasPosition = !!margin && num(margin.num_positions) > 0 && num(margin.pos_qty) !== 0;

  // Cross-venue equity snapshot: sum only the numerically-comparable balances
  // we can actually read. This is a raw notional sum across assets/venues (no
  // FX/price conversion) — labelled clearly as an approximate snapshot.
  const equity = useMemo(() => {
    let sum = 0;
    let sources = 0;
    if (custodyQ.isSuccess) {
      sum += custodyRows.reduce((a, r) => a + num(r.balance), 0);
      sources++;
    }
    if (spotQ.isSuccess) {
      sum += spotRows.reduce((a, b) => a + num(b.balance), 0);
      sources++;
    }
    if (marginQ.isSuccess) {
      sum += num(margin?.balance);
      sources++;
    }
    if (stakingQ.isSuccess) {
      sum += stakingTotals.total;
      sources++;
    }
    return { sum, sources };
  }, [
    custodyQ.isSuccess,
    spotQ.isSuccess,
    marginQ.isSuccess,
    stakingQ.isSuccess,
    custodyRows,
    spotRows,
    margin,
    stakingTotals.total,
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
            <h1 className="text-xl font-semibold leading-tight">Portfolio</h1>
            <p className="text-xs text-muted-foreground">
              Read-only overview across custody, trading, margin &amp; staking.
            </p>
          </div>
        </div>
        <Button variant="outline" size="sm" className="gap-2 self-start sm:self-auto" onClick={refetchAll}>
          <RefreshCw className={cn("h-4 w-4", anyFetching && "animate-spin")} />
          Refresh
        </Button>
      </div>

      {/* Total equity */}
      <Card>
        <CardContent className="flex flex-col gap-1 py-6">
          <span className="text-xs uppercase tracking-wide text-muted-foreground">
            Total equity — cross-venue snapshot
          </span>
          {anyLoading ? (
            <Skeleton className="h-9 w-48" />
          ) : (
            <div className="flex items-baseline gap-2">
              <span className="num text-3xl font-bold tabular-nums">
                {equity.sum.toLocaleString(undefined, { maximumFractionDigits: 8 })}
              </span>
              {anyFetching && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
            </div>
          )}
          <span className="text-[11px] text-muted-foreground">
            Approximate raw sum of readable balances from {equity.sources} of 4 venue
            {equity.sources === 1 ? "" : "s"} — assets are NOT FX/price-converted; unavailable
            sources are excluded.
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
              {custodyRows.map((r) => (
                <KV key={r.symbol} label={r.symbol} value={fmtAmount(r.balance)} />
              ))}
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
              {spotRows.map((b, i) => (
                <div key={b.symbol ?? b.asset ?? i} className="flex items-center justify-between gap-3 py-1">
                  <span className="text-muted-foreground">{b.symbol ?? `asset ${b.asset ?? "?"}`}</span>
                  <span className="text-right">
                    <span className="num font-medium tabular-nums">{fmtAmount(b.balance)}</span>
                    {b.available != null && (
                      <span className="ml-2 text-[11px] text-muted-foreground">
                        ({fmtAmount(b.available)} avail)
                      </span>
                    )}
                  </span>
                </div>
              ))}
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
              <KV label="Balance" value={fmtAmount(margin?.balance)} />
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
              <KV label="Total staked" value={fmtAmount(stakingTotals.total)} />
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
    </div>
  );
}
