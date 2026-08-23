import SurfaceIntro from "@/components/onboarding/SurfaceIntro";
import { Link } from "react-router-dom";
import { Boxes, Plus, FileText } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { useStrategyMarket, useMyStrategies } from "@/hooks/useStrategies";
import type { Strategy, StrategyStatus } from "@/api/endpoints/strategies";
import { formatBps, formatCents, capacityFilledFraction } from "@/lib/strategies";
import { PendingBackend, PooledNavNote } from "./PendingBackend";

const STATUS_VARIANT: Record<StrategyStatus, "default" | "secondary" | "destructive" | "outline"> = {
  draft: "outline",
  paper: "secondary",
  published: "default",
  closed: "destructive",
};

function StatusBadge({ status }: { status: StrategyStatus }) {
  return <Badge variant={STATUS_VARIANT[status] ?? "outline"}>{status}</Badge>;
}

function capacityRemaining(s: Strategy): string {
  if (!(s.max_aum_cents > 0)) return "Uncapped";
  const filled = capacityFilledFraction(s.aum_cents ?? 0, s.max_aum_cents);
  const remaining = Math.max(0, s.max_aum_cents - (s.aum_cents ?? 0));
  return `${formatCents(remaining)} (${Math.round((1 - filled) * 100)}%)`;
}

function MarketTable({ strategies }: { strategies: Strategy[] }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Name</TableHead>
          <TableHead className="text-right">NAV / unit</TableHead>
          <TableHead className="text-right">AUM</TableHead>
          <TableHead className="text-right">Fees (mgmt / perf)</TableHead>
          <TableHead className="text-right">Capacity left</TableHead>
          <TableHead className="text-right">Since inception</TableHead>
          <TableHead className="w-16" />
        </TableRow>
      </TableHeader>
      <TableBody>
        {strategies.map((s) => (
          <TableRow key={s.strategy_id} data-testid="strategy-row">
            <TableCell className="max-w-[16rem]">
              <div className="truncate font-medium">{s.name}</div>
              <div className="text-xs text-muted-foreground">{s.kind === "rule" ? "Rule-based" : "Basket"}</div>
            </TableCell>
            <TableCell className="text-right tabular-nums">
              {s.nav_per_unit != null ? formatCents(s.nav_per_unit) : "—"}
            </TableCell>
            <TableCell className="text-right tabular-nums">
              {s.aum_cents != null ? formatCents(s.aum_cents) : "—"}
            </TableCell>
            <TableCell className="text-right tabular-nums">
              {formatBps(s.mgmt_fee_bps)} / {formatBps(s.perf_fee_bps)}
            </TableCell>
            <TableCell className="text-right tabular-nums">{capacityRemaining(s)}</TableCell>
            <TableCell className="text-right tabular-nums">
              {s.inception_return_bps != null ? (
                <span
                  className={
                    s.inception_return_bps >= 0
                      ? "text-emerald-600 dark:text-emerald-400"
                      : "text-rose-600 dark:text-rose-400"
                  }
                >
                  {s.inception_return_bps >= 0 ? "+" : ""}
                  {formatBps(s.inception_return_bps)}
                </span>
              ) : (
                "—"
              )}
            </TableCell>
            <TableCell>
              <Button asChild variant="ghost" size="sm">
                <Link to={`/strategies/${encodeURIComponent(s.strategy_id)}`}>View</Link>
              </Button>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function MineTable({ strategies }: { strategies: Strategy[] }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Name</TableHead>
          <TableHead>Status</TableHead>
          <TableHead className="text-right">Legs</TableHead>
          <TableHead className="text-right">Min invest</TableHead>
          <TableHead className="w-16" />
        </TableRow>
      </TableHeader>
      <TableBody>
        {strategies.map((s) => (
          <TableRow key={s.strategy_id} data-testid="my-strategy-row">
            <TableCell className="max-w-[16rem] truncate font-medium">{s.name}</TableCell>
            <TableCell>
              <StatusBadge status={s.status} />
            </TableCell>
            <TableCell className="text-right tabular-nums">{s.legs?.length ?? 0}</TableCell>
            <TableCell className="text-right tabular-nums">{formatCents(s.min_investment_cents)}</TableCell>
            <TableCell>
              <Button asChild variant="ghost" size="sm">
                <Link to={`/strategies/${encodeURIComponent(s.strategy_id)}`}>Open</Link>
              </Button>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export default function StrategyMarketPage() {
  const market = useStrategyMarket();
  const mine = useMyStrategies();

  const marketStrategies = market.data?.strategies ?? [];
  const myStrategies = mine.data?.strategies ?? [];

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 md:p-6">
      <SurfaceIntro surfaceId="strategies" />

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Boxes className="h-6 w-6 text-primary" />
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Strategies &amp; Baskets</h1>
            <p className="text-sm text-muted-foreground">
              Investable funds — a basket of target weights you can paper-trade, backtest, then
              invest in at NAV.
            </p>
          </div>
        </div>
        <Button asChild data-testid="new-strategy-cta">
          <Link to="/strategies/new">
            <Plus className="mr-1.5 h-4 w-4" /> Create a strategy
          </Link>
        </Button>
      </div>

      <PooledNavNote />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Marketplace — published funds</CardTitle>
        </CardHeader>
        <CardContent>
          {market.isLoading ? (
            <div className="space-y-2">
              <Skeleton className="h-8 w-full" />
              <Skeleton className="h-8 w-full" />
              <Skeleton className="h-8 w-full" />
            </div>
          ) : market.isError ? (
            <PendingBackend label="The strategy marketplace" />
          ) : marketStrategies.length === 0 ? (
            <div className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">
              No strategies are published yet. Be the first to{" "}
              <Link to="/strategies/new" className="font-medium text-primary underline-offset-4 hover:underline">
                create one
              </Link>
              .
            </div>
          ) : (
            <MarketTable strategies={marketStrategies} />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <FileText className="h-4 w-4" /> My strategies
          </CardTitle>
        </CardHeader>
        <CardContent>
          {mine.isLoading ? (
            <Skeleton className="h-8 w-full" />
          ) : mine.isError ? (
            <PendingBackend label="Your strategies" />
          ) : myStrategies.length === 0 ? (
            <div className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
              You haven&rsquo;t created any strategies yet.
            </div>
          ) : (
            <MineTable strategies={myStrategies} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
