// FEE TIERS BY TRADING VOLUME (maker/taker VIP schedule).
//
// Shows the caller their maker/taker fee tier driven by 30-day rolling trading
// VOLUME. Volume is computed CLIENT-SIDE from the live executed-fill feed
// (`GET /me/fills/fees`, the same feed the Tax report uses) using the pure
// `lib/feeTiers` engine. An OPTIONAL authoritative backend read
// (`GET /me/fees/tier`) overrides the estimate when it resolves; on 404 we
// fall back to the client computation and label it "estimated".

import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Percent, Info, RefreshCw, TrendingUp } from "lucide-react";

import { ApiError } from "@/api/client";
import { getFeeTier } from "@/api/endpoints/fees";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";
import { useFillsFees } from "@/hooks/useTrading";
import { useSymbols } from "@/hooks/useMarketData";
import type { FillFee } from "@/api/endpoints/trading";
import type { MarketSymbol } from "@/api/endpoints/marketData";
import { useFeeTier } from "@/hooks/useFeeTier";
import {
  FEE_TIERS,
  tierForVolume,
  tierById,
  nextTier,
  progressToNextFraction,
  volumeToNextTierCents,
  type VolumeFill,
  type FeeTier,
} from "@/lib/feeTiers";

/** Format integer cents as a $ decimal string. */
function money(cents: number): string {
  return (cents / 100).toLocaleString(undefined, {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
}

/** bps -> "0.15%" */
function bpsPct(bps: number): string {
  return `${(bps / 100).toLocaleString(undefined, { maximumFractionDigits: 4 })}%`;
}

export default function FeesPage() {
  const symbolsQuery = useSymbols();
  const fillsQuery = useFillsFees();

  // Authoritative read; 404s until the edge deploys -> degrade to the estimate.
  // Kept alongside the shared hook (same query key -> one network call) only to
  // drive the "showing an estimate" notice below.
  const tierQuery = useQuery({
    queryKey: ["fees", "tier"],
    queryFn: getFeeTier,
    retry: false,
  });

  // symbolid -> catalog entry (name + price scaler), same resolver as Tax report.
  const symById = useMemo(() => {
    const m = new Map<number, MarketSymbol>();
    for (const s of symbolsQuery.data?.symbols ?? []) m.set(s.symbol_id, s);
    return m;
  }, [symbolsQuery.data]);

  const rawFills: FillFee[] = Array.isArray(fillsQuery.data?.fills) ? fillsQuery.data!.fills! : [];

  // Normalize the engine feed -> integer-cents fills (price int64 tick / scaler).
  const normalized: VolumeFill[] = useMemo(() => {
    const out: VolumeFill[] = [];
    for (const f of rawFills) {
      const scaler = symById.get(f.symbolid)?.price_scaler || 1;
      const priceCents = Math.round((f.price / scaler) * 100);
      const qty = Math.abs(f.qty);
      if (!qty || priceCents <= 0) continue;
      out.push({ ts: f.ts, priceCents, qty });
    }
    return out;
  }, [rawFills, symById]);

  // Shared resolver (authoritative -> estimate) — the single source of truth
  // for the tier + maker/taker bps + backing volume, deduped with the ticket.
  const resolved = useFeeTier();
  const isAuthoritative = resolved.source === "authoritative";
  const volumeCents = resolved.volumeCents;
  const currentTier: FeeTier = tierById(resolved.tierId) || tierForVolume(volumeCents);

  const upcoming = nextTier(currentTier);
  const fraction = progressToNextFraction(volumeCents);
  const toNextCents = volumeToNextTierCents(volumeCents);

  const makerBps = resolved.makerBps;
  const takerBps = resolved.takerBps;

  const feedLoading = fillsQuery.isLoading || symbolsQuery.isLoading;
  const feedUnavailable =
    fillsQuery.isError && !isAuthoritative && normalized.length === 0;
  const hasNoFills = !isAuthoritative && normalized.length === 0;

  const is404 = (e: unknown) => e instanceof ApiError && e.status === 404;

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-4 md:p-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            <Percent className="h-6 w-6 text-primary" />
            Fee Tiers
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Your maker/taker fees drop as your 30-day trading volume climbs.
          </p>
        </div>
        <Badge variant={isAuthoritative ? "default" : "secondary"}>
          {isAuthoritative ? "Live account tier" : "Estimated from your trade history"}
        </Badge>
      </div>

      {/* Summary cards */}
      <div className="grid gap-4 sm:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>30-day volume</CardDescription>
            <CardTitle className="text-2xl">
              {feedLoading && !isAuthoritative ? "..." : money(volumeCents)}
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground">
            {isAuthoritative
              ? "As reported by the exchange."
              : "Computed from your executed fills."}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Current tier</CardDescription>
            <CardTitle className="flex items-center gap-2 text-2xl">
              <TrendingUp className="h-5 w-5 text-primary" />
              {currentTier.name}
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground">
            {money(currentTier.minVolumeCents)}+ 30-day volume
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Your rates</CardDescription>
            <CardTitle className="text-2xl">
              {bpsPct(makerBps)}
              <span className="text-muted-foreground"> / </span>
              {bpsPct(takerBps)}
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground">
            maker {makerBps} bps &middot; taker {takerBps} bps
          </CardContent>
        </Card>
      </div>

      {/* Progress to next tier */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">
            {upcoming ? `Progress to ${upcoming.name}` : "Top tier reached"}
          </CardTitle>
          <CardDescription>
            {upcoming
              ? `${money(toNextCents)} more volume for ${upcoming.name} - maker ${bpsPct(
                  upcoming.makerBps,
                )} / taker ${bpsPct(upcoming.takerBps)}`
              : "You are on the best maker/taker schedule available."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Progress value={Math.round(fraction * 100)} max={100} />
          <div className="mt-2 flex justify-between text-xs text-muted-foreground">
            <span>{currentTier.name}</span>
            <span>{Math.round(fraction * 100)}%</span>
            <span>{upcoming ? upcoming.name : "-"}</span>
          </div>
        </CardContent>
      </Card>

      {/* State notices */}
      {tierQuery.isError && !is404(tierQuery.error) && (
        <Alert>
          <Info className="h-4 w-4" />
          <AlertTitle>Showing an estimate</AlertTitle>
          <AlertDescription>
            The authoritative tier read is unavailable right now; the numbers
            above are computed from your recent fills.
          </AlertDescription>
        </Alert>
      )}

      {feedUnavailable && (
        <Alert>
          <RefreshCw className="h-4 w-4" />
          <AlertTitle>Trade history unavailable</AlertTitle>
          <AlertDescription>
            We could not load your executed fills, so your volume cannot be
            estimated yet. The tier table below still shows the full schedule.
          </AlertDescription>
        </Alert>
      )}

      {!feedUnavailable && hasNoFills && !feedLoading && (
        <Alert>
          <Info className="h-4 w-4" />
          <AlertTitle>No trades in the last 30 days</AlertTitle>
          <AlertDescription>
            You start on the {FEE_TIERS[0]!.name} tier. Trade to build 30-day
            volume and unlock lower maker/taker fees.
          </AlertDescription>
        </Alert>
      )}

      {/* Full tier table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Full VIP schedule</CardTitle>
          <CardDescription>
            Thresholds are 30-day rolling volume in USD. Your tier is highlighted.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Tier</TableHead>
                <TableHead className="text-right">30-day volume &ge;</TableHead>
                <TableHead className="text-right">Maker</TableHead>
                <TableHead className="text-right">Taker</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {FEE_TIERS.map((t) => {
                const mine = t.id === currentTier.id;
                return (
                  <TableRow key={t.id} className={cn(mine && "bg-primary/10 font-medium")}>
                    <TableCell>
                      <span className="flex items-center gap-2">
                        {t.name}
                        {mine && <Badge variant="default">You</Badge>}
                      </span>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {money(t.minVolumeCents)}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{bpsPct(t.makerBps)}</TableCell>
                    <TableCell className="text-right tabular-nums">{bpsPct(t.takerBps)}</TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
