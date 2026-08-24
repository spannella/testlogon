import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  Award,
  CalendarX,
  Coins,
  Download,
  ScrollText,
  TriangleAlert,
} from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import { ApiError } from "@/api/client";
import { getRewards, getRewardsHistory, getRewardsExpiry } from "@/api/endpoints/rewards";
import type { RewardHistoryEntry } from "@/api/endpoints/rewards";
import { toCsv, downloadCsv } from "@/lib/exportReport";
import { formatPoints, formatCents } from "@/lib/rewards";
import {
  EXPIRY_MONTHS,
  computeExpiryFromHistory,
  daysUntil,
  expiryToCsv,
  formatExpiryDate,
  statementRows,
  tsToMs,
} from "@/lib/pointsExpiry";
import { PendingRewards } from "./PendingRewards";

function is404(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

type Period = "all" | "year" | "month";

const PERIODS: { id: Period; label: string }[] = [
  { id: "all", label: "All" },
  { id: "year", label: "This year" },
  { id: "month", label: "This month" },
];

/** Keep only entries whose ts falls inside the chosen period (relative to now). */
function filterByPeriod(entries: RewardHistoryEntry[], period: Period, now: Date): RewardHistoryEntry[] {
  if (period === "all") return entries;
  const y = now.getFullYear();
  const m = now.getMonth();
  const start =
    period === "year" ? new Date(y, 0, 1).getTime() : new Date(y, m, 1).getTime();
  return entries.filter((e) => {
    const ms = tsToMs(e.ts);
    return Number.isFinite(ms) && ms >= start;
  });
}

export default function RewardsStatementPage() {
  const nowMs = Date.now();
  const [period, setPeriod] = useState<Period>("all");

  const rewardsQ = useQuery({
    queryKey: ["me", "rewards", "summary"],
    queryFn: getRewards,
    retry: false,
  });
  const historyQ = useQuery({
    queryKey: ["me", "rewards", "history"],
    queryFn: getRewardsHistory,
    retry: false,
  });
  const expiryQ = useQuery({
    queryKey: ["me", "rewards", "expiry"],
    queryFn: getRewardsExpiry,
    retry: false,
  });

  const historyPending = is404(historyQ.error);

  const entries: RewardHistoryEntry[] = historyQ.data?.entries ?? [];
  const points = rewardsQ.data?.points ?? 0;

  // Full statement (asc, running balance) then period-filtered for display/CSV.
  const allRows = useMemo(() => statementRows(entries), [entries]);
  const rows = useMemo(
    () => filterByPeriod(entries, period, new Date(nowMs)),
    [entries, period, nowMs],
  );
  const displayRows = useMemo(() => {
    const keptTs = new Set(rows.map((e) => e.ts));
    return allRows.filter((r) => keptTs.has(r.ts));
  }, [allRows, rows]);

  // Client-computed expiry (always available) + optional authoritative override.
  const computed = useMemo(
    () => computeExpiryFromHistory(entries, nowMs, EXPIRY_MONTHS),
    [entries, nowMs],
  );
  const authoritative = expiryQ.data && !is404(expiryQ.error) ? expiryQ.data : null;

  const expiringSoonPoints = authoritative
    ? authoritative.expiring_soon_points
    : computed.expiringSoonPoints;
  const nextExpiryTs = authoritative
    ? authoritative.next_expiry_ts != null
      ? tsToMs(authoritative.next_expiry_ts)
      : null
    : computed.nextExpiryTs;
  const nextExpiryPoints = authoritative
    ? authoritative.next_expiry_points
    : computed.nextExpiryPoints;
  const policyMonths = authoritative?.policy_months ?? EXPIRY_MONTHS;
  const isEstimated = !authoritative;

  // Upcoming-expirations mini-list (soonest first, first 6).
  const upcomingLots = useMemo(() => {
    if (authoritative && Array.isArray(authoritative.lots)) {
      return [...authoritative.lots]
        .map((l) => ({
          expiresTs: tsToMs(l.expires_ts),
          remaining: l.points_remaining,
        }))
        .filter((l) => Number.isFinite(l.expiresTs) && l.remaining > 0)
        .sort((a, b) => a.expiresTs - b.expiresTs)
        .slice(0, 6);
    }
    return computed.lots
      .map((l) => ({ expiresTs: l.expiresTs, remaining: l.remaining }))
      .slice(0, 6);
  }, [authoritative, computed]);

  const onDownload = () => {
    const csv = expiryToCsv(displayRows, toCsv);
    const label = period === "all" ? "all" : period === "year" ? "this-year" : "this-month";
    downloadCsv(`rewards-statement-${label}.csv`, csv);
  };

  const loading = rewardsQ.isLoading || historyQ.isLoading;

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-4 md:p-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold">
            <ScrollText className="h-6 w-6" /> Points statement
          </h1>
          <p className="text-sm text-muted-foreground">
            Your running points ledger, upcoming expirations, and a downloadable statement.
          </p>
        </div>
        <Button asChild variant="outline" size="sm">
          <Link to="/rewards">
            <Award className="mr-1.5 h-4 w-4" /> Rewards
          </Link>
        </Button>
      </div>

      {loading ? (
        <Skeleton className="h-24 w-full" />
      ) : historyPending ? (
        <PendingRewards label="Your points statement" />
      ) : (
        <>
          {/* Balance + expiring-soon warning */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Card>
              <CardContent className="flex items-center gap-3 p-4">
                <div className="rounded-lg bg-muted p-2 text-muted-foreground">
                  <Coins className="h-5 w-5" />
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Points balance</p>
                  <p className="text-xl font-semibold tabular-nums">
                    {formatPoints(points, false)}
                  </p>
                  <p className="text-xs text-muted-foreground">available to redeem</p>
                </div>
              </CardContent>
            </Card>

            {expiringSoonPoints > 0 && nextExpiryTs != null ? (
              <Card className="border-amber-500/40 bg-amber-500/5">
                <CardContent className="flex items-start gap-3 p-4">
                  <div className="rounded-lg bg-amber-500/15 p-2 text-amber-600 dark:text-amber-400">
                    <TriangleAlert className="h-5 w-5" />
                  </div>
                  <div>
                    <p className="flex items-center gap-2 text-sm font-medium">
                      {formatPoints(expiringSoonPoints)} expiring soon
                      {isEstimated ? (
                        <Badge variant="secondary" className="text-[10px]">
                          Est
                        </Badge>
                      ) : null}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {formatPoints(nextExpiryPoints)} expire on {formatExpiryDate(nextExpiryTs)} (
                      {daysUntil(nextExpiryTs, nowMs)} days). Redeem before then to keep them.
                    </p>
                  </div>
                </CardContent>
              </Card>
            ) : (
              <Card>
                <CardContent className="flex items-start gap-3 p-4">
                  <div className="rounded-lg bg-muted p-2 text-muted-foreground">
                    <CalendarX className="h-5 w-5" />
                  </div>
                  <div>
                    <p className="text-sm font-medium">Nothing expiring soon</p>
                    <p className="text-xs text-muted-foreground">
                      {nextExpiryTs != null
                        ? `Your next points expire on ${formatExpiryDate(nextExpiryTs)}.`
                        : "You have no points scheduled to expire."}
                    </p>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>

          <p className="rounded-lg border border-dashed bg-muted/30 p-3 text-xs text-muted-foreground">
            Points expire {policyMonths} months after they are earned. We warn you when points are
            within 60 days of expiring.
            {isEstimated
              ? " Expiry dates below are estimated from your history (first-in, first-out)."
              : ""}
          </p>

          {/* Upcoming expirations mini-list */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <CalendarX className="h-5 w-5" /> Upcoming expirations
              </CardTitle>
              <CardDescription>Points scheduled to expire, soonest first.</CardDescription>
            </CardHeader>
            <CardContent>
              {upcomingLots.length === 0 ? (
                <p className="py-4 text-center text-sm text-muted-foreground">
                  No points are scheduled to expire.
                </p>
              ) : (
                <ul className="divide-y">
                  {upcomingLots.map((l, i) => (
                    <li key={`${l.expiresTs}-${i}`} className="flex items-center justify-between gap-3 py-2.5">
                      <div>
                        <p className="text-sm font-medium tabular-nums">
                          {formatPoints(l.remaining)}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          expires {formatExpiryDate(l.expiresTs)}
                        </p>
                      </div>
                      <Badge variant="outline" className="tabular-nums">
                        {daysUntil(l.expiresTs, nowMs)} days
                      </Badge>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          {/* Statement table */}
          <Card>
            <CardHeader>
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <CardTitle>Statement</CardTitle>
                  <CardDescription>
                    Every earn, redemption, and expiry with a running balance.
                  </CardDescription>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <div className="inline-flex rounded-md border p-0.5">
                    {PERIODS.map((p) => (
                      <button
                        key={p.id}
                        type="button"
                        onClick={() => setPeriod(p.id)}
                        className={
                          "rounded px-2.5 py-1 text-xs font-medium transition-colors " +
                          (period === p.id
                            ? "bg-primary text-primary-foreground"
                            : "text-muted-foreground hover:text-foreground")
                        }
                      >
                        {p.label}
                      </button>
                    ))}
                  </div>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={displayRows.length === 0}
                    onClick={onDownload}
                  >
                    <Download className="mr-1.5 h-4 w-4" /> Download CSV
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {historyQ.isError && !historyPending ? (
                <p className="text-sm text-destructive">Could not load your statement.</p>
              ) : displayRows.length === 0 ? (
                <p className="py-6 text-center text-sm text-muted-foreground">
                  {entries.length === 0
                    ? "No rewards activity yet."
                    : "No activity in this period."}
                </p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Date</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Description</TableHead>
                      <TableHead className="text-right">Points</TableHead>
                      <TableHead className="text-right">Balance</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {displayRows.map((r, i) => (
                      <TableRow key={`${r.ts}-${i}`}>
                        <TableCell className="whitespace-nowrap text-muted-foreground">
                          {Number.isFinite(tsToMs(r.ts))
                            ? new Date(tsToMs(r.ts)).toLocaleDateString()
                            : "—"}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="capitalize">
                            {r.type || "—"}
                          </Badge>
                        </TableCell>
                        <TableCell>{r.description || r.type || "—"}</TableCell>
                        <TableCell
                          className={
                            "text-right tabular-nums " +
                            (r.points > 0
                              ? "text-emerald-600 dark:text-emerald-400"
                              : r.points < 0
                                ? "text-destructive"
                                : "")
                          }
                        >
                          {r.points > 0
                            ? `+${formatPoints(r.points, false)}`
                            : formatPoints(r.points, false)}
                          {r.cashCents ? (
                            <span className="ml-1 text-xs text-muted-foreground">
                              ({formatCents(r.cashCents)})
                            </span>
                          ) : null}
                        </TableCell>
                        <TableCell className="text-right font-medium tabular-nums">
                          {formatPoints(r.balanceAfter, false)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
