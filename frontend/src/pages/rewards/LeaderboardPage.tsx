import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Trophy, Medal, Users, ArrowLeft } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";

import { ApiError } from "@/api/client";
import { getReferralLeaderboard } from "@/api/endpoints/rewards";
import type {
  LeaderboardPeriod,
  ReferralLeaderboardEntry,
} from "@/api/endpoints/rewards";
import { formatCents } from "@/lib/rewards";
import {
  findYou,
  formatCount,
  formatRank,
  rankMedal,
  topN,
} from "@/lib/referralLeaderboard";
import { PendingRewards } from "./PendingRewards";

const TOP_N = 25;

function is404(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

const MEDAL_CLASS: Record<string, string> = {
  gold: "text-yellow-500",
  silver: "text-slate-400",
  bronze: "text-amber-700",
};

function RankCell({ rank }: { rank: number }) {
  const medal = rankMedal(rank);
  return (
    <div className="flex items-center gap-1.5 tabular-nums">
      {medal ? (
        <Medal className={cn("h-4 w-4", MEDAL_CLASS[medal])} aria-hidden />
      ) : null}
      <span className={cn(medal ? "font-semibold" : "text-muted-foreground")}>
        {formatRank(rank)}
      </span>
    </div>
  );
}

function LeaderRow({
  row,
  highlight,
}: {
  row: ReferralLeaderboardEntry;
  highlight?: boolean;
}) {
  return (
    <TableRow className={cn(highlight && "bg-primary/10 hover:bg-primary/15")}>
      <TableCell>
        <RankCell rank={row.rank} />
      </TableCell>
      <TableCell className="font-medium">
        <span className="flex items-center gap-2">
          {row.masked_name || "—"}
          {row.is_you ? (
            <Badge variant="default" className="px-1.5 py-0 text-[10px]">
              You
            </Badge>
          ) : null}
        </span>
      </TableCell>
      <TableCell className="text-right tabular-nums">
        {formatCount(row.referred_count)}
      </TableCell>
      <TableCell className="text-right tabular-nums">
        {formatCount(row.qualified_count)}
      </TableCell>
      <TableCell className="text-right tabular-nums">
        {formatCents(row.reward_cents)}
      </TableCell>
    </TableRow>
  );
}

export default function LeaderboardPage() {
  const [period, setPeriod] = useState<LeaderboardPeriod>("all");

  const boardQ = useQuery({
    queryKey: ["me", "referral", "leaderboard", period],
    queryFn: () => getReferralLeaderboard(period),
    retry: false,
  });

  const board = boardQ.data;
  const entries = board?.entries ?? [];
  const shown = topN(entries, TOP_N);
  const you = findYou(entries, shown, board?.you);

  const boardPending = is404(boardQ.error);

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-4 md:p-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold">
            <Trophy className="h-6 w-6" /> Referral leaderboard
          </h1>
          <p className="text-sm text-muted-foreground">
            The top referrers ranked by qualified referrals and rewards earned.
          </p>
        </div>
        <Button asChild variant="outline" size="sm">
          <Link to="/rewards/referrals">
            <ArrowLeft className="mr-1.5 h-4 w-4" /> Referrals
          </Link>
        </Button>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-4 space-y-0">
          <div>
            <CardTitle>Top referrers</CardTitle>
            <CardDescription>
              {board?.updated_ts
                ? `Updated ${new Date(board.updated_ts * 1000).toLocaleString()}`
                : "See where you stand against the top referrers."}
            </CardDescription>
          </div>
          <Tabs
            value={period}
            onValueChange={(v) => setPeriod(v as LeaderboardPeriod)}
          >
            <TabsList>
              <TabsTrigger value="all">All-time</TabsTrigger>
              <TabsTrigger value="month">This month</TabsTrigger>
            </TabsList>
          </Tabs>
        </CardHeader>
        <CardContent className="space-y-4">
          {boardQ.isLoading ? (
            <Skeleton className="h-48 w-full" />
          ) : boardPending ? (
            <PendingRewards label="The referral leaderboard" />
          ) : boardQ.isError ? (
            <p className="text-sm text-destructive">
              Could not load the leaderboard. Please try again later.
            </p>
          ) : shown.length === 0 ? (
            <div className="flex flex-col items-center gap-2 py-10 text-center">
              <Trophy className="h-8 w-8 text-muted-foreground" />
              <p className="font-medium">No rankings yet</p>
              <p className="max-w-sm text-sm text-muted-foreground">
                Be the first to climb the board — share your referral link and
                start earning.
              </p>
              <Button asChild variant="outline" size="sm" className="mt-1">
                <Link to="/rewards/referrals">
                  <Users className="mr-1.5 h-4 w-4" /> Get your link
                </Link>
              </Button>
            </div>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-20">Rank</TableHead>
                    <TableHead>Referrer</TableHead>
                    <TableHead className="text-right">Referred</TableHead>
                    <TableHead className="text-right">Qualified</TableHead>
                    <TableHead className="text-right">Earned</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {shown.map((row) => (
                    <LeaderRow key={row.id} row={row} highlight={row.is_you} />
                  ))}
                </TableBody>
              </Table>

              {you.pinned ? (
                <div className="rounded-lg border border-primary/40 bg-primary/5 p-3">
                  <p className="mb-2 text-xs font-medium text-muted-foreground">
                    Your rank
                  </p>
                  <Table>
                    <TableBody>
                      <LeaderRow row={you.pinned} highlight />
                    </TableBody>
                  </Table>
                </div>
              ) : null}
            </>
          )}
        </CardContent>
      </Card>

      <p className="text-xs text-muted-foreground">
        Rankings are computed server-side from qualified referrals. Names are
        masked for privacy; only your own row is shown in full.
      </p>
    </div>
  );
}
