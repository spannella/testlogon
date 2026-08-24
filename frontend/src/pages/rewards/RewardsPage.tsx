import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  Award,
  Coins,
  Wallet,
  Sparkles,
  Gift,
  Users,
  TrendingUp,
  ArrowRight,
  DollarSign,
} from "lucide-react";
import { toast } from "sonner";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";

import { ApiError } from "@/api/client";
import {
  getRewards,
  getRewardsHistory,
  getRewardsCatalog,
  getTradingRewards,
  redeemReward,
  redeemPointsForCash,
} from "@/api/endpoints/rewards";
import type { CatalogReward, RewardHistoryEntry } from "@/api/endpoints/rewards";
import {
  formatCents,
  formatPoints,
  pointsAfterRedeem,
  redeemableCatalog,
} from "@/lib/rewards";
import {
  CENTS_PER_POINT,
  MIN_REDEEM_POINTS,
  cashCentsForPoints,
  pointsForCashCents,
  validatePointsRedemption,
} from "@/lib/rewardsCash";
import { tradingRewardsSummary } from "@/lib/tradingRewards";
import { useFeeTier } from "@/hooks/useFeeTier";
import { PendingRewards } from "./PendingRewards";

function is404(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

function BalanceCard({
  icon,
  label,
  value,
  hint,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  hint?: string;
}) {
  return (
    <Card>
      <CardContent className="flex items-center gap-3 p-4">
        <div className="rounded-lg bg-muted p-2 text-muted-foreground">{icon}</div>
        <div>
          <p className="text-xs text-muted-foreground">{label}</p>
          <p className="text-xl font-semibold tabular-nums">{value}</p>
          {hint ? <p className="text-xs text-muted-foreground">{hint}</p> : null}
        </div>
      </CardContent>
    </Card>
  );
}

export default function RewardsPage() {
  const qc = useQueryClient();
  const [pending, setPending] = useState<CatalogReward | null>(null);

  // DIRECT "convert points to cash" flow state.
  const [convertInput, setConvertInput] = useState("");
  const [convertConfirm, setConvertConfirm] = useState<number | null>(null);

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
  const catalogQ = useQuery({
    queryKey: ["me", "rewards", "catalog"],
    queryFn: getRewardsCatalog,
    retry: false,
  });
  const tradingQ = useQuery({
    queryKey: ["me", "rewards", "trading"],
    queryFn: getTradingRewards,
    retry: false,
  });

  // 30-day executed-trade volume, reused from the shared fee-tier resolver.
  const feeTier = useFeeTier();

  const rewards = rewardsQ.data;
  const points = rewards?.points ?? 0;
  const history: RewardHistoryEntry[] = historyQ.data?.entries ?? [];
  const catalog = redeemableCatalog(catalogQ.data?.rewards ?? [], points);

  // Prefer the authoritative /me/rewards/trading read; else estimate from
  // the caller’s own 30-day trade volume. Never throws, degrades gracefully.
  const trading = tradingRewardsSummary(feeTier.volumeCents, tradingQ.data);
  const tradingVolumeReady = !feeTier.isPending || tradingQ.isSuccess;

  // Surface trading as a first-class "way to earn" alongside the backend list.
  const tradingWayToEarn = {
    id: "__trading",
    title: "Trade to earn points",
    points: trading.pointsPerDollar,
    detail: `Earn ${formatPoints(trading.pointsPerDollar, false)} per $1 of trading volume.`,
  };
  const waysToEarn = [tradingWayToEarn, ...(rewards?.ways_to_earn ?? [])];

  const redeemMut = useMutation({
    mutationFn: (rewardId: string) => redeemReward(rewardId),
    onSuccess: (res) => {
      toast.success(`Redeemed. ${formatPoints(res.points_remaining)} remaining.`);
      qc.invalidateQueries({ queryKey: ["me", "rewards"] });
      qc.invalidateQueries({ queryKey: ["ui", "billing", "wallet"] });
      qc.invalidateQueries({ queryKey: ["billing", "wallet"] });
      setPending(null);
    },
    onError: (err: unknown) => {
      if (is404(err)) {
        toast.error("Redemption is not available yet — the rewards backend has not shipped.");
      } else if (err instanceof ApiError) {
        toast.error(err.message || "Could not redeem this reward.");
      } else {
        toast.error("Could not redeem this reward.");
      }
      setPending(null);
    },
  });

  // DIRECT points-to-cash conversion mutation.
  const convertMut = useMutation({
    mutationFn: (pts: number) => redeemPointsForCash(pts),
    onSuccess: (res) => {
      toast.success(
        `Converted to cash. ${formatCents(res.cash_cents)} added to your USD wallet — ${formatPoints(res.points_remaining)} remaining.`,
      );
      qc.invalidateQueries({ queryKey: ["me", "rewards"] });
      qc.invalidateQueries({ queryKey: ["ui", "billing", "wallet"] });
      qc.invalidateQueries({ queryKey: ["billing", "wallet"] });
      setConvertConfirm(null);
      setConvertInput("");
    },
    onError: (err: unknown) => {
      if (is404(err)) {
        toast.error("Cash conversion is not available yet — the rewards backend has not shipped.");
      } else if (err instanceof ApiError) {
        toast.error(err.message || "Could not convert your points to cash.");
      } else {
        toast.error("Could not convert your points to cash.");
      }
      setConvertConfirm(null);
    },
  });

  const rewardsPending = is404(rewardsQ.error);
  const historyPending = is404(historyQ.error);
  const catalogPending = is404(catalogQ.error);

  // Parsed convert amount + live validation against the current points balance.
  const convertPoints = useMemo(() => {
    const trimmed = convertInput.trim();
    if (trimmed === "") return Number.NaN;
    return Number(trimmed);
  }, [convertInput]);
  const convertValidation = useMemo(
    () => validatePointsRedemption(convertPoints, points),
    [convertPoints, points],
  );
  const convertCashCents = Number.isFinite(convertPoints)
    ? cashCentsForPoints(Math.max(0, Math.trunc(convertPoints)))
    : 0;

  const setPreset = (cents: number) => {
    // Preset by target USD; clamp to the caller's available balance.
    const wanted = pointsForCashCents(cents);
    setConvertInput(String(Math.min(wanted, points)));
  };

  const confirmDescription = pending
    ? pending.kind === "cash"
      ? `Redeem ${formatPoints(pending.cost_points)} for ${formatCents(pending.value_cents)}? This credits your USD cash wallet. You will have ${formatPoints(pointsAfterRedeem(points, pending.cost_points))} left.`
      : `Redeem ${formatPoints(pending.cost_points)} for "${pending.name}"? You will have ${formatPoints(pointsAfterRedeem(points, pending.cost_points))} left.`
    : "";

  const convertDescription =
    convertConfirm !== null
      ? `Redeem ${formatPoints(convertConfirm)} for ${formatCents(cashCentsForPoints(convertConfirm))} to your USD cash wallet? You will have ${formatPoints(pointsAfterRedeem(points, convertConfirm))} left.`
      : "";

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-4 md:p-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold">
            <Award className="h-6 w-6" /> Rewards
          </h1>
          <p className="text-sm text-muted-foreground">
            Earn points from referrals and activity, then redeem for cash or perks.
          </p>
        </div>
        <Button asChild variant="outline" size="sm">
          <Link to="/rewards/referrals">
            <Users className="mr-1.5 h-4 w-4" /> Referrals
          </Link>
        </Button>
      </div>

      {/* Balances */}
      {rewardsQ.isLoading ? (
        <Skeleton className="h-24 w-full" />
      ) : rewardsPending ? (
        <PendingRewards label="The rewards program" />
      ) : rewardsQ.isError ? (
        <p className="text-sm text-destructive">Could not load your rewards balance.</p>
      ) : rewards ? (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <BalanceCard
            icon={<Coins className="h-5 w-5" />}
            label="Points"
            value={formatPoints(rewards.points, false)}
            hint="available to redeem"
          />
          <BalanceCard
            icon={<Wallet className="h-5 w-5" />}
            label="Reward cash"
            value={formatCents(rewards.cash_cents)}
            hint="credited to USD wallet"
          />
          <BalanceCard
            icon={<Sparkles className="h-5 w-5" />}
            label="Lifetime points"
            value={formatPoints(rewards.lifetime_points, false)}
            hint="earned all-time"
          />
        </div>
      ) : null}

      {/* Ways to earn */}
      {rewards && !rewardsPending ? (
        <Card>
          <CardHeader>
            <CardTitle>Ways to earn</CardTitle>
            <CardDescription>Rack up points across the platform.</CardDescription>
          </CardHeader>
          <CardContent>
            {waysToEarn.length === 0 ? (
              <p className="py-4 text-center text-sm text-muted-foreground">
                No earning opportunities listed right now.
              </p>
            ) : (
              <ul className="divide-y">
                {waysToEarn.map((w) => (
                  <li key={w.id} className="flex items-center justify-between gap-3 py-3">
                    <div>
                      <p className="font-medium">{w.title}</p>
                      <p className="text-sm text-muted-foreground">{w.detail}</p>
                    </div>
                    <Badge variant="secondary" className="shrink-0 tabular-nums">
                      +{formatPoints(w.points)}
                    </Badge>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      ) : null}

      {/* Trading rewards — earn points by trading volume */}
      <Card>
        <CardHeader>
          <div className="flex items-start justify-between gap-3">
            <div>
              <CardTitle className="flex items-center gap-2">
                <TrendingUp className="h-5 w-5" /> Trade to earn points
              </CardTitle>
              <CardDescription>
                Earn{" "}
                <span className="font-medium text-foreground">
                  {formatPoints(trading.pointsPerDollar, false)}
                  {trading.pointsPerDollar === 1 ? " point" : " points"}
                </span>{" "}
                per $1 traded. Points accrue automatically on every fill.
              </CardDescription>
            </div>
            <Badge variant={trading.source === "authoritative" ? "default" : "secondary"}>
              {trading.source === "authoritative" ? "Live" : "Estimated"}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {tradingVolumeReady ? (
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border p-4">
              <div>
                <p className="text-xs text-muted-foreground">Your 30-day volume</p>
                <p className="text-xl font-semibold tabular-nums">
                  {formatCents(trading.volume30dCents)}
                </p>
              </div>
              <ArrowRight className="h-5 w-5 shrink-0 text-muted-foreground" />
              <div className="text-right">
                <p className="text-xs text-muted-foreground">
                  {trading.source === "authoritative" ? "Points earned" : "~ Estimated points"}
                </p>
                <p className="text-xl font-semibold tabular-nums text-primary">
                  {trading.source === "authoritative" ? "" : "~"}
                  {formatPoints(trading.pointsEarned30d, false)}
                </p>
              </div>
            </div>
          ) : feeTier.isPending ? (
            <Skeleton className="h-20 w-full" />
          ) : (
            <p className="rounded-lg border p-4 text-sm text-muted-foreground">
              Your trading volume is unavailable right now. Start trading to earn{" "}
              {formatPoints(trading.pointsPerDollar, false)} per $1 of volume.
            </p>
          )}

          {trading.source === "authoritative" && trading.lifetimeTradingPoints > 0 ? (
            <p className="text-sm text-muted-foreground">
              Lifetime trading points:{" "}
              <span className="font-medium text-foreground tabular-nums">
                {formatPoints(trading.lifetimeTradingPoints)}
              </span>
            </p>
          ) : (
            <p className="text-xs text-muted-foreground">
              Estimated from your recent trade history. Points are credited server-side as
              your fills settle.
            </p>
          )}

          <div className="flex flex-wrap gap-2">
            <Button asChild size="sm">
              <Link to="/markets">
                <TrendingUp className="mr-1.5 h-4 w-4" /> Trade now
              </Link>
            </Button>
            <Button asChild size="sm" variant="outline">
              <Link to="/fees">Volume &amp; tiers</Link>
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Convert points to cash — DIRECT flexible redemption */}
      {rewards && !rewardsPending ? (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <DollarSign className="h-5 w-5" /> Convert points to cash
            </CardTitle>
            <CardDescription>
              {formatPoints(100 / CENTS_PER_POINT, false)} points = {formatCents(100)}. Cash lands
              in your{" "}
              <Link
                to="/custody/cash"
                className="font-medium text-primary underline-offset-4 hover:underline"
              >
                USD cash wallet
              </Link>
              . Minimum {formatPoints(MIN_REDEEM_POINTS)} ({formatCents(cashCentsForPoints(MIN_REDEEM_POINTS))}).
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex flex-wrap items-end gap-3">
              <div className="min-w-[10rem] flex-1">
                <label htmlFor="convert-points" className="text-xs text-muted-foreground">
                  Points to convert
                </label>
                <Input
                  id="convert-points"
                  type="number"
                  inputMode="numeric"
                  min={MIN_REDEEM_POINTS}
                  step={1}
                  placeholder={String(MIN_REDEEM_POINTS)}
                  value={convertInput}
                  onChange={(e) => setConvertInput(e.target.value)}
                  className="mt-1 tabular-nums"
                />
              </div>
              <div className="flex flex-wrap gap-2">
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={points < pointsForCashCents(500)}
                  onClick={() => setPreset(500)}
                >
                  $5
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={points < pointsForCashCents(1000)}
                  onClick={() => setPreset(1000)}
                >
                  $10
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={points < MIN_REDEEM_POINTS}
                  onClick={() => setConvertInput(String(points))}
                >
                  Max
                </Button>
              </div>
            </div>

            <div className="flex items-center justify-between gap-3 rounded-lg border p-4">
              <div>
                <p className="text-xs text-muted-foreground">You have</p>
                <p className="text-lg font-semibold tabular-nums">
                  {formatPoints(points)}
                </p>
              </div>
              <ArrowRight className="h-5 w-5 shrink-0 text-muted-foreground" />
              <div className="text-right">
                <p className="text-xs text-muted-foreground">You&apos;ll receive</p>
                <p className="text-lg font-semibold tabular-nums text-primary">
                  {formatCents(convertCashCents)}
                </p>
              </div>
            </div>

            {convertInput.trim() !== "" && !convertValidation.ok ? (
              <p className="text-sm text-destructive">{convertValidation.reason}</p>
            ) : null}

            <Button
              className="w-full sm:w-auto"
              disabled={!convertValidation.ok || convertMut.isPending}
              onClick={() => {
                if (convertValidation.ok) setConvertConfirm(Math.trunc(convertPoints));
              }}
            >
              <DollarSign className="mr-1.5 h-4 w-4" />
              Convert to cash
            </Button>
          </CardContent>
        </Card>
      ) : null}

      {/* Redeem catalog */}
      <Card>
        <CardHeader>
          <CardTitle>Redeem points</CardTitle>
          <CardDescription>
            Cash rewards are credited to your{" "}
            <Link
              to="/custody/cash"
              className="font-medium text-primary underline-offset-4 hover:underline"
            >
              USD cash wallet
            </Link>
            .
          </CardDescription>
        </CardHeader>
        <CardContent>
          {catalogQ.isLoading ? (
            <Skeleton className="h-32 w-full" />
          ) : catalogPending ? (
            <PendingRewards label="The rewards catalog" />
          ) : catalogQ.isError ? (
            <p className="text-sm text-destructive">Could not load the rewards catalog.</p>
          ) : catalog.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              No rewards available to redeem yet.
            </p>
          ) : (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              {catalog.map((r) => (
                <div
                  key={r.id}
                  className="flex flex-col justify-between gap-3 rounded-lg border p-4"
                >
                  <div>
                    <div className="flex items-center justify-between gap-2">
                      <p className="font-medium">{r.name}</p>
                      <Badge variant={r.kind === "cash" ? "default" : "outline"}>
                        {r.kind === "cash" ? "Cash" : "Perk"}
                      </Badge>
                    </div>
                    <p className="mt-1 text-sm text-muted-foreground">{r.description}</p>
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <div className="text-sm">
                      <span className="font-semibold tabular-nums">
                        {formatPoints(r.cost_points)}
                      </span>
                      {r.kind === "cash" && r.value_cents > 0 ? (
                        <span className="text-muted-foreground">
                          {" "}
                          → {formatCents(r.value_cents)}
                        </span>
                      ) : null}
                    </div>
                    <Button
                      size="sm"
                      disabled={!r.affordable || redeemMut.isPending}
                      onClick={() => setPending(r)}
                    >
                      {r.affordable ? "Redeem" : "Locked"}
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* History */}
      <Card>
        <CardHeader>
          <CardTitle>Rewards history</CardTitle>
          <CardDescription>Points earned and redeemed.</CardDescription>
        </CardHeader>
        <CardContent>
          {historyQ.isLoading ? (
            <Skeleton className="h-24 w-full" />
          ) : historyPending ? (
            <PendingRewards label="Your rewards history" />
          ) : historyQ.isError ? (
            <p className="text-sm text-destructive">Could not load your rewards history.</p>
          ) : history.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              No rewards activity yet.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Date</TableHead>
                  <TableHead>Activity</TableHead>
                  <TableHead className="text-right">Points</TableHead>
                  <TableHead className="text-right">Cash</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {history.map((e, i) => (
                  <TableRow key={`${e.ts}-${i}`}>
                    <TableCell className="text-muted-foreground">
                      {e.ts ? new Date(e.ts * 1000).toLocaleDateString() : "—"}
                    </TableCell>
                    <TableCell>{e.description || e.type}</TableCell>
                    <TableCell className="text-right tabular-nums">
                      {e.points > 0 ? `+${formatPoints(e.points, false)}` : formatPoints(e.points, false)}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {e.cash_cents ? formatCents(e.cash_cents) : "—"}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{e.status}</Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
        <Gift className="h-3.5 w-3.5" /> Reward crediting is handled server-side; redemptions are
        applied to your account and, for cash rewards, your USD cash wallet.
      </p>

      <ConfirmDialog
        open={pending !== null}
        onOpenChange={(o) => {
          if (!o) setPending(null);
        }}
        title="Confirm redemption"
        description={confirmDescription}
        confirmLabel="Redeem"
        loading={redeemMut.isPending}
        onConfirm={() => {
          if (pending) redeemMut.mutate(pending.id);
        }}
      />

      <ConfirmDialog
        open={convertConfirm !== null}
        onOpenChange={(o) => {
          if (!o) setConvertConfirm(null);
        }}
        title="Convert points to cash"
        description={convertDescription}
        confirmLabel="Convert to cash"
        loading={convertMut.isPending}
        onConfirm={() => {
          if (convertConfirm !== null) convertMut.mutate(convertConfirm);
        }}
      />
    </div>
  );
}
