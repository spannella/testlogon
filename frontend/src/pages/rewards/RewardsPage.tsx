import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Award, Coins, Wallet, Sparkles, Gift, Users } from "lucide-react";
import { toast } from "sonner";

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
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";

import { ApiError } from "@/api/client";
import {
  getRewards,
  getRewardsHistory,
  getRewardsCatalog,
  redeemReward,
} from "@/api/endpoints/rewards";
import type { CatalogReward, RewardHistoryEntry } from "@/api/endpoints/rewards";
import {
  formatCents,
  formatPoints,
  pointsAfterRedeem,
  redeemableCatalog,
} from "@/lib/rewards";
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

  const rewards = rewardsQ.data;
  const points = rewards?.points ?? 0;
  const history: RewardHistoryEntry[] = historyQ.data?.entries ?? [];
  const catalog = redeemableCatalog(catalogQ.data?.rewards ?? [], points);

  const redeemMut = useMutation({
    mutationFn: (rewardId: string) => redeemReward(rewardId),
    onSuccess: (res) => {
      toast.success(`Redeemed. ${formatPoints(res.points_remaining)} remaining.`);
      qc.invalidateQueries({ queryKey: ["me", "rewards"] });
      qc.invalidateQueries({ queryKey: ["ui", "billing", "wallet"] });
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

  const rewardsPending = is404(rewardsQ.error);
  const historyPending = is404(historyQ.error);
  const catalogPending = is404(catalogQ.error);

  const confirmDescription = pending
    ? pending.kind === "cash"
      ? `Redeem ${formatPoints(pending.cost_points)} for ${formatCents(pending.value_cents)}? This credits your USD cash wallet. You will have ${formatPoints(pointsAfterRedeem(points, pending.cost_points))} left.`
      : `Redeem ${formatPoints(pending.cost_points)} for "${pending.name}"? You will have ${formatPoints(pointsAfterRedeem(points, pending.cost_points))} left.`
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
            {rewards.ways_to_earn.length === 0 ? (
              <p className="py-4 text-center text-sm text-muted-foreground">
                No earning opportunities listed right now.
              </p>
            ) : (
              <ul className="divide-y">
                {rewards.ways_to_earn.map((w) => (
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
    </div>
  );
}
