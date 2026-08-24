import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Award, Crown, Check, Lock, Sparkles, ArrowLeft } from "lucide-react";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";

import { ApiError } from "@/api/client";
import { getRewards, getRewardsStatus } from "@/api/endpoints/rewards";
import { formatPoints } from "@/lib/rewards";
import {
  STATUS_TIERS,
  resolveStatus,
  statusTierForPoints,
  multiplierLabel,
} from "@/lib/statusTiers";

function is404(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

export default function RewardsStatusPage() {
  const statusQ = useQuery({
    queryKey: ["me", "rewards", "status"],
    queryFn: getRewardsStatus,
    retry: false,
  });
  const rewardsQ = useQuery({
    queryKey: ["me", "rewards", "summary"],
    queryFn: getRewards,
    retry: false,
  });

  const authoritative = statusQ.isSuccess ? statusQ.data : null;
  const lifetimePoints = rewardsQ.data?.lifetime_points ?? 0;

  const resolved = resolveStatus(lifetimePoints, authoritative);

  const loading =
    (statusQ.isLoading || rewardsQ.isLoading) &&
    !statusQ.isSuccess &&
    !rewardsQ.isSuccess;

  const rewardsUnavailable =
    rewardsQ.isError && !is404(rewardsQ.error) && !authoritative;
  const rewardsPending = is404(rewardsQ.error) && !authoritative;

  const achievedTierId = statusTierForPoints(resolved.lifetimePoints).id;
  const achievedThreshold =
    STATUS_TIERS.find((t) => t.id === achievedTierId)?.thresholdPoints ?? 0;

  return (
    <div className="mx-auto max-w-3xl space-y-6 p-4 md:p-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold">
            <Crown className="h-6 w-6" /> Rewards Status
          </h1>
          <p className="text-sm text-muted-foreground">
            Your loyalty membership tier, earned by lifetime reward points. Higher
            tiers earn points faster and unlock perks.
          </p>
        </div>
        <Button asChild variant="outline" size="sm">
          <Link to="/rewards">
            <ArrowLeft className="mr-1.5 h-4 w-4" /> Rewards
          </Link>
        </Button>
      </div>

      {loading ? (
        <>
          <Skeleton className="h-40 w-full" />
          <Skeleton className="h-64 w-full" />
        </>
      ) : rewardsUnavailable ? (
        <Card>
          <CardContent className="p-6 text-center text-sm text-muted-foreground">
            Could not load your rewards status right now. Please try again later.
          </CardContent>
        </Card>
      ) : (
        <>
          <Card>
            <CardHeader>
              <div className="flex items-start justify-between gap-3">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Award className="h-5 w-5" /> {resolved.name}
                  </CardTitle>
                  <CardDescription>
                    {resolved.source === "authoritative"
                      ? "Your current membership tier."
                      : rewardsPending
                        ? "Estimated tier — the rewards program has not shipped yet."
                        : "Estimated from your lifetime points."}
                  </CardDescription>
                </div>
                <Badge variant={resolved.source === "authoritative" ? "default" : "secondary"}>
                  {resolved.source === "authoritative" ? "Live" : "Est"}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div className="rounded-lg border p-4">
                  <p className="text-xs text-muted-foreground">Lifetime points</p>
                  <p className="text-xl font-semibold tabular-nums">
                    {formatPoints(resolved.lifetimePoints, false)}
                  </p>
                </div>
                <div className="rounded-lg border p-4">
                  <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
                    <Sparkles className="h-3.5 w-3.5" /> Points multiplier
                  </p>
                  <p className="text-xl font-semibold tabular-nums text-primary">
                    {multiplierLabel(resolved.multiplierBps)}
                  </p>
                </div>
              </div>

              {resolved.nextName ? (
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">
                      {formatPoints(resolved.pointsToNext)} to {resolved.nextName}
                    </span>
                    <span className="tabular-nums text-muted-foreground">
                      {Math.round(resolved.progressFraction * 100)}%
                    </span>
                  </div>
                  <Progress value={resolved.progressFraction * 100} max={100} />
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">
                  You have reached the top tier — every perk is unlocked.
                </p>
              )}

              {resolved.perks.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {resolved.perks.map((p) => (
                    <Badge key={p} variant="outline">
                      {p}
                    </Badge>
                  ))}
                </div>
              ) : null}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Tier ladder</CardTitle>
              <CardDescription>
                Reach each tier by earning lifetime reward points.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {STATUS_TIERS.map((t) => {
                const isCurrent = t.id === achievedTierId;
                const isAchieved = t.thresholdPoints <= achievedThreshold;
                return (
                  <div
                    key={t.id}
                    className={
                      "rounded-lg border p-4 " +
                      (isCurrent ? "border-primary bg-primary/5" : "")
                    }
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div className="flex items-center gap-2">
                        {isAchieved ? (
                          <Check className="h-4 w-4 text-primary" />
                        ) : (
                          <Lock className="h-4 w-4 text-muted-foreground" />
                        )}
                        <span className="font-medium">{t.name}</span>
                        {isCurrent ? (
                          <Badge variant="default" className="ml-1">
                            Current
                          </Badge>
                        ) : null}
                      </div>
                      <div className="text-right">
                        <p className="text-sm font-semibold tabular-nums">
                          {multiplierLabel(t.multiplierBps)}
                        </p>
                        <p className="text-xs text-muted-foreground tabular-nums">
                          {formatPoints(t.thresholdPoints)}
                        </p>
                      </div>
                    </div>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {t.perks.map((p) => (
                        <Badge key={p} variant="secondary" className="font-normal">
                          {p}
                        </Badge>
                      ))}
                    </div>
                  </div>
                );
              })}
            </CardContent>
          </Card>

          <p className="text-xs text-muted-foreground">
            Status tiers are a loyalty ladder based on lifetime reward points and are
            separate from your{" "}
            <Link
              to="/fees"
              className="font-medium text-primary underline-offset-4 hover:underline"
            >
              trading fee tier
            </Link>
            .
          </p>
        </>
      )}
    </div>
  );
}
