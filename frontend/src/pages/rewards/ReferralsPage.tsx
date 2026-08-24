import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Copy, Share2, Users, CheckCircle, DollarSign, Clock, Gift } from "lucide-react";
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

import { ApiError } from "@/api/client";
import { getReferralSummary, getReferralList } from "@/api/endpoints/rewards";
import type { ReferralEntry, ReferralStatus } from "@/api/endpoints/rewards";
import { formatCents, referralShareText } from "@/lib/rewards";
import { PendingRewards } from "./PendingRewards";

function is404(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

const STATUS_VARIANT: Record<ReferralStatus, "default" | "secondary" | "outline"> = {
  pending: "outline",
  qualified: "secondary",
  rewarded: "default",
};

function StatusBadge({ status }: { status: ReferralStatus }) {
  return <Badge variant={STATUS_VARIANT[status] ?? "outline"}>{status}</Badge>;
}

function StatCard({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
}) {
  return (
    <Card>
      <CardContent className="flex items-center gap-3 p-4">
        <div className="rounded-lg bg-muted p-2 text-muted-foreground">{icon}</div>
        <div>
          <p className="text-xs text-muted-foreground">{label}</p>
          <p className="text-lg font-semibold tabular-nums">{value}</p>
        </div>
      </CardContent>
    </Card>
  );
}

export default function ReferralsPage() {
  const summaryQ = useQuery({
    queryKey: ["me", "referral", "summary"],
    queryFn: getReferralSummary,
    retry: false,
  });
  const listQ = useQuery({
    queryKey: ["me", "referral", "list"],
    queryFn: getReferralList,
    retry: false,
  });

  const summary = summaryQ.data;
  const referrals: ReferralEntry[] = listQ.data?.referrals ?? [];

  const copyLink = async () => {
    const link = summary?.link;
    if (!link) return;
    try {
      await navigator.clipboard.writeText(link);
      toast.success("Referral link copied to clipboard");
    } catch {
      toast.error("Failed to copy link");
    }
  };

  const share = async () => {
    if (!summary) return;
    const text = referralShareText(summary.code, summary.link);
    const nav = navigator as Navigator & {
      share?: (data: { title?: string; text?: string; url?: string }) => Promise<void>;
    };
    if (typeof nav.share === "function") {
      try {
        await nav.share({ title: "Join me", text, url: summary.link || undefined });
        return;
      } catch {
        // user cancelled or share failed - fall through to clipboard
      }
    }
    try {
      await navigator.clipboard.writeText(text);
      toast.success("Invite text copied to clipboard");
    } catch {
      toast.error("Sharing is not available on this device");
    }
  };

  const summaryPending = is404(summaryQ.error);
  const listPending = is404(listQ.error);

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-4 md:p-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold">
            <Users className="h-6 w-6" /> Referrals
          </h1>
          <p className="text-sm text-muted-foreground">
            Share your code, track who joins, and earn a reward for every qualified referral.
          </p>
        </div>
        <Button asChild variant="outline" size="sm">
          <Link to="/rewards">
            <Gift className="mr-1.5 h-4 w-4" /> Rewards
          </Link>
        </Button>
      </div>

      {/* Your code + share */}
      <Card>
        <CardHeader>
          <CardTitle>Your referral code</CardTitle>
          <CardDescription>
            {summary?.reward_per_referral_cents
              ? `Earn ${formatCents(summary.reward_per_referral_cents)} for every referral that qualifies.`
              : "Invite friends and earn rewards when they qualify."}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {summaryQ.isLoading ? (
            <Skeleton className="h-10 w-full" />
          ) : summaryPending ? (
            <PendingRewards label="The referral program" />
          ) : summaryQ.isError ? (
            <p className="text-sm text-destructive">Could not load your referral details.</p>
          ) : summary ? (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <code className="rounded-md border bg-muted px-3 py-2 font-mono text-sm">
                  {summary.code || "—"}
                </code>
                {summary.link ? (
                  <span className="truncate rounded-md border bg-muted/50 px-3 py-2 text-xs text-muted-foreground">
                    {summary.link}
                  </span>
                ) : null}
              </div>
              <div className="flex flex-wrap gap-2">
                <Button onClick={copyLink} disabled={!summary.link}>
                  <Copy className="mr-1.5 h-4 w-4" /> Copy link
                </Button>
                <Button variant="outline" onClick={share}>
                  <Share2 className="mr-1.5 h-4 w-4" /> Share
                </Button>
              </div>
            </>
          ) : null}
        </CardContent>
      </Card>

      {/* Stats */}
      {summary && !summaryPending ? (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          <StatCard icon={<Users className="h-4 w-4" />} label="Referred" value={summary.referred_count} />
          <StatCard
            icon={<CheckCircle className="h-4 w-4" />}
            label="Qualified"
            value={summary.qualified_count}
          />
          <StatCard
            icon={<DollarSign className="h-4 w-4" />}
            label="Earned"
            value={formatCents(summary.earned_reward_cents)}
          />
          <StatCard
            icon={<Clock className="h-4 w-4" />}
            label="Pending"
            value={formatCents(summary.pending_reward_cents)}
          />
        </div>
      ) : null}

      {/* Referral list */}
      <Card>
        <CardHeader>
          <CardTitle>Your referrals</CardTitle>
          <CardDescription>People who joined with your code.</CardDescription>
        </CardHeader>
        <CardContent>
          {listQ.isLoading ? (
            <Skeleton className="h-24 w-full" />
          ) : listPending ? (
            <PendingRewards label="Your referral list" />
          ) : listQ.isError ? (
            <p className="text-sm text-destructive">Could not load your referrals.</p>
          ) : referrals.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              No referrals yet. Share your link to get started.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Referral</TableHead>
                  <TableHead>Joined</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Reward</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {referrals.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell className="font-medium">{r.masked_name}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {r.joined_ts ? new Date(r.joined_ts * 1000).toLocaleDateString() : "—"}
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={r.status} />
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {formatCents(r.reward_cents)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <p className="text-xs text-muted-foreground">
        Reward crediting is handled server-side. A referral becomes eligible once it qualifies;
        cash rewards are credited to your{" "}
        <Link to="/custody/cash" className="font-medium text-primary underline-offset-4 hover:underline">
          USD cash wallet
        </Link>
        .
      </p>
    </div>
  );
}
