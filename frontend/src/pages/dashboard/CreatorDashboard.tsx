import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Trophy } from "lucide-react";
import { getDashboardSummary, refreshDashboard, listMilestones, acknowledgeMilestone } from "@/api/endpoints/dashboard";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import KpiCard from "./KpiCard";
import QuickActionBar from "./QuickActionBar";
import EarningsSummaryCard from "./EarningsSummaryCard";
import TopContentList from "./TopContentList";
import MilestoneSettingsDialog from "./MilestoneSettingsDialog";

function formatCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)}K`;
  return n.toLocaleString();
}

export default function CreatorDashboard() {
  const queryClient = useQueryClient();

  const { data: summary, isLoading } = useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: getDashboardSummary,
    refetchInterval: 60_000,
  });

  const { data: milestones } = useQuery({
    queryKey: ["milestones"],
    queryFn: listMilestones,
  });

  const refreshMut = useMutation({
    mutationFn: refreshDashboard,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["dashboard-summary"] });
    },
  });

  const ackMut = useMutation({
    mutationFn: (id: string) => acknowledgeMilestone(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["milestones"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard-summary"] });
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-32">
        <p className="text-muted-foreground">Loading dashboard...</p>
      </div>
    );
  }

  const warnings = summary?.warnings ?? [];
  const earningsBreakdown = summary?.earnings_breakdown ?? {
    subscriptions: 0,
    tips: 0,
    unlocks: 0,
    vod_purchases: 0,
    other: 0,
  };

  const unacknowledged = (milestones ?? []).filter((m) => !m.acknowledged);

  return (
    <div className="space-y-6 p-4 sm:p-6 max-w-4xl mx-auto">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Creator Dashboard</h1>
        <Button
          variant="outline"
          size="sm"
          onClick={() => refreshMut.mutate()}
          disabled={refreshMut.isPending}
        >
          {refreshMut.isPending ? "Refreshing..." : "Refresh"}
        </Button>
      </div>

      {/* Warnings */}
      {warnings.length > 0 && (
        <div
          className="flex items-center gap-2 rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive"
          data-testid="dashboard-warnings"
        >
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span>Some data sources are currently unavailable: {warnings.join(", ")}</span>
        </div>
      )}

      {/* Quick actions */}
      <QuickActionBar />

      {/* KPI cards - 2x2 grid on mobile, 4-col on sm+ */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <KpiCard
          label="Today's Earnings"
          value={formatCents(summary?.today_earnings_cents ?? 0)}
        />
        <KpiCard
          label="Subscribers"
          value={formatNumber(summary?.total_subscribers ?? 0)}
        />
        <KpiCard
          label="7d Views"
          value={formatNumber(summary?.period_views ?? 0)}
        />
        <KpiCard
          label="7d Revenue"
          value={formatCents(summary?.period_revenue_cents ?? 0)}
        />
      </div>

      {/* Earnings breakdown */}
      <EarningsSummaryCard breakdown={earningsBreakdown} currency={summary?.currency ?? "USD"} />

      {/* Active broadcasts */}
      {(summary?.active_broadcasts ?? []).length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Active Broadcasts</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {summary!.active_broadcasts.map((b) => (
                <li key={b.session_id} className="flex items-center gap-2 text-sm">
                  <span className="inline-block h-2 w-2 rounded-full bg-red-500 animate-pulse" />
                  <span>{b.name ?? b.session_id}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      {/* Top content */}
      <TopContentList items={summary?.top_content ?? []} />

      {/* Milestones */}
      {unacknowledged.length > 0 && (
        <Card>
          <CardHeader className="pb-2 flex flex-row items-center justify-between">
            <CardTitle className="text-base flex items-center gap-2">
              <Trophy className="h-4 w-4" />
              Milestones
            </CardTitle>
            <MilestoneSettingsDialog />
          </CardHeader>
          <CardContent className="space-y-3">
            {unacknowledged.map((m) => (
              <div key={m.milestone_id} className="flex items-center justify-between text-sm">
                <div>
                  <span className="font-medium">{m.formatted}</span>{" "}
                  <span className="text-muted-foreground">{m.metric.replace(/_/g, " ")}</span>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => ackMut.mutate(m.milestone_id)}
                  disabled={ackMut.isPending}
                >
                  Dismiss
                </Button>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
