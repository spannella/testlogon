import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, AlertTriangle } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { fetchKycMetrics } from "@/api/endpoints/kyc-admin";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatLatency(seconds: number | null | undefined): string {
  if (seconds == null) return "--";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`;
  return `${(seconds / 86400).toFixed(1)}d`;
}

function latencyColor(seconds: number | null | undefined): string {
  if (seconds == null) return "text-muted-foreground";
  if (seconds < 86400) return "text-green-600"; // < 24h
  if (seconds < 172800) return "text-yellow-600"; // 24-48h
  return "text-red-600"; // > 48h
}

const STATUS_LABELS: Record<string, string> = {
  draft: "Draft",
  submitted: "Submitted",
  under_review: "Under Review",
  needs_more_info: "Needs More Info",
  approved: "Approved",
  rejected: "Rejected",
  expired: "Expired",
};

const STATUS_COLORS: Record<string, string> = {
  draft: "bg-gray-400",
  submitted: "bg-blue-500",
  under_review: "bg-yellow-500",
  needs_more_info: "bg-orange-500",
  approved: "bg-green-500",
  rejected: "bg-red-500",
  expired: "bg-gray-300",
};

// ─── Component ────────────────────────────────────────────────────────────────

export default function KycMetricsDashboard() {
  const navigate = useNavigate();

  const metricsQuery = useQuery({
    queryKey: ["kyc-metrics"],
    queryFn: () => fetchKycMetrics(),
    staleTime: 60_000,
  });

  const metrics = metricsQuery.data?.metrics;

  const totalDecided =
    (metrics?.funnel_counts?.approved ?? 0) + (metrics?.funnel_counts?.rejected ?? 0);
  const approvalRate =
    totalDecided > 0
      ? ((metrics?.funnel_counts?.approved ?? 0) / totalDecided * 100).toFixed(1)
      : "--";

  const maxFunnelCount = metrics
    ? Math.max(1, ...Object.values(metrics.funnel_counts))
    : 1;

  return (
    <div className="container mx-auto max-w-6xl space-y-6 px-4 py-6">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="sm" onClick={() => navigate("/admin/kyc")}>
          <ArrowLeft className="mr-1 h-4 w-4" />
          Back to Queue
        </Button>
      </div>

      <PageHeader
        title="KYC Metrics"
        description="Overview of KYC verification funnel, latency, and queue health."
      />

      {metricsQuery.isLoading && (
        <p className="text-muted-foreground">Loading metrics...</p>
      )}

      {metrics && (
        <>
          {/* Stale Queue Alert */}
          {metrics.stale_queue_count > 0 && (
            <Card className="border-orange-500/50 bg-orange-50 dark:bg-orange-950/20">
              <CardContent className="flex items-center gap-3 py-4">
                <AlertTriangle className="h-5 w-5 text-orange-600" />
                <div>
                  <p className="font-medium text-orange-700 dark:text-orange-400" data-testid="stale-alert">
                    {metrics.stale_queue_count} stale case{metrics.stale_queue_count > 1 ? "s" : ""} in queue
                  </p>
                  <p className="text-sm text-orange-600/80 dark:text-orange-500/80">
                    Cases waiting longer than 48 hours for review.
                  </p>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Top Row: Funnel + Approval Rate */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            {/* Funnel Counts */}
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle className="text-sm font-medium">Funnel Counts</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {Object.entries(STATUS_LABELS).map(([status, label]) => {
                  const count = metrics.funnel_counts[status] ?? 0;
                  const pct = maxFunnelCount > 0 ? (count / maxFunnelCount) * 100 : 0;
                  return (
                    <div key={status} className="space-y-1">
                      <div className="flex items-center justify-between text-sm">
                        <span>{label}</span>
                        <span className="font-medium" data-testid={`funnel-${status}`}>
                          {count}
                        </span>
                      </div>
                      <div className="h-2 w-full rounded-full bg-muted">
                        <div
                          className={`h-2 rounded-full ${STATUS_COLORS[status] ?? "bg-gray-400"}`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </CardContent>
            </Card>

            {/* Approval Rate */}
            <Card>
              <CardHeader>
                <CardTitle className="text-sm font-medium">Approval Rate</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col items-center justify-center py-8">
                <span className="text-4xl font-bold" data-testid="approval-rate">
                  {approvalRate}
                  {approvalRate !== "--" && "%"}
                </span>
                <span className="text-sm text-muted-foreground mt-1">
                  {metrics.funnel_counts.approved ?? 0} approved / {totalDecided} decided
                </span>
              </CardContent>
            </Card>
          </div>

          {/* Latency Cards */}
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            {(["p50", "p90", "p99"] as const).map((pLabel) => {
              const val = metrics.review_latency_seconds?.[pLabel] as number | null | undefined;
              return (
                <Card key={pLabel}>
                  <CardHeader>
                    <CardTitle className="text-sm font-medium uppercase">
                      Review Latency {pLabel}
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="flex flex-col items-center py-6">
                    <span
                      className={`text-3xl font-bold ${latencyColor(val)}`}
                      data-testid={`latency-${pLabel}`}
                    >
                      {formatLatency(val)}
                    </span>
                    <span className="text-xs text-muted-foreground mt-1">
                      {val != null ? `${Math.round(val)}s` : "No data"}
                    </span>
                  </CardContent>
                </Card>
              );
            })}
          </div>

          {/* Sync Counters */}
          {Object.keys(metrics.ticket_sync_counters ?? {}).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm font-medium">Ticket Sync Counters</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(metrics.ticket_sync_counters).map(([key, count]) => (
                    <Badge key={key} variant="secondary">
                      {key}: {count}
                    </Badge>
                  ))}
                  {metrics.ticket_sync_deadletter_count > 0 && (
                    <Badge variant="destructive">
                      Dead letters: {metrics.ticket_sync_deadletter_count}
                    </Badge>
                  )}
                </div>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
