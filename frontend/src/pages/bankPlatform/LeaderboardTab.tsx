/**
 * PLT-002: Metrics Leaderboard tab.
 *
 * Endpoint: GET /v1/admin/api-usage/leaderboard
 * Auth: admin-only (filemgr_admin_users allowlist)
 * Flag gate: OPEN_BANK_PROJECT_ENABLED + METRICS_LEADERBOARD_ENABLED → 404 when off.
 *
 * Shows top consumers (by API key) or top endpoints (by route) ranked by a
 * chosen metric for the current or a past billing period.
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Gauge, Users, BarChart2, RefreshCw } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError } from "@/api/client";
import {
  getLeaderboard,
  type LeaderboardDimension,
  type LeaderboardMetric,
  type LeaderboardItem,
} from "@/api/endpoints/bankPlatform";

const DIMENSION_OPTS: { value: LeaderboardDimension; label: string }[] = [
  { value: "consumers", label: "Top Consumers (API keys)" },
  { value: "endpoints", label: "Top Endpoints (routes)" },
];

const METRIC_OPTS: { value: LeaderboardMetric; label: string }[] = [
  { value: "cost_subtotal_micros", label: "Cost (micros)" },
  { value: "calls_total", label: "Total calls" },
  { value: "request_units_total", label: "Request units" },
];

function fmtMicros(v: number) {
  if (v === 0) return "$0.00";
  const dollars = v / 1_000_000;
  return `$${dollars.toFixed(4)}`;
}

function fmtMetricValue(metric: LeaderboardMetric, item: LeaderboardItem) {
  if (metric === "cost_subtotal_micros") return fmtMicros(item.cost_subtotal_micros);
  if (metric === "calls_total") return item.calls_total.toLocaleString();
  return item.request_units_total.toLocaleString();
}

export default function LeaderboardTab() {
  const [dimension, setDimension] = useState<LeaderboardDimension>("consumers");
  const [metric, setMetric] = useState<LeaderboardMetric>("cost_subtotal_micros");
  const [topN, setTopN] = useState(10);
  const [periodId, setPeriodId] = useState(() => {
    const now = new Date();
    return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`;
  });
  const [userSubFilter, setUserSubFilter] = useState("");

  const query = useQuery({
    queryKey: ["bank-platform", "leaderboard", dimension, metric, topN, periodId, userSubFilter],
    queryFn: () =>
      getLeaderboard({
        dimension,
        metric,
        top_n: topN,
        period_id: periodId || undefined,
        user_sub_filter: userSubFilter.trim() || undefined,
      }),
    retry: false,
  });

  const isNotEnabled =
    query.error instanceof ApiError && (query.error.status === 404 || query.error.status === 403 || query.error.status === 503);

  if (isNotEnabled) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Gauge className="h-5 w-5" />
            Metrics Leaderboard
          </CardTitle>
          <CardDescription>
            {query.error instanceof ApiError && query.error.status === 403
              ? "You need admin privileges to view the metrics leaderboard."
              : "The metrics leaderboard is not enabled. Set OPEN_BANK_PROJECT_ENABLED=1 and METRICS_LEADERBOARD_ENABLED=1."}
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }

  const items = query.data?.items ?? [];
  const scope = query.data?.scope;
  const totalScanned = query.data?.total_rows_scanned ?? 0;

  return (
    <div className="flex flex-col gap-4">
      {/* Controls */}
      <Card>
        <CardContent className="pt-4">
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <div className="flex flex-col gap-1.5">
              <Label className="text-xs">Dimension</Label>
              <Select value={dimension} onValueChange={(v) => setDimension(v as LeaderboardDimension)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {DIMENSION_OPTS.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="flex flex-col gap-1.5">
              <Label className="text-xs">Metric</Label>
              <Select value={metric} onValueChange={(v) => setMetric(v as LeaderboardMetric)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {METRIC_OPTS.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="flex flex-col gap-1.5">
              <Label className="text-xs">Period (YYYY-MM)</Label>
              <Input
                value={periodId}
                onChange={(e) => setPeriodId(e.target.value)}
                placeholder="2026-06"
                maxLength={7}
              />
            </div>

            <div className="flex flex-col gap-1.5">
              <Label className="text-xs">Top N</Label>
              <Select value={String(topN)} onValueChange={(v) => setTopN(Number(v))}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {[5, 10, 25, 50, 100].map((n) => (
                    <SelectItem key={n} value={String(n)}>
                      Top {n}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="mt-3 flex items-end gap-3">
            <div className="flex flex-col gap-1.5 flex-1 max-w-xs">
              <Label className="text-xs">User sub filter (optional)</Label>
              <Input
                value={userSubFilter}
                onChange={(e) => setUserSubFilter(e.target.value)}
                placeholder="Scope to a single user sub…"
              />
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => query.refetch()}
              disabled={query.isFetching}
              className="gap-1.5"
            >
              <RefreshCw className={`h-4 w-4 ${query.isFetching ? "animate-spin" : ""}`} />
              Refresh
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Loading */}
      {query.isLoading && (
        <div className="flex flex-col gap-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-14" />
          ))}
        </div>
      )}

      {/* Error */}
      {query.isError && !isNotEnabled && (
        <Card className="border-destructive">
          <CardContent className="pt-4 text-sm text-destructive">
            {query.error instanceof Error ? query.error.message : "Failed to load leaderboard"}
          </CardContent>
        </Card>
      )}

      {/* Results */}
      {!query.isLoading && !query.isError && (
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-base flex items-center gap-2">
                {dimension === "consumers" ? (
                  <Users className="h-4 w-4" />
                ) : (
                  <BarChart2 className="h-4 w-4" />
                )}
                {dimension === "consumers" ? "Top API Consumers" : "Top Endpoints"}
              </CardTitle>
              <div className="flex items-center gap-2">
                {scope && (
                  <Badge variant="secondary" className="text-xs">
                    {scope === "user" ? "User scope" : "Platform-wide"}
                  </Badge>
                )}
                <span className="text-xs text-muted-foreground">{totalScanned} rows scanned</span>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {items.length === 0 ? (
              <p className="text-sm text-muted-foreground py-6 text-center">
                No data for period {periodId}.
              </p>
            ) : (
              <div className="flex flex-col divide-y">
                {items.map((item) => (
                  <LeaderboardRow
                    key={item.id}
                    item={item}
                    metric={metric}
                    dimension={dimension}
                  />
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function LeaderboardRow({
  item,
  metric,
}: {
  item: LeaderboardItem;
  metric: LeaderboardMetric;
  dimension: LeaderboardDimension;
}) {
  return (
    <div className="flex items-center gap-3 py-3">
      <span className="w-7 shrink-0 text-right text-sm font-mono text-muted-foreground">
        #{item.rank}
      </span>
      <div className="flex flex-1 min-w-0 flex-col gap-0.5">
        <span className="truncate text-sm font-mono">
          {item.id || "—"}
        </span>
        {item.user_sub && (
          <span className="truncate text-xs text-muted-foreground">{item.user_sub}</span>
        )}
      </div>
      <div className="shrink-0 text-right">
        <span className="text-sm font-semibold tabular-nums">
          {fmtMetricValue(metric, item)}
        </span>
        <div className="text-xs text-muted-foreground">
          {item.calls_total.toLocaleString()} calls
        </div>
      </div>
    </div>
  );
}
