import * as React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { ExportCsvButton } from "@/components/shared/ExportCsvButton";
import type { QuestionnaireVersionAnalytics, QuestionnaireAnalyticsPoint } from "@/api/types";

// ─── Types ────────────────────────────────────────────────────────────────────

interface AnalyticsData {
  generated_at: string;
  freshness_sla_seconds: number;
  versions: QuestionnaireVersionAnalytics[];
  totals: {
    starts: number;
    completions: number;
    top_dropoffs: QuestionnaireAnalyticsPoint[];
    top_validation_hotspots: QuestionnaireAnalyticsPoint[];
  };
}

interface QuestionnaireAnalyticsTabProps {
  analytics: AnalyticsData | undefined;
  isLoading: boolean;
  questionnaireId?: string;
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function FunnelChart({
  starts,
  completions,
  rate,
}: {
  starts: number;
  completions: number;
  rate: number;
}) {
  const completionWidth = starts > 0 ? Math.max(5, (completions / starts) * 100) : 0;
  const pct = Math.round(rate * 100);

  if (starts === 0) {
    return (
      <div
        className="flex items-center justify-center h-24 text-muted-foreground text-sm"
        data-testid="analytics-funnel-chart"
      >
        No responses yet
      </div>
    );
  }

  return (
    <div className="space-y-3" data-testid="analytics-funnel-chart">
      <div className="space-y-1">
        <div className="flex items-center gap-3">
          <div
            className="h-10 rounded-md bg-blue-500 transition-all duration-500"
            style={{ width: "100%" }}
          />
          <span className="text-sm font-medium whitespace-nowrap">
            {starts} started
          </span>
        </div>
        <div className="flex items-center gap-3">
          <div
            className="h-10 rounded-md bg-green-500 transition-all duration-500"
            style={{ width: `${completionWidth}%` }}
          />
          <span className="text-sm font-medium whitespace-nowrap">
            {completions} completed
          </span>
        </div>
      </div>
      <div className="text-center text-sm text-muted-foreground">
        {pct}% completion rate
      </div>
    </div>
  );
}

function CompletionGauge({ rate }: { rate: number }) {
  const pct = Math.round(rate * 100);
  const radius = 45;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (pct / 100) * circumference;

  // Color based on rate
  const color =
    pct >= 70 ? "text-green-500" : pct >= 40 ? "text-yellow-500" : "text-red-500";

  return (
    <div className="relative" data-testid="analytics-completion-gauge">
      <svg viewBox="0 0 100 100" className="h-28 w-28">
        {/* Background circle */}
        <circle
          cx="50"
          cy="50"
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth="8"
          className="text-muted/20"
        />
        {/* Progress circle */}
        <circle
          cx="50"
          cy="50"
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth="8"
          className={color}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 50 50)"
          style={{ transition: "stroke-dashoffset 0.8s ease-out" }}
        />
        {/* Center text */}
        <text
          x="50"
          y="50"
          textAnchor="middle"
          dominantBaseline="central"
          className="fill-foreground font-bold"
          style={{ fontSize: "20px" }}
        >
          {pct}%
        </text>
      </svg>
    </div>
  );
}

function DropoffBarChart({
  dropoffs,
}: {
  dropoffs: QuestionnaireAnalyticsPoint[];
}) {
  if (dropoffs.length === 0) {
    return (
      <div className="text-sm text-muted-foreground py-2" data-testid="analytics-dropoff-chart">
        No drop-off points recorded
      </div>
    );
  }

  const maxCount = Math.max(...dropoffs.map((d) => d.count));

  return (
    <div className="space-y-2" data-testid="analytics-dropoff-chart">
      {dropoffs.map((item, idx) => {
        const widthPct =
          maxCount > 0 ? Math.max(5, (item.count / maxCount) * 100) : 0;
        const severity = item.count / maxCount;
        const barColor =
          severity > 0.5
            ? "bg-red-500"
            : severity > 0.25
              ? "bg-orange-400"
              : "bg-gray-400";

        return (
          <div key={`${item.label}-${idx}`} className="flex items-center gap-3">
            <div
              className="w-40 truncate text-xs text-right"
              title={item.label || ""}
            >
              {item.label}
            </div>
            <div className="flex-1 h-6 rounded bg-muted/30 overflow-hidden">
              <div
                className={`h-full rounded ${barColor} transition-all duration-500`}
                style={{ width: `${widthPct}%` }}
              />
            </div>
            <span className="text-xs font-medium w-8 text-right">
              {item.count}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function HotspotList({
  hotspots,
}: {
  hotspots: QuestionnaireAnalyticsPoint[];
}) {
  if (hotspots.length === 0) {
    return (
      <div className="text-sm text-muted-foreground py-2" data-testid="analytics-hotspot-chart">
        No validation errors recorded
      </div>
    );
  }

  const maxCount = Math.max(...hotspots.map((h) => h.count));

  const humanize = (key: string): string => {
    const map: Record<string, string> = {
      "form:submit": "Form submission error",
      "form:validate": "Form validation error",
    };
    return map[key] || key.replace(/_/g, " ").replace(/^q /, "Question: ");
  };

  return (
    <TooltipProvider>
      <div className="space-y-1.5" data-testid="analytics-hotspot-chart">
        {hotspots.map((item, idx) => {
          const severity = item.count / maxCount;
          const badgeVariant: "destructive" | "secondary" | "outline" =
            severity > 0.5
              ? "destructive"
              : severity > 0.25
                ? "secondary"
                : "outline";

          return (
            <Tooltip key={`${item.key}-${idx}`}>
              <TooltipTrigger asChild>
                <div className="flex items-center justify-between rounded px-2 py-1.5 hover:bg-muted/50 cursor-default">
                  <span className="text-sm">{humanize(item.key || "")}</span>
                  <Badge variant={badgeVariant} className="text-xs">
                    {item.count} error{item.count !== 1 ? "s" : ""}
                  </Badge>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                <p>
                  Error key: <code>{item.key}</code>
                </p>
                <p>Count: {item.count}</p>
              </TooltipContent>
            </Tooltip>
          );
        })}
      </div>
    </TooltipProvider>
  );
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const min = Math.floor(seconds / 60);
  const sec = Math.round(seconds % 60);
  return sec > 0 ? `${min}m ${sec}s` : `${min}m`;
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function QuestionnaireAnalyticsTab({
  analytics,
  isLoading,
  questionnaireId,
}: QuestionnaireAnalyticsTabProps) {
  const [selectedVersion, setSelectedVersion] = React.useState<string>("totals");

  // Determine which data to show based on selected version
  const currentData = React.useMemo(() => {
    if (!analytics) return null;
    if (selectedVersion === "totals") {
      const totalStarts = analytics.totals.starts;
      const totalCompletions = analytics.totals.completions;
      return {
        funnel: {
          starts: totalStarts,
          completions: totalCompletions,
          completion_rate:
            totalStarts > 0 ? totalCompletions / totalStarts : 0,
        },
        dropoffs: analytics.totals.top_dropoffs,
        hotspots: analytics.totals.top_validation_hotspots,
        avgCompletionSeconds: null as number | null,
      };
    }
    const version = analytics.versions.find(
      (v) => v.version_id === selectedVersion,
    );
    if (!version) return null;
    return {
      funnel: version.funnel,
      dropoffs: version.dropoff_points,
      hotspots: version.validation_hotspots,
      avgCompletionSeconds: version.average_completion_seconds,
    };
  }, [analytics, selectedVersion]);

  if (isLoading) {
    return (
      <Card data-testid="questionnaire-analytics-card">
        <CardHeader>
          <CardTitle>Response analytics</CardTitle>
        </CardHeader>
        <CardContent>Loading analytics...</CardContent>
      </Card>
    );
  }

  if (!analytics || !currentData) {
    return (
      <Card data-testid="questionnaire-analytics-card">
        <CardHeader>
          <CardTitle>Response analytics</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">
          No analytics data available.
        </CardContent>
      </Card>
    );
  }

  return (
    <Card data-testid="questionnaire-analytics-card">
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>Response analytics</CardTitle>
        <div className="flex items-center gap-2">
          {questionnaireId && (
            <ExportCsvButton
              source="questionnaire_responses"
              params={{ questionnaire_id: questionnaireId }}
              label="Export Responses"
            />
          )}
        {analytics.versions.length > 1 && (
          <Select value={selectedVersion} onValueChange={setSelectedVersion}>
            <SelectTrigger className="w-48" data-testid="analytics-version-selector">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="totals">All versions (totals)</SelectItem>
              {analytics.versions.map((v) => (
                <SelectItem key={v.version_id} value={v.version_id}>
                  Version {v.version_number ?? "?"} ({v.version_id})
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        </div>
      </CardHeader>
      <CardContent className="space-y-6 text-sm">
        {/* Freshness indicator */}
        <div
          data-testid="analytics-freshness"
          className="text-xs text-muted-foreground"
        >
          Updated at {analytics.generated_at} (SLA{" "}
          {analytics.freshness_sla_seconds}s)
        </div>

        {/* Summary stats row */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div
            data-testid="analytics-total-starts"
            className="rounded-lg border p-3 text-center"
          >
            <div className="text-2xl font-bold">{currentData.funnel.starts}</div>
            <div className="text-xs text-muted-foreground">Started</div>
          </div>
          <div
            data-testid="analytics-total-completions"
            className="rounded-lg border p-3 text-center"
          >
            <div className="text-2xl font-bold">
              {currentData.funnel.completions}
            </div>
            <div className="text-xs text-muted-foreground">Completed</div>
          </div>
          <div
            data-testid="analytics-version-count"
            className="rounded-lg border p-3 text-center"
          >
            <div className="text-2xl font-bold">{analytics.versions.length}</div>
            <div className="text-xs text-muted-foreground">
              Published versions
            </div>
          </div>
        </div>

        {/* Funnel + Gauge row */}
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
          <FunnelChart
            starts={currentData.funnel.starts}
            completions={currentData.funnel.completions}
            rate={currentData.funnel.completion_rate}
          />
          <div className="flex flex-col items-center justify-center">
            <CompletionGauge rate={currentData.funnel.completion_rate} />
            {currentData.avgCompletionSeconds != null && (
              <div className="mt-2 text-xs text-muted-foreground">
                Avg completion: {formatDuration(currentData.avgCompletionSeconds)}
              </div>
            )}
          </div>
        </div>

        {/* Per-version funnel data-testid (preserved for backward compatibility) */}
        {analytics.versions.map((row) => (
          <div
            key={row.version_id}
            data-testid={`analytics-version-${row.version_id}`}
            className="hidden"
            aria-hidden="true"
          >
            <span data-testid={`analytics-funnel-${row.version_id}`}>
              Funnel: {row.funnel.starts} starts &rarr; {row.funnel.completions}{" "}
              completions ({Math.round((row.funnel.completion_rate || 0) * 100)}%)
            </span>
          </div>
        ))}

        {/* Dropoff bar chart */}
        <div>
          <h4 className="font-medium mb-2">Top drop-off points</h4>
          <DropoffBarChart dropoffs={currentData.dropoffs} />
          {/* Hidden list for backward compatibility */}
          <ul data-testid="analytics-dropoff-list" className="sr-only">
            {currentData.dropoffs.map((item) => (
              <li key={`${item.label}-${item.count}`}>
                {item.label}: {item.count}
              </li>
            ))}
          </ul>
        </div>

        {/* Validation hotspots */}
        <div>
          <h4 className="font-medium mb-2">Validation hotspots</h4>
          <HotspotList hotspots={currentData.hotspots} />
          {/* Hidden list for backward compatibility */}
          <ul data-testid="analytics-hotspot-list" className="sr-only">
            {currentData.hotspots.map((item) => (
              <li key={`${item.key}-${item.count}`}>
                {item.key}: {item.count}
              </li>
            ))}
          </ul>
        </div>
      </CardContent>
    </Card>
  );
}
