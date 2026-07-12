import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, BarChart3, TrendingDown, AlertTriangle, Pencil } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { ApiError } from "@/api/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  getSurvey,
  getSurveyAnalytics,
  getDistributionSummary,
  type SurveyVersionAnalytics,
} from "@/api/endpoints/crmSurveys";

function pct(rate: number): string {
  return `${(rate * 100).toFixed(1)}%`;
}

function fmtDuration(secs: number | null): string {
  if (secs == null) return "—";
  if (secs < 60) return `${Math.round(secs)}s`;
  const m = Math.floor(secs / 60);
  const s = Math.round(secs % 60);
  return `${m}m ${s}s`;
}

function VersionCard({ v }: { v: SurveyVersionAnalytics }) {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="text-base">
            Version {v.version_number ?? "—"}
          </CardTitle>
          <Badge variant="secondary">{pct(v.funnel.completion_rate)} complete</Badge>
        </div>
        <CardDescription>
          {v.funnel.completions} of {v.funnel.starts} responses · avg{" "}
          {fmtDuration(v.average_completion_seconds)}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <Progress value={Math.round(v.funnel.completion_rate * 100)} />

        {v.dropoff_points.length > 0 ? (
          <div>
            <p className="mb-2 flex items-center gap-1.5 text-sm font-medium">
              <TrendingDown className="h-4 w-4 text-muted-foreground" />
              Drop-off points
            </p>
            <ul className="space-y-1 text-sm">
              {v.dropoff_points.map((d, i) => (
                <li key={i} className="flex justify-between gap-2">
                  <span className="truncate text-muted-foreground">{d.label}</span>
                  <span className="font-medium">{d.count}</span>
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {v.validation_hotspots.length > 0 ? (
          <div>
            <p className="mb-2 flex items-center gap-1.5 text-sm font-medium">
              <AlertTriangle className="h-4 w-4 text-muted-foreground" />
              Validation hotspots
            </p>
            <ul className="space-y-1 text-sm">
              {v.validation_hotspots.map((h, i) => (
                <li key={i} className="flex justify-between gap-2">
                  <span className="truncate text-muted-foreground">{h.key}</span>
                  <span className="font-medium">{h.count}</span>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

export default function CrmSurveyResultsPage() {
  const { surveyId = "" } = useParams<{ surveyId: string }>();

  const surveyQuery = useQuery({
    queryKey: ["crm-surveys", surveyId],
    queryFn: () => getSurvey(surveyId),
    enabled: !!surveyId,
    retry: false,
  });

  const analyticsQuery = useQuery({
    queryKey: ["crm-surveys", surveyId, "analytics"],
    queryFn: () => getSurveyAnalytics(surveyId),
    enabled: !!surveyId,
    retry: false,
  });

  const distributionQuery = useQuery({
    queryKey: ["crm-surveys", surveyId, "distribution-summary"],
    queryFn: () => getDistributionSummary(surveyId),
    enabled: !!surveyId,
    // Distribution is flag-gated; 404/503 means "not enabled" — don't retry.
    retry: (count, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return count < 1;
    },
  });

  const survey = surveyQuery.data?.draft;
  const analytics = analyticsQuery.data?.analytics;
  const distribution = distributionQuery.data;
  const distributionDisabled =
    distributionQuery.isError &&
    distributionQuery.error instanceof ApiError &&
    (distributionQuery.error.status === 404 || distributionQuery.error.status === 503);

  return (
    <div className="space-y-6">
      <Button asChild variant="ghost" size="sm">
        <Link to="/crm/surveys">
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to surveys
        </Link>
      </Button>

      <PageHeader
        title={survey ? `${survey.title} — Results` : "Survey results"}
        description="Response funnel, completion analytics, and distribution summary."
        actions={
          <Button asChild variant="outline" size="sm">
            <Link to={`/crm/surveys/${encodeURIComponent(surveyId)}/build`}>
              <Pencil className="mr-1.5 h-4 w-4" />
              Edit survey
            </Link>
          </Button>
        }
      />

      {surveyQuery.isError ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-destructive">
            Survey not found or you do not have access.
          </CardContent>
        </Card>
      ) : null}

      {/* Distribution summary */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Distribution</CardTitle>
          <CardDescription>Invitation reach and response rate.</CardDescription>
        </CardHeader>
        <CardContent>
          {distributionDisabled ? (
            <p className="text-sm text-muted-foreground">
              Survey distribution is not enabled on this platform.
            </p>
          ) : distributionQuery.isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : distribution ? (
            <div className="grid grid-cols-3 gap-4 text-center">
              <div>
                <p className="text-2xl font-semibold">{distribution.total_sent}</p>
                <p className="text-xs text-muted-foreground">Invitations sent</p>
              </div>
              <div>
                <p className="text-2xl font-semibold">{distribution.total_responses}</p>
                <p className="text-xs text-muted-foreground">Responses</p>
              </div>
              <div>
                <p className="text-2xl font-semibold">{pct(distribution.response_rate)}</p>
                <p className="text-xs text-muted-foreground">Response rate</p>
              </div>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No distribution data.</p>
          )}
        </CardContent>
      </Card>

      {/* Overall totals */}
      {analyticsQuery.isLoading ? (
        <Card>
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            Loading analytics…
          </CardContent>
        </Card>
      ) : analyticsQuery.isError ? (
        <Card>
          <CardContent className="py-8 text-center text-sm text-destructive">
            Failed to load analytics.
            <div className="mt-3">
              <Button variant="outline" size="sm" onClick={() => analyticsQuery.refetch()}>
                Retry
              </Button>
            </div>
          </CardContent>
        </Card>
      ) : analytics ? (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <BarChart3 className="h-4 w-4" />
                Overall
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-4 text-center sm:grid-cols-4">
                <div>
                  <p className="text-2xl font-semibold">{analytics.totals.starts}</p>
                  <p className="text-xs text-muted-foreground">Started</p>
                </div>
                <div>
                  <p className="text-2xl font-semibold">{analytics.totals.completions}</p>
                  <p className="text-xs text-muted-foreground">Completed</p>
                </div>
                <div>
                  <p className="text-2xl font-semibold">
                    {analytics.totals.starts
                      ? pct(analytics.totals.completions / analytics.totals.starts)
                      : "—"}
                  </p>
                  <p className="text-xs text-muted-foreground">Completion rate</p>
                </div>
                <div>
                  <p className="text-2xl font-semibold">{analytics.versions.length}</p>
                  <p className="text-xs text-muted-foreground">Versions</p>
                </div>
              </div>
            </CardContent>
          </Card>

          {analytics.totals.top_dropoffs.length > 0 ? (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Top drop-off points</CardTitle>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Where</TableHead>
                      <TableHead className="text-right">Count</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {analytics.totals.top_dropoffs.map((d, i) => (
                      <TableRow key={i}>
                        <TableCell>{d.label}</TableCell>
                        <TableCell className="text-right">{d.count}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          ) : null}

          <div>
            <h2 className="mb-3 text-lg font-medium">By version</h2>
            {analytics.versions.length === 0 ? (
              <Card>
                <CardContent className="py-10 text-center text-sm text-muted-foreground">
                  No published versions yet. Publish the survey to start collecting responses.
                </CardContent>
              </Card>
            ) : (
              <div className="grid gap-4 md:grid-cols-2">
                {analytics.versions.map((v) => (
                  <VersionCard key={v.version_id} v={v} />
                ))}
              </div>
            )}
          </div>
        </>
      ) : null}
    </div>
  );
}
