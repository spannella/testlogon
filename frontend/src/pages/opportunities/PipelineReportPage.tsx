import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { ArrowLeft, BarChart3 } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
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
import {
  formatCents,
  formatDate,
  getPipelineReport,
  stageLabel,
} from "@/api/endpoints/opportunities";
import { FeatureDisabledState } from "./FeatureDisabledState";

export default function PipelineReportPage() {
  const navigate = useNavigate();

  const reportQuery = useQuery({
    queryKey: ["opps", "pipeline-report"],
    queryFn: () => getPipelineReport(),
    retry: (count, err) =>
      !(err instanceof ApiError && err.status === 503) && count < 2,
  });

  const report = reportQuery.data;

  const maxAmount = useMemo(() => {
    if (!report) return 0;
    return Math.max(1, ...report.stages.map((s) => s.total_amount_cents));
  }, [report]);

  if (reportQuery.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-64" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (reportQuery.error instanceof ApiError && reportQuery.error.status === 503) {
    return (
      <div className="space-y-6">
        <Button variant="ghost" size="sm" onClick={() => navigate("/crm/opportunities")}>
          <ArrowLeft className="mr-1.5 h-4 w-4" />
          Back
        </Button>
        <FeatureDisabledState />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <Button variant="ghost" size="sm" onClick={() => navigate("/crm/opportunities")}>
        <ArrowLeft className="mr-1.5 h-4 w-4" />
        Back to pipeline
      </Button>

      <PageHeader
        title="Pipeline report"
        description="Funnel breakdown of your open and closed deals by stage."
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">
              Total amount
            </CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-semibold">
            {formatCents(report?.total_amount_cents ?? 0)}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">
              Weighted total
            </CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-semibold">
            {formatCents(report?.total_weighted_cents ?? 0)}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">
              Generated
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm">
            {report ? new Date(report.generated_at * 1000).toLocaleString() : "—"}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <BarChart3 className="h-4 w-4" />
            Funnel by stage
          </CardTitle>
        </CardHeader>
        <CardContent>
          {!report || report.stages.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">
              No pipeline data available.
            </p>
          ) : (
            <>
              {/* Visual funnel bars */}
              <div className="mb-6 space-y-2">
                {report.stages.map((s) => (
                  <div key={s.stage} className="flex items-center gap-3">
                    <span className="w-40 shrink-0 text-sm">
                      {s.label || stageLabel(s.stage)}
                    </span>
                    <div className="h-6 flex-1 overflow-hidden rounded bg-muted">
                      <div
                        className="h-full rounded bg-primary/80"
                        style={{
                          width: `${(s.total_amount_cents / maxAmount) * 100}%`,
                        }}
                      />
                    </div>
                    <span className="w-28 shrink-0 text-right text-xs font-medium">
                      {formatCents(s.total_amount_cents)}
                    </span>
                  </div>
                ))}
              </div>

              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Stage</TableHead>
                    <TableHead className="text-right">Count</TableHead>
                    <TableHead className="text-right">Amount</TableHead>
                    <TableHead className="text-right">Weighted</TableHead>
                    <TableHead className="text-right">Avg close</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {report.stages.map((s) => (
                    <TableRow key={s.stage} data-testid="funnel-row">
                      <TableCell className="font-medium">
                        {s.label || stageLabel(s.stage)}
                      </TableCell>
                      <TableCell className="text-right">{s.count}</TableCell>
                      <TableCell className="text-right">
                        {formatCents(s.total_amount_cents)}
                      </TableCell>
                      <TableCell className="text-right">
                        {formatCents(s.weighted_amount_cents)}
                      </TableCell>
                      <TableCell className="text-right">
                        {formatDate(s.avg_close_date)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
