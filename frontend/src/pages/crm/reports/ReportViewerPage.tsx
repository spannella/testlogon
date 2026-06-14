import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft, Play, RefreshCw, Save, BarChart3 } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import {
  getReport,
  runReport,
  updateReport,
  type ChartType,
  type ReportRunOut,
} from "@/api/endpoints/crmReports";
import { ReportChart } from "./ReportChart";
import { ReportSchedules } from "./ReportSchedules";
import { ReportsNotEnabled } from "./ReportsNotEnabled";
import { fmtCell, fmtTs, isNotEnabled, looksLikeCents, fmtCents, moduleLabel } from "./reportUtils";

export default function ReportViewerPage() {
  const { reportId = "" } = useParams<{ reportId: string }>();
  const qc = useQueryClient();

  const [lastRun, setLastRun] = useState<ReportRunOut | null>(null);

  // Chart config editor state
  const [chartType, setChartType] = useState<ChartType>("bar");
  const [xField, setXField] = useState("");
  const [yField, setYField] = useState("");

  const reportQuery = useQuery({
    queryKey: ["crm-reports", "detail", reportId],
    queryFn: async () => {
      const r = await getReport(reportId);
      // Seed chart editor from saved config
      if (r.chart) {
        setChartType(r.chart.chart_type);
        setXField(r.chart.x_field);
        setYField(r.chart.y_field);
      }
      return r;
    },
    enabled: !!reportId,
    retry: false,
  });

  const runMut = useMutation({
    mutationFn: () => runReport(reportId),
    onSuccess: (res) => {
      setLastRun(res);
      if (res.status === "ok") {
        toast.success(`Ran report — ${res.row_count} row(s)`);
      } else {
        toast.error(res.error_msg || "Report run failed");
      }
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to run report"),
  });

  const saveChartMut = useMutation({
    mutationFn: () =>
      updateReport(reportId, {
        chart:
          xField && yField
            ? { chart_type: chartType, x_field: xField, y_field: yField }
            : null,
      }),
    onSuccess: () => {
      toast.success("Chart configuration saved");
      void qc.invalidateQueries({ queryKey: ["crm-reports", "detail", reportId] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to save chart"),
  });

  if (reportQuery.isError && isNotEnabled(reportQuery.error)) {
    return (
      <div className="space-y-6">
        <PageHeader title="Report" />
        <ReportsNotEnabled />
      </div>
    );
  }

  if (reportQuery.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-64" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (reportQuery.isError || !reportQuery.data) {
    return (
      <div className="space-y-6">
        <PageHeader title="Report" />
        <Card>
          <CardContent className="py-12 text-center text-sm text-destructive">
            Unable to load this report.
          </CardContent>
        </Card>
        <Button variant="outline" asChild>
          <Link to="/crm/reports">
            <ArrowLeft className="mr-2 h-4 w-4" /> Back to reports
          </Link>
        </Button>
      </div>
    );
  }

  const report = reportQuery.data;
  const run = lastRun;
  const columns = run?.columns ?? [];
  const chartColumnOptions = run?.columns ?? report.fields;
  const effectiveChart = run?.chart ?? report.chart ?? null;

  return (
    <div className="space-y-6">
      <PageHeader
        title={report.name}
        description={report.description || `${moduleLabel(report.module)} report`}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" asChild>
              <Link to="/crm/reports">
                <ArrowLeft className="mr-2 h-4 w-4" /> Reports
              </Link>
            </Button>
            <Button onClick={() => runMut.mutate()} disabled={runMut.isPending}>
              {runMut.isPending ? (
                <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Play className="mr-2 h-4 w-4" />
              )}
              Run report
            </Button>
          </div>
        }
      />

      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Badge variant="secondary">{moduleLabel(report.module)}</Badge>
        {report.group_by && <Badge variant="outline">Grouped by {report.group_by}</Badge>}
        {report.conditions.length > 0 && (
          <Badge variant="outline">{report.conditions.length} filter(s)</Badge>
        )}
        {run && (
          <span className="text-muted-foreground">
            Last run {fmtTs(run.run_at)} · {run.row_count} row(s) · status {run.status}
          </span>
        )}
      </div>

      <Tabs defaultValue="results">
        <TabsList>
          <TabsTrigger value="results">Results</TabsTrigger>
          <TabsTrigger value="chart">Chart</TabsTrigger>
          <TabsTrigger value="schedules">Schedules</TabsTrigger>
        </TabsList>

        {/* ── Results ── */}
        <TabsContent value="results" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Tabular results</CardTitle>
              <CardDescription>
                Run the report to fetch the latest rows from your live data.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {!run ? (
                <div className="flex flex-col items-center gap-3 py-12 text-center">
                  <Play className="h-10 w-10 text-muted-foreground" />
                  <p className="text-sm text-muted-foreground">
                    No results yet. Click <strong>Run report</strong> to execute.
                  </p>
                </div>
              ) : run.status !== "ok" ? (
                <div className="py-8 text-center text-sm text-destructive">
                  {run.error_msg || "Report execution failed."}
                </div>
              ) : run.rows.length === 0 ? (
                <div className="py-8 text-center text-sm text-muted-foreground">
                  No rows matched.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        {columns.map((c) => (
                          <TableHead key={c}>{c}</TableHead>
                        ))}
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {run.rows.map((row, ri) => (
                        <TableRow key={ri}>
                          {row.map((cell, ci) => {
                            const col = columns[ci] ?? "";
                            const display =
                              looksLikeCents(col) && typeof cell === "number"
                                ? fmtCents(cell)
                                : fmtCell(cell);
                            return <TableCell key={ci}>{display}</TableCell>;
                          })}
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Chart ── */}
        <TabsContent value="chart" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Chart</CardTitle>
              <CardDescription>
                Configure a chart over the report columns, then save it to the report.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-3 sm:grid-cols-3">
                <div className="space-y-1.5">
                  <Label>Type</Label>
                  <Select value={chartType} onValueChange={(v) => setChartType(v as ChartType)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="bar">Bar</SelectItem>
                      <SelectItem value="line">Line</SelectItem>
                      <SelectItem value="pie">Pie</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label>X axis (category)</Label>
                  {chartColumnOptions.length > 0 ? (
                    <Select value={xField} onValueChange={setXField}>
                      <SelectTrigger>
                        <SelectValue placeholder="Select column" />
                      </SelectTrigger>
                      <SelectContent>
                        {chartColumnOptions.map((c) => (
                          <SelectItem key={c} value={c}>
                            {c}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  ) : (
                    <Input value={xField} onChange={(e) => setXField(e.target.value)} placeholder="column" />
                  )}
                </div>
                <div className="space-y-1.5">
                  <Label>Y axis (value)</Label>
                  {chartColumnOptions.length > 0 ? (
                    <Select value={yField} onValueChange={setYField}>
                      <SelectTrigger>
                        <SelectValue placeholder="Select column" />
                      </SelectTrigger>
                      <SelectContent>
                        {chartColumnOptions.map((c) => (
                          <SelectItem key={c} value={c}>
                            {c}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  ) : (
                    <Input value={yField} onChange={(e) => setYField(e.target.value)} placeholder="column" />
                  )}
                </div>
              </div>

              <div className="flex justify-end">
                <Button
                  variant="outline"
                  onClick={() => saveChartMut.mutate()}
                  disabled={saveChartMut.isPending}
                >
                  <Save className="mr-2 h-4 w-4" />
                  {saveChartMut.isPending ? "Saving…" : "Save chart"}
                </Button>
              </div>

              {!run ? (
                <div className="flex h-64 flex-col items-center justify-center gap-2 text-center text-sm text-muted-foreground">
                  <BarChart3 className="h-8 w-8" />
                  Run the report to render the chart.
                </div>
              ) : effectiveChart ? (
                <ReportChart chart={effectiveChart} columns={run.columns} rows={run.rows} />
              ) : xField && yField ? (
                <ReportChart
                  chart={{ chart_type: chartType, x_field: xField, y_field: yField }}
                  columns={run.columns}
                  rows={run.rows}
                />
              ) : (
                <div className="flex h-64 items-center justify-center text-sm text-muted-foreground">
                  Choose X and Y columns to preview a chart.
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Schedules ── */}
        <TabsContent value="schedules">
          <ReportSchedules reportId={reportId} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
