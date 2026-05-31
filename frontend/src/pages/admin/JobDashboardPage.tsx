import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Activity, RefreshCw, CheckCircle, AlertTriangle, XCircle, HelpCircle, Play } from "lucide-react";
import { toast } from "sonner";
import { getJobHealth, getRecentJobRuns, runJobNow } from "@/api/endpoints/jobDashboard";
import type { JobHealthEntry, JobRunOut } from "@/api/types";

function healthBadge(health: string) {
  switch (health) {
    case "ok":
      return <Badge className="bg-green-500 text-white">OK</Badge>;
    case "degraded":
      return <Badge className="bg-amber-500 text-white">Degraded</Badge>;
    case "failed":
      return <Badge variant="destructive">Failed</Badge>;
    default:
      return <Badge variant="secondary">Unknown</Badge>;
  }
}

function healthIcon(health: string) {
  switch (health) {
    case "ok":
      return <CheckCircle className="h-4 w-4 text-green-500" />;
    case "degraded":
      return <AlertTriangle className="h-4 w-4 text-amber-500" />;
    case "failed":
      return <XCircle className="h-4 w-4 text-red-500" />;
    default:
      return <HelpCircle className="h-4 w-4 text-muted-foreground" />;
  }
}

function fmtDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "—";
  if (ms < 1) return "<1ms";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function fmtTime(ts: number | null | undefined): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export default function JobDashboardPage() {
  const qc = useQueryClient();

  const healthQ = useQuery({
    queryKey: ["admin", "job-dashboard", "health"],
    queryFn: getJobHealth,
    refetchInterval: 15_000,
  });

  const runsQ = useQuery({
    queryKey: ["admin", "job-dashboard", "runs"],
    queryFn: () => getRecentJobRuns(50),
    refetchInterval: 15_000,
  });

  const runNowMut = useMutation({
    mutationFn: (jobName: string) => runJobNow(jobName),
    onSuccess: (_res, jobName) => {
      toast.success(`Triggered ${jobName}`);
      qc.invalidateQueries({ queryKey: ["admin", "job-dashboard"] });
    },
    onError: () => toast.error("Failed to trigger job"),
  });

  const jobs = healthQ.data?.jobs ?? [];
  const runs = runsQ.data?.items ?? [];

  const okCount = jobs.filter((j) => j.health === "ok").length;
  const attentionCount = jobs.filter((j) => j.health === "failed" || j.health === "degraded").length;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Activity className="h-6 w-6" /> Background Jobs
          </h1>
          <p className="text-sm text-muted-foreground">
            {okCount} healthy, {attentionCount} need attention
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => qc.invalidateQueries({ queryKey: ["admin", "job-dashboard"] })}
        >
          <RefreshCw className="h-4 w-4 mr-2" /> Refresh
        </Button>
      </div>

      {/* Job health table */}
      <Card>
        <CardHeader>
          <CardTitle>Job Health</CardTitle>
          <CardDescription>
            Per-job status derived from the latest recorded run. Auto-refreshes every 15s.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left">
                  <th className="py-2 pr-4">Job</th>
                  <th className="pr-4">Health</th>
                  <th className="pr-4">Last Run</th>
                  <th className="pr-4">Next Run</th>
                  <th className="pr-4">Duration</th>
                  <th className="pr-4">Processed</th>
                  <th className="pr-4">Failed</th>
                  <th className="pr-4">Last Error</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((job: JobHealthEntry) => (
                  <tr key={job.name} className="border-b hover:bg-muted/50">
                    <td className="py-2 pr-4">
                      <div className="flex items-center gap-2">
                        {healthIcon(job.health)}
                        <div>
                          <span className="font-medium">{job.label}</span>
                          <p className="text-xs text-muted-foreground font-mono">{job.name}</p>
                        </div>
                      </div>
                    </td>
                    <td className="pr-4">{healthBadge(job.health)}</td>
                    <td className="pr-4 text-xs">{fmtTime(job.last_run_at)}</td>
                    <td className="pr-4 text-xs">{fmtTime(job.next_run_at)}</td>
                    <td className="pr-4 text-xs">{fmtDuration(job.last_duration_ms)}</td>
                    <td className="pr-4">{job.last_items_processed}</td>
                    <td className={`pr-4 ${job.last_items_failed > 0 ? "text-destructive font-medium" : ""}`}>
                      {job.last_items_failed}
                    </td>
                    <td className="pr-4 max-w-xs truncate text-xs text-muted-foreground">
                      {job.last_error || "—"}
                    </td>
                    <td>
                      {job.run_now_safe ? (
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={runNowMut.isPending}
                          onClick={() => runNowMut.mutate(job.name)}
                        >
                          <Play className="h-3 w-3 mr-1" /> Run Now
                        </Button>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </td>
                  </tr>
                ))}
                {jobs.length === 0 && (
                  <tr>
                    <td colSpan={9} className="py-4 text-center text-muted-foreground text-sm">
                      No jobs registered
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Recent runs */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Runs</CardTitle>
          <CardDescription>Most recent job runs across all jobs.</CardDescription>
        </CardHeader>
        <CardContent>
          {runs.length === 0 ? (
            <div className="flex items-center gap-2 text-muted-foreground text-sm py-4">
              <CheckCircle className="h-4 w-4 text-green-500" /> No runs recorded yet
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left">
                    <th className="py-2 pr-4">Job</th>
                    <th className="pr-4">Status</th>
                    <th className="pr-4">Started</th>
                    <th className="pr-4">Duration</th>
                    <th className="pr-4">Processed</th>
                    <th className="pr-4">Failed</th>
                    <th className="pr-4">Trigger</th>
                    <th>Error</th>
                  </tr>
                </thead>
                <tbody>
                  {runs.map((run: JobRunOut) => (
                    <tr key={run.run_id} className="border-b">
                      <td className="py-2 pr-4 font-mono text-xs">{run.job_name}</td>
                      <td className="pr-4">
                        <Badge variant={run.status === "failed" ? "destructive" : "outline"}>
                          {run.status}
                        </Badge>
                      </td>
                      <td className="pr-4 text-xs">{fmtTime(run.started_at)}</td>
                      <td className="pr-4 text-xs">{fmtDuration(run.duration_ms)}</td>
                      <td className="pr-4">{run.items_processed}</td>
                      <td className={`pr-4 ${run.items_failed > 0 ? "text-destructive" : ""}`}>
                        {run.items_failed}
                      </td>
                      <td className="pr-4 text-xs text-muted-foreground">{run.triggered_by}</td>
                      <td className="max-w-xs truncate text-xs text-destructive">
                        {run.error || "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
