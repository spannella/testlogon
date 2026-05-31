import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getProjectDashboard, getPmMetrics } from "@/api/endpoints/pmAgent";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { LayoutDashboard } from "lucide-react";

export default function ProjectDashboardPage() {
  const [params] = useSearchParams();
  const [typeId, setTypeId] = useState(params.get("type_id") ?? "");
  const tid = typeId || undefined;

  const { data: dash } = useQuery({
    queryKey: ["pm-dashboard", tid],
    queryFn: () => getProjectDashboard(tid),
    staleTime: 15_000,
  });
  const { data: metrics } = useQuery({
    queryKey: ["pm-dashboard-metrics", tid],
    queryFn: () => getPmMetrics(tid),
    staleTime: 15_000,
  });

  return (
    <div data-testid="project-dashboard-page" className="space-y-4 p-4">
      <div className="flex items-center gap-2">
        <LayoutDashboard className="h-6 w-6" />
        <h1 className="text-2xl font-bold">Project Dashboard</h1>
      </div>

      <div className="max-w-xs">
        <Label>PM Agent type id (optional)</Label>
        <Input data-testid="dashboard-type-id" value={typeId} onChange={(e) => setTypeId(e.target.value)} placeholder="pm agent type id" />
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4" data-testid="dashboard-metrics">
        <Metric label="Backlog Size" value={metrics?.backlog_size ?? dash?.pipeline_funnel?.find((s) => s.stage === "Ideas")?.count ?? 0} />
        <Metric label="Open P0" value={metrics?.p0_count ?? 0} />
        <Metric label="Velocity" value={metrics?.velocity_current ?? 0} />
        <Metric label="Blockers" value={metrics?.blockers_count ?? dash?.blockers?.length ?? 0} />
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card data-testid="dashboard-sprint">
          <CardHeader>
            <CardTitle className="text-sm">Current Sprint</CardTitle>
          </CardHeader>
          <CardContent className="text-sm">
            {dash?.sprint ? (
              <>
                <p>
                  Sprint #{dash.sprint.sprint_number} <Badge variant="secondary">{dash.sprint.status}</Badge>
                </p>
                <p>
                  {dash.sprint.completed_hours}/{dash.sprint.planned_hours}h ·{" "}
                  {dash.sprint.tickets_completed}/{dash.sprint.tickets_planned} tickets
                </p>
              </>
            ) : (
              <p className="text-muted-foreground">No active sprint.</p>
            )}
          </CardContent>
        </Card>

        <Card data-testid="dashboard-velocity">
          <CardHeader>
            <CardTitle className="text-sm">Velocity Trend</CardTitle>
          </CardHeader>
          <CardContent className="text-sm">
            {(dash?.velocity_trend ?? []).map((v) => (
              <div key={v.sprint_number} className="flex justify-between">
                <span>Sprint #{v.sprint_number}</span>
                <span>{v.velocity}h</span>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card data-testid="dashboard-pipeline">
          <CardHeader>
            <CardTitle className="text-sm">Pipeline Funnel</CardTitle>
          </CardHeader>
          <CardContent className="text-sm">
            {(dash?.pipeline_funnel ?? []).map((s) => (
              <div key={s.stage} className="flex justify-between">
                <span>{s.stage}</span>
                <span>{s.count}</span>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card data-testid="dashboard-backlog-health">
          <CardHeader>
            <CardTitle className="text-sm">Backlog by Priority</CardTitle>
          </CardHeader>
          <CardContent className="text-sm">
            {Object.entries(dash?.backlog_by_priority ?? {}).map(([p, c]) => (
              <div key={p} className="flex justify-between">
                <span>{p}</span>
                <span>{c as number}</span>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card data-testid="dashboard-utilization">
          <CardHeader>
            <CardTitle className="text-sm">Agent Utilization</CardTitle>
          </CardHeader>
          <CardContent className="text-sm">
            {(dash?.agent_utilization ?? []).map((u) => (
              <div key={u.agent_type} className="flex justify-between">
                <span>{u.agent_type}</span>
                <span>
                  {u.used_hours}/{u.total_capacity_hours}h ({u.utilization_pct}%)
                </span>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card data-testid="dashboard-blockers">
          <CardHeader>
            <CardTitle className="text-sm">Blockers</CardTitle>
          </CardHeader>
          <CardContent className="text-sm">
            {(dash?.blockers ?? []).length === 0 ? (
              <p className="text-muted-foreground">No blockers.</p>
            ) : (
              (dash?.blockers ?? []).map((b) => (
                <div key={b.ticket_id} className="border-b py-1">
                  <Badge variant="destructive">{b.blocker_type}</Badge> {b.ticket_id}: {b.details}
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>

      <Card data-testid="dashboard-completions">
        <CardHeader>
          <CardTitle className="text-sm">Recent Completions</CardTitle>
        </CardHeader>
        <CardContent className="text-sm">
          {(dash?.recent_completions ?? []).length === 0 ? (
            <p className="text-muted-foreground">No recent completions.</p>
          ) : (
            (dash?.recent_completions ?? []).map((c) => (
              <div key={c.ticket_id} className="flex justify-between">
                <span>{c.subject || c.ticket_id}</span>
                <span>{new Date(c.completed_at * 1000).toLocaleDateString()}</span>
              </div>
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">{label}</CardTitle>
      </CardHeader>
      <CardContent className="text-2xl font-bold">{value}</CardContent>
    </Card>
  );
}
