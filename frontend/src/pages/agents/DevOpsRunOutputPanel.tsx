import { useQuery } from "@tanstack/react-query";
import { getDevOpsOutput, getDeploymentLog } from "@/api/endpoints/devopsAgent";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Check, X, Clock } from "lucide-react";
import type { DevOpsOutput } from "@/api/types";

function statusVariant(status: string): "default" | "destructive" | "secondary" {
  if (status === "success") return "default";
  if (status === "failed" || status === "rolled_back" || status === "rejected") return "destructive";
  return "secondary";
}

interface Props {
  runId: string;
  output?: DevOpsOutput;
}

export default function DevOpsRunOutputPanel({ runId, output: outputProp }: Props) {
  const { data: fetched } = useQuery({
    queryKey: ["devops-output", runId],
    queryFn: () => getDevOpsOutput(runId).catch(() => undefined),
    enabled: !outputProp,
    staleTime: 10_000,
  });
  const output = outputProp ?? fetched;

  const { data: log } = useQuery({
    queryKey: ["deployment-log", runId],
    queryFn: () => getDeploymentLog(runId).catch(() => undefined),
    staleTime: 10_000,
  });

  if (!output) {
    return <p className="text-sm text-muted-foreground">No deployment output.</p>;
  }

  return (
    <div data-testid="devops-output-panel" className="space-y-4">
      <div className="flex items-center gap-2">
        <Badge variant={statusVariant(output.status)}>{output.status}</Badge>
        <span className="text-sm">Environment: {output.environment}</span>
        <span className="text-sm">Duration: {output.total_duration_seconds}s</span>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Deployment Timeline</CardTitle>
        </CardHeader>
        <CardContent className="space-y-1">
          {(log?.steps ?? []).map((s) => (
            <div key={s.step_number} className="flex items-center gap-2 text-sm">
              {s.status === "success" ? (
                <Check className="h-4 w-4 text-green-600" />
              ) : s.status === "pending" ? (
                <Clock className="h-4 w-4 text-amber-600" />
              ) : (
                <X className="h-4 w-4 text-red-600" />
              )}
              <span className="font-mono text-xs">{s.step_type}</span>
              <span className="truncate text-muted-foreground">{s.command}</span>
              <span className="ml-auto">{s.duration_seconds}s</span>
            </div>
          ))}
        </CardContent>
      </Card>

      {output.health_check_results.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Health Check Results</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>URL</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Latency</TableHead>
                  <TableHead>Healthy</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {output.health_check_results.map((h) => (
                  <TableRow key={h.url}>
                    <TableCell className="font-mono text-xs">{h.url}</TableCell>
                    <TableCell className={h.status_code === 200 ? "text-green-600" : "text-red-600"}>
                      {h.status_code}
                    </TableCell>
                    <TableCell>{h.response_time_ms}ms</TableCell>
                    <TableCell>
                      <Badge variant={h.healthy ? "default" : "destructive"}>
                        {h.healthy ? "healthy" : "unhealthy"}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {output.rollback_executed && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Rollback Status</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <Badge variant={output.rollback_success ? "default" : "destructive"}>
              {output.rollback_success ? "Rollback Succeeded" : "Rollback Failed"}
            </Badge>
            {output.incident_ticket_id && (
              <p>
                Incident ticket: <code>{output.incident_ticket_id}</code>
              </p>
            )}
          </CardContent>
        </Card>
      )}

      {output.monitoring_snapshot && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Monitoring Snapshot</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="overflow-x-auto rounded bg-muted p-2 text-xs">
              {JSON.stringify(output.monitoring_snapshot, null, 2)}
            </pre>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
