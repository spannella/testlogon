import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { CoderOutput } from "@/api/types";

interface CoderRunOutputPanelProps {
  runId: string;
  output: CoderOutput | undefined;
  isLoading: boolean;
}

export default function CoderRunOutputPanel({ output, isLoading }: CoderRunOutputPanelProps) {
  if (isLoading) {
    return <p className="text-sm text-muted-foreground">Loading coder output…</p>;
  }
  if (!output) {
    return <p className="text-sm text-muted-foreground">No coder output available.</p>;
  }
  return (
    <div data-testid="coder-output-panel" className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Branch &amp; PR</CardTitle>
        </CardHeader>
        <CardContent className="space-y-1 text-sm">
          <div className="font-mono">{output.branch_name}</div>
          {output.pr_url && (
            <a className="text-primary underline" href={output.pr_url} target="_blank" rel="noreferrer">
              {output.pr_url}
            </a>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Files Changed</CardTitle>
        </CardHeader>
        <CardContent className="text-sm">
          <ul className="font-mono">
            {output.files_changed.map((f) => (
              <li key={f}>{f}</li>
            ))}
          </ul>
          <div className="mt-2 flex gap-3">
            <span className="text-green-600">+{output.insertions}</span>
            <span className="text-red-600">-{output.deletions}</span>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Test Results</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          {output.test_results.map((r, idx) => (
            <div key={idx} className="flex items-center gap-2">
              <Badge variant={r.exit_code === 0 ? "default" : "destructive"}>
                {r.exit_code === 0 ? "pass" : "fail"}
              </Badge>
              <span className="font-mono">{r.command}</span>
              <span className="text-muted-foreground">{r.duration_seconds}s</span>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Run Info</CardTitle>
        </CardHeader>
        <CardContent className="text-sm space-y-1">
          <div>Retries: {output.test_retry_count}</div>
          <div>Duration: {output.total_duration_seconds}s</div>
          <div>Escalated: {output.escalated ? "yes" : "no"}</div>
          {output.escalation_reason && <div>Reason: {output.escalation_reason}</div>}
        </CardContent>
      </Card>
    </div>
  );
}
