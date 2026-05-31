import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { getQaOutput, getQaScreenshots } from "@/api/endpoints/qaAgent";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

const VERDICT_VARIANT: Record<string, string> = {
  pass: "bg-green-600 text-white",
  fail: "bg-red-600 text-white",
  flaky: "bg-yellow-500 text-black",
  error: "bg-gray-500 text-white",
};

export default function QaRunOutputPanel({ runId }: { runId: string }) {
  const { data: output } = useQuery({
    queryKey: ["qa-output", runId],
    queryFn: () => getQaOutput(runId),
    enabled: !!runId,
  });
  const { data: shots } = useQuery({
    queryKey: ["qa-screenshots", runId],
    queryFn: () => getQaScreenshots(runId),
    enabled: !!runId,
  });

  if (!output) {
    return (
      <div data-testid="qa-output-panel" className="text-sm text-muted-foreground">
        No QA output for this run yet.
      </div>
    );
  }

  const screenshots = shots?.screenshots ?? [];

  return (
    <div data-testid="qa-output-panel" className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Badge className={VERDICT_VARIANT[output.verdict] ?? ""} data-testid="qa-verdict-badge">
          {output.verdict}
        </Badge>
        {output.pr_url && (
          <a className="text-sm text-primary underline" href={output.pr_url} target="_blank" rel="noreferrer">
            PR: {output.pr_url}
          </a>
        )}
        <span className="text-sm">Ticket: {output.ticket_id}</span>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Test Results</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p className="font-semibold">New Tests</p>
            <p>{output.new_tests_pass_count} passed</p>
            <p>{output.new_tests_fail_count} failed</p>
          </div>
          <div>
            <p className="font-semibold">Regression Tests</p>
            <p>{output.regression_tests_pass} passed</p>
            <p>{output.regression_tests_fail} failed</p>
          </div>
        </CardContent>
      </Card>

      {output.regression_failures.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Regression Failures</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="list-disc pl-5 text-sm">
              {output.regression_failures.map((f) => (
                <li key={f}>{f}</li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      {screenshots.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Screenshots</CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-3 gap-2">
            {screenshots.map((s) => (
              <div key={s.name} className="space-y-1">
                <img src={s.presigned_url} alt={s.name} className="rounded border" />
                <div className="flex items-center gap-1 text-xs">
                  <Badge variant="secondary">{s.status}</Badge>
                  <span>{s.step}</span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {output.bug_ticket_ids.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Bug Tickets Filed</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="list-disc pl-5 text-sm">
              {output.bug_ticket_ids.map((id) => (
                <li key={id}>
                  <Link className="text-primary underline" to={`/tickets/${id}`}>
                    {id}
                  </Link>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      {output.flaky_tests.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Flaky Tests</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="list-disc pl-5 text-sm">
              {output.flaky_tests.map((t) => (
                <li key={t}>{t}</li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      <div className="flex gap-4 text-sm text-muted-foreground">
        <span>Duration: {output.total_duration_seconds}s</span>
        <span>PR Review: {output.pr_review_action}</span>
      </div>
    </div>
  );
}
