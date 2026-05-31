import { useQuery } from "@tanstack/react-query";
import { getArchitectOutput } from "@/api/endpoints/architectAgent";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import DependencyGraphView from "./DependencyGraphView";
import type { DependencyGraph } from "@/api/types";

interface Props {
  runId: string;
}

/**
 * Embedded panel for an Agent Run detail page showing the Solution Architect
 * decomposition output: codebase analysis, design decisions, generated tickets,
 * dependency graph, and effort breakdown. (AGENT-011)
 */
export default function ArchitectRunOutputPanel({ runId }: Props) {
  const { data, isLoading } = useQuery({
    queryKey: ["architect-output", runId],
    queryFn: () => getArchitectOutput(runId).catch(() => undefined),
    staleTime: 30_000,
  });

  if (isLoading) return <p className="text-sm text-muted-foreground">Loading…</p>;
  if (!data) return <p className="text-sm text-muted-foreground">No architect output for this run.</p>;

  const graph: DependencyGraph = {
    nodes: data.tickets_created.map((t) => ({
      id: t.ticket_id,
      subject: t.subject,
      complexity: t.complexity,
      order: t.order,
      status: "open",
    })),
    edges: Object.entries(data.dependency_graph).flatMap(([to, deps]) =>
      (deps ?? []).map((from) => ({ from, to })),
    ),
  };

  return (
    <div data-testid="architect-output-panel" className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Architecture Summary</CardTitle>
        </CardHeader>
        <CardContent>
          <pre className="whitespace-pre-wrap text-sm">{data.decomposition_summary}</pre>
          <div className="mt-2 flex gap-2">
            <Badge variant="secondary">{data.total_tickets} tickets</Badge>
            <Badge variant="secondary">{data.total_estimated_hours}h</Badge>
            {data.feedback_requested && <Badge>review requested</Badge>}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Codebase Analysis</CardTitle>
        </CardHeader>
        <CardContent className="space-y-1 text-sm">
          <div>Files scanned: {data.codebase_analysis.files_scanned}</div>
          <div>Patterns: {data.codebase_analysis.patterns_found.join(", ")}</div>
          <div>Related files: {data.codebase_analysis.existing_related_files.join(", ")}</div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Design Decisions</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {data.design_decisions.map((d, i) => (
            <div key={i} className="rounded border p-2 text-sm">
              <div className="font-medium">{d.decision}</div>
              <div className="text-muted-foreground">{d.rationale}</div>
              {d.alternatives_considered?.length > 0 && (
                <div className="text-xs text-muted-foreground">
                  Alternatives: {d.alternatives_considered.join(", ")}
                </div>
              )}
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Dependency Graph</CardTitle>
        </CardHeader>
        <CardContent>
          <DependencyGraphView graph={graph} />
        </CardContent>
      </Card>
    </div>
  );
}
