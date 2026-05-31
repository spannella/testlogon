import { useQuery } from "@tanstack/react-query";
import { getPmOutput } from "@/api/endpoints/pmAgent";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

/**
 * Embedded in the Agent Run detail page. Shows the structured PM operation
 * output: operation type, ideas processed, tickets created/reprioritized,
 * blockers found, escalations, report link, and velocity snapshot.
 */
export default function PmRunOutputPanel({ runId }: { runId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ["pm-output", runId],
    queryFn: () => getPmOutput(runId).catch(() => undefined),
    enabled: !!runId,
  });

  if (isLoading) return <p className="text-sm text-muted-foreground">Loading PM output…</p>;
  if (!data) return <p className="text-sm text-muted-foreground">No PM output for this run.</p>;

  return (
    <Card data-testid="pm-output-panel">
      <CardHeader>
        <CardTitle className="text-sm">
          PM Operation <Badge variant="secondary">{data.operation_type}</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="grid grid-cols-2 gap-2 text-sm md:grid-cols-3">
        <Stat label="Ideas processed" value={data.ideas_processed} />
        <Stat label="Ideas accepted" value={data.ideas_accepted} />
        <Stat label="Ideas rejected" value={data.ideas_rejected} />
        <Stat label="Feature tickets created" value={data.feature_tickets_created.length} />
        <Stat label="Tickets reprioritized" value={data.tickets_reprioritized} />
        <Stat label="Blockers found" value={data.blockers_found} />
        <Stat label="Escalations" value={data.escalations_created} />
        {data.report_id && <Stat label="Report" value={data.report_id} />}
        {data.velocity_current != null && <Stat label="Velocity" value={data.velocity_current} />}
        {data.velocity_trend && <Stat label="Trend" value={data.velocity_trend} />}
        <Stat label="Duration (s)" value={data.total_duration_seconds} />
      </CardContent>
    </Card>
  );
}

function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="font-semibold">{value}</p>
    </div>
  );
}
