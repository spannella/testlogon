import { useQuery } from "@tanstack/react-query";
import { getLiveQaStats } from "@/api/endpoints/liveQa";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface LiveQaStatsPanelProps {
  sessionId: string;
}

export function LiveQaStatsPanel({ sessionId }: LiveQaStatsPanelProps) {
  const { data } = useQuery({
    queryKey: ["live-qa-stats", sessionId],
    queryFn: () => getLiveQaStats(sessionId),
  });

  const stats = [
    { label: "Total", value: data?.total_questions ?? 0 },
    { label: "Answered", value: data?.answered ?? 0 },
    { label: "Pending", value: data?.pending ?? 0 },
    { label: "Dismissed", value: data?.dismissed ?? 0 },
    { label: "Total Upvotes", value: data?.total_upvotes ?? 0 },
    { label: "Avg Upvotes", value: data?.avg_upvotes ?? 0 },
    { label: "Answer Rate", value: `${data?.answer_rate ?? 0}%` },
  ];

  return (
    <Card data-testid="live-qa-stats-panel">
      <CardHeader>
        <CardTitle className="text-base">Q&amp;A Engagement</CardTitle>
      </CardHeader>
      <CardContent>
        <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {stats.map((s) => (
            <div key={s.label} className="rounded-md border p-2 text-center">
              <dt className="text-xs text-muted-foreground">{s.label}</dt>
              <dd className="text-lg font-semibold">{s.value}</dd>
            </div>
          ))}
        </dl>
      </CardContent>
    </Card>
  );
}
