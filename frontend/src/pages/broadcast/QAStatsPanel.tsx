import { useQuery } from "@tanstack/react-query";
import { getQAStats } from "@/api/endpoints/broadcastQA";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { QAStats } from "@/api/types";

interface QAStatsPanelProps {
  sessionId: string;
}

export function QAStatsPanel({ sessionId }: QAStatsPanelProps) {
  const { data: stats } = useQuery<QAStats>({
    queryKey: ["qa-stats", sessionId],
    queryFn: () => getQAStats(sessionId),
  });

  if (!stats) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Q&A Statistics</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-muted-foreground">Total Questions</p>
            <p className="text-lg font-semibold">{stats.total_questions}</p>
          </div>
          <div>
            <p className="text-muted-foreground">Answered</p>
            <p className="text-lg font-semibold">{stats.answered}</p>
          </div>
          <div>
            <p className="text-muted-foreground">Answer Rate</p>
            <p className="text-lg font-semibold">{stats.answer_rate}%</p>
          </div>
          <div>
            <p className="text-muted-foreground">Avg Upvotes</p>
            <p className="text-lg font-semibold">{stats.avg_upvotes}</p>
          </div>
          <div>
            <p className="text-muted-foreground">Total Upvotes</p>
            <p className="text-lg font-semibold">{stats.total_upvotes}</p>
          </div>
          <div>
            <p className="text-muted-foreground">Pending</p>
            <p className="text-lg font-semibold">{stats.pending}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
