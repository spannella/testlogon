import { useQuery } from "@tanstack/react-query";
import { DollarSign } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/shared/EmptyState";
import { Skeleton } from "@/components/ui/skeleton";
import { getTipsSummary } from "@/api/endpoints/alerts";

export function TipsFeed() {
  const summaryQuery = useQuery({
    queryKey: ["alerts", "tips-summary", "30d"],
    queryFn: () => getTipsSummary("30d"),
  });

  if (summaryQuery.isLoading) {
    return <Skeleton className="h-48 w-full rounded-lg" />;
  }

  const summary = summaryQuery.data;

  if (!summary || (summary.tip_count === 0 && summary.top_tippers.length === 0)) {
    return (
      <EmptyState
        icon={<DollarSign className="h-8 w-8" />}
        title="No tips yet"
        description="Tips you receive will appear here with earnings summaries."
        className="py-16"
      />
    );
  }

  return (
    <div className="space-y-4">
      {/* Summary card */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Tips & Earnings (30 days)</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-3 gap-4 text-center">
            <div>
              <p className="text-2xl font-bold">
                ${(summary.total_tips_cents / 100).toFixed(2)}
              </p>
              <p className="text-xs text-muted-foreground">Total Earned</p>
            </div>
            <div>
              <p className="text-2xl font-bold">{summary.tip_count}</p>
              <p className="text-xs text-muted-foreground">Tips Received</p>
            </div>
            <div>
              <p className="text-2xl font-bold">{summary.top_tippers.length}</p>
              <p className="text-xs text-muted-foreground">Unique Tippers</p>
            </div>
          </div>

          {/* Top tippers */}
          {summary.top_tippers.length > 0 && (
            <div className="mt-4">
              <h4 className="text-sm font-medium mb-2">Top Supporters</h4>
              {summary.top_tippers.slice(0, 5).map((tipper) => (
                <div
                  key={tipper.user_id}
                  className="flex items-center justify-between py-1"
                >
                  <span className="text-sm">{tipper.display_name}</span>
                  <span className="text-sm font-medium">
                    ${(tipper.total_cents / 100).toFixed(2)}
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* By type breakdown */}
          <div className="mt-4 border-t pt-3">
            <h4 className="text-sm font-medium mb-2">Breakdown</h4>
            <div className="flex justify-between py-1">
              <span className="text-sm text-muted-foreground">Post tips</span>
              <span className="text-sm">
                {summary.by_type.post_tip.count} (${(summary.by_type.post_tip.total_cents / 100).toFixed(2)})
              </span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-sm text-muted-foreground">Message tips</span>
              <span className="text-sm">
                {summary.by_type.message_tip.count} (${(summary.by_type.message_tip.total_cents / 100).toFixed(2)})
              </span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
