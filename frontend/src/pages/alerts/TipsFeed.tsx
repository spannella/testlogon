import { useQuery } from "@tanstack/react-query";
import { DollarSign } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/shared/EmptyState";
import { Skeleton } from "@/components/ui/skeleton";
import { getTipsReceivedSummary } from "@/api/endpoints/tips";

/** Human labels for the ledger-backed per-surface breakdown (TIPX-D1). */
const SURFACE_LABELS: Record<string, string> = {
  post: "Post tips",
  message: "Message tips",
  comment: "Comment tips",
  broadcast: "Broadcast tips",
  video: "Video tips",
  post_react: "Post reaction tips",
  message_react: "Message reaction tips",
  video_comment: "Video comment tips",
  profile: "Direct creator tips",
  other: "Other tips",
};

function surfaceLabel(key: string): string {
  return SURFACE_LABELS[key] ?? key.replace(/_/g, " ");
}

export function TipsFeed() {
  // TIPX-D1: read the LEDGER-backed summary (net, all 8 surfaces, reversed-excluded)
  // so this number reconciles to the earnings tips bucket and the leaderboard —
  // it is no longer the gross, 2-surface, 1000-alert-capped alert-stream total.
  const summaryQuery = useQuery({
    queryKey: ["tips", "received-summary", "30d"],
    queryFn: () => getTipsReceivedSummary("30d"),
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

  const uniqueTippers = summary.unique_tippers ?? summary.top_tippers.length;
  const bySurface = summary.by_surface ?? {};
  const surfaceRows = Object.entries(bySurface)
    .filter(([, b]) => b.count > 0)
    .sort((a, b) => b[1].total_cents - a[1].total_cents);

  return (
    <div className="space-y-4">
      {/* Summary card */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Tips &amp; Earnings (30 days)</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-3 gap-4 text-center">
            <div>
              <p className="text-2xl font-bold">
                ${(summary.total_tips_cents / 100).toFixed(2)}
              </p>
              {/* TIPX-D1: honest label — this is NET of the platform fee, and it
                  reconciles to the creator-earnings tips bucket. */}
              <p className="text-xs text-muted-foreground">Net tips received</p>
            </div>
            <div>
              <p className="text-2xl font-bold">{summary.tip_count}</p>
              <p className="text-xs text-muted-foreground">Tips Received</p>
            </div>
            <div>
              <p className="text-2xl font-bold">{uniqueTippers}</p>
              <p className="text-xs text-muted-foreground">Unique Tippers</p>
            </div>
          </div>

          <p className="mt-2 text-center text-[11px] text-muted-foreground">
            Net of the platform fee, across all tip types. Reversed tips are excluded.
          </p>

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

          {/* Per-surface breakdown — TIPX-D1: all 8 surfaces, not just post/message */}
          {surfaceRows.length > 0 && (
            <div className="mt-4 border-t pt-3">
              <h4 className="text-sm font-medium mb-2">Breakdown</h4>
              {surfaceRows.map(([key, bucket]) => (
                <div key={key} className="flex justify-between py-1">
                  <span className="text-sm text-muted-foreground">{surfaceLabel(key)}</span>
                  <span className="text-sm">
                    {bucket.count} (${(bucket.total_cents / 100).toFixed(2)})
                  </span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
