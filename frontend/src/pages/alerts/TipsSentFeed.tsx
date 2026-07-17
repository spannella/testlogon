import { useQuery } from "@tanstack/react-query";
import { Send } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/shared/EmptyState";
import { Skeleton } from "@/components/ui/skeleton";
import { getTipsSent, getTipsSentSummary } from "@/api/endpoints/tips";
import type { TipSentItem } from "@/api/types";

/** TIPX-D4: tipper-side sent-tip receipts. Each row is one debit (gross) receipt. */

const SURFACE_LABELS: Record<string, string> = {
  post: "post",
  message: "message",
  comment: "comment",
  broadcast: "broadcast",
  video: "video",
  post_react: "post reaction",
  message_react: "message reaction",
  video_comment: "video comment",
  profile: "creator",
  other: "tip",
};

function surfaceLabel(key: string): string {
  return SURFACE_LABELS[key] ?? key.replace(/_/g, " ");
}

function formatDate(tsSeconds: number): string {
  if (!tsSeconds) return "";
  return new Date(tsSeconds * 1000).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function SentRow({ item }: { item: TipSentItem }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b py-2 last:border-b-0">
      <div className="min-w-0">
        <p className="truncate text-sm font-medium">
          {item.counterparty_display_name || item.counterparty_user_id}
        </p>
        <p className="text-xs text-muted-foreground">
          {surfaceLabel(item.content_type)} tip &middot; {formatDate(item.ts)}
        </p>
      </div>
      <div className="text-right">
        <p className="text-sm font-semibold">${(item.amount_cents / 100).toFixed(2)}</p>
        {item.platform_fee_cents > 0 && (
          <p className="text-[11px] text-muted-foreground">
            fee ${(item.platform_fee_cents / 100).toFixed(2)}
          </p>
        )}
      </div>
    </div>
  );
}

export function TipsSentFeed() {
  const summaryQuery = useQuery({
    queryKey: ["tips", "sent-summary", "all"],
    queryFn: () => getTipsSentSummary("all"),
  });
  const listQuery = useQuery({
    queryKey: ["tips", "sent", "all"],
    queryFn: () => getTipsSent({ period: "all", limit: 50 }),
  });

  if (summaryQuery.isLoading || listQuery.isLoading) {
    return <Skeleton className="h-40 w-full rounded-lg" />;
  }

  const items = listQuery.data?.items ?? [];
  const summary = summaryQuery.data;

  if (items.length === 0) {
    return (
      <EmptyState
        icon={<Send className="h-8 w-8" />}
        title="No tips sent yet"
        description="Tips you send to creators will appear here as receipts."
        className="py-12"
      />
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">Tips Sent</CardTitle>
      </CardHeader>
      <CardContent>
        {summary && (
          <div className="mb-3 grid grid-cols-3 gap-4 text-center">
            <div>
              <p className="text-xl font-bold">${(summary.total_sent_cents / 100).toFixed(2)}</p>
              <p className="text-xs text-muted-foreground">Total Sent</p>
            </div>
            <div>
              <p className="text-xl font-bold">{summary.tip_count}</p>
              <p className="text-xs text-muted-foreground">Tips</p>
            </div>
            <div>
              <p className="text-xl font-bold">{summary.unique_recipients}</p>
              <p className="text-xs text-muted-foreground">Creators</p>
            </div>
          </div>
        )}
        <div>
          {items.map((item) => (
            <SentRow key={item.entry_id} item={item} />
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
