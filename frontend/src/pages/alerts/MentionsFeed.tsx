import { useNavigate } from "react-router-dom";
import { useInfiniteQuery } from "@tanstack/react-query";
import { AtSign } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/shared/EmptyState";
import { Skeleton } from "@/components/ui/skeleton";
import { getAlerts } from "@/api/endpoints/alerts";
import type { Alert } from "@/api/types";

export function MentionsFeed() {
  const navigate = useNavigate();

  const mentionsQuery = useInfiniteQuery({
    queryKey: ["alerts", "mentions"],
    queryFn: ({ pageParam }) =>
      getAlerts({ limit: 25, cursor: pageParam as string | undefined }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor,
  });

  // Filter for mention-type alerts client-side
  const allAlerts: Alert[] = (mentionsQuery.data?.pages ?? []).flatMap((p) => p.alerts);
  const mentions = allAlerts.filter((a) => a.event === "mention");

  if (mentionsQuery.isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-16 w-full rounded-lg" />
        ))}
      </div>
    );
  }

  if (mentions.length === 0) {
    return (
      <EmptyState
        icon={<AtSign className="h-8 w-8" />}
        title="No mentions yet"
        description="When someone mentions you, it will appear here."
        className="py-16"
      />
    );
  }

  return (
    <div className="space-y-1">
      {mentions.map((alert) => (
        <button
          key={alert.alert_id}
          className={cn(
            "w-full text-left rounded-lg border px-4 py-3 transition-colors hover:bg-accent/50",
            !alert.read_at && "bg-accent/30",
          )}
          onClick={() => {
            const actionUrl = alert.action_url;
            if (actionUrl) navigate(actionUrl);
          }}
        >
          <div className="flex items-center gap-3">
            <AtSign className="h-5 w-5 text-muted-foreground shrink-0" />
            <div className="flex-1 min-w-0">
              <p className={cn("text-sm", !alert.read_at && "font-medium")}>
                {alert.title}
              </p>
              {!!alert.details?.text_preview && (
                <p className="mt-0.5 truncate text-xs text-muted-foreground">
                  {String(alert.details.text_preview)}
                </p>
              )}
              <p className="mt-1 text-[10px] text-muted-foreground">
                {formatTime(alert.ts)}
              </p>
            </div>
            {!alert.read_at && (
              <div className="h-2 w-2 rounded-full bg-primary shrink-0" />
            )}
          </div>
        </button>
      ))}

      {mentionsQuery.hasNextPage && (
        <div className="flex justify-center pt-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => mentionsQuery.fetchNextPage()}
            disabled={mentionsQuery.isFetchingNextPage}
          >
            {mentionsQuery.isFetchingNextPage ? "Loading..." : "Load more"}
          </Button>
        </div>
      )}
    </div>
  );
}

function formatTime(ts: number): string {
  const date = new Date(ts * 1000);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMin = Math.floor(diffMs / 60_000);

  if (diffMin < 1) return "Just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHrs = Math.floor(diffMin / 60);
  if (diffHrs < 24) return `${diffHrs}h ago`;
  const diffDays = Math.floor(diffHrs / 24);
  if (diffDays === 1) return "Yesterday";
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}
