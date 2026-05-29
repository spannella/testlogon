import { useNavigate } from "react-router-dom";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Bell } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/shared/EmptyState";
import { Skeleton } from "@/components/ui/skeleton";
import { getActivityFeed, markGroupRead } from "@/api/endpoints/alerts";
import { ActivityGroupCard } from "./ActivityGroupCard";

export function ActivityFeed() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const activityQuery = useInfiniteQuery({
    queryKey: ["alerts", "activity"],
    queryFn: ({ pageParam }) =>
      getActivityFeed({ limit: 20, cursor: pageParam }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor,
  });

  const markGroupReadMut = useMutation({
    mutationFn: (alertIds: string[]) => markGroupRead(alertIds),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
      toast.success("Marked as read");
    },
  });

  const allItems = activityQuery.data?.pages.flatMap((p) => p.items) ?? [];

  if (activityQuery.isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-24 w-full rounded-lg" />
        ))}
      </div>
    );
  }

  if (allItems.length === 0) {
    return (
      <EmptyState
        icon={<Bell className="h-8 w-8" />}
        title="No activity yet"
        description="When people interact with your content, it will show up here."
        className="py-16"
      />
    );
  }

  return (
    <div className="space-y-3">
      {allItems.map((item) => (
        <ActivityGroupCard
          key={`${item.source_type}:${item.source_id}`}
          item={item}
          onClick={() => item.action_url && navigate(item.action_url)}
          onMarkRead={() => markGroupReadMut.mutate(item.alert_ids)}
        />
      ))}
      {activityQuery.hasNextPage && (
        <div className="flex justify-center pt-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => activityQuery.fetchNextPage()}
            disabled={activityQuery.isFetchingNextPage}
          >
            {activityQuery.isFetchingNextPage ? "Loading..." : "Load more"}
          </Button>
        </div>
      )}
    </div>
  );
}
