import { useRef, useCallback } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import { Loader2, Newspaper } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { getFeed } from "@/api/endpoints/newsfeed";
import { CreatePost } from "./CreatePost";
import { PostCard } from "./PostCard";
import { EmptyState } from "@/components/shared/EmptyState";
import { newsfeedSchedulingUiEnabled } from "@/lib/featureFlags";
import { ScheduledPostsPanel } from "./ScheduledPostsPanel";

export function NewsFeed() {
  const schedulingUiEnabled = newsfeedSchedulingUiEnabled;
  const feedQuery = useInfiniteQuery({
    queryKey: ["feed"],
    queryFn: ({ pageParam }) => getFeed(pageParam as string | undefined),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor,
  });

  const allPosts = (feedQuery.data?.pages ?? []).flatMap((p) => p.items);

  // Infinite scroll via IntersectionObserver on a sentinel element
  const observer = useRef<IntersectionObserver | null>(null);
  const sentinelRef = useCallback(
    (node: HTMLDivElement | null) => {
      if (feedQuery.isFetchingNextPage) return;
      if (observer.current) observer.current.disconnect();
      if (!node) return;
      observer.current = new IntersectionObserver((entries) => {
        if (entries[0]?.isIntersecting && feedQuery.hasNextPage) {
          feedQuery.fetchNextPage();
        }
      });
      observer.current.observe(node);
    },
    [feedQuery.isFetchingNextPage, feedQuery.hasNextPage, feedQuery.fetchNextPage],
  );

  if (feedQuery.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-28 w-full rounded-xl" />
        <Skeleton className="h-48 w-full rounded-xl" />
        <Skeleton className="h-48 w-full rounded-xl" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <CreatePost />
      {schedulingUiEnabled ? <ScheduledPostsPanel /> : null}

      {allPosts.length === 0 ? (
        <EmptyState
          icon={<Newspaper className="h-8 w-8" />}
          title="No posts yet"
          description="Be the first to share something with the community."
        />
      ) : (
        <>
          {allPosts.map((post) => (
            <PostCard key={post.post_id} post={post} />
          ))}

          {/* Sentinel for infinite scroll */}
          <div ref={sentinelRef} className="h-4" />

          {feedQuery.isFetchingNextPage && (
            <div className="flex justify-center py-4">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          )}
        </>
      )}
    </div>
  );
}
