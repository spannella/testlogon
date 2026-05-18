import { useCallback, useEffect, useMemo, useRef } from "react";
import { Loader2, Newspaper } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { CreatePost } from "./CreatePost";
import { PostCard } from "./PostCard";
import { EmptyState } from "@/components/shared/EmptyState";
import { useFeedTimelineQuery } from "@/hooks/useFeedTimelineQuery";
import { mergeFeedPages } from "@/lib/feedPagination";

interface FeedTimelineProps {
  authorId?: string;
  q?: string;
  from?: string;
  to?: string;
  hasMedia?: boolean;
  cursor?: string;
  onCursorChange?: (cursor?: string) => void;
  showComposer?: boolean;
  emptyTitle?: string;
  emptyDescription?: string;
}

export function FeedTimeline({
  authorId,
  q,
  from,
  to,
  hasMedia,
  cursor,
  onCursorChange,
  showComposer = false,
  emptyTitle = "No posts yet",
  emptyDescription = "Be the first to share something with the community.",
}: FeedTimelineProps) {
  const feedQuery = useFeedTimelineQuery({ authorId, q, from, to, hasMedia, cursor });

  const allPosts = useMemo(() => mergeFeedPages((feedQuery.data?.pages ?? []) as any), [feedQuery.data?.pages]);

  useEffect(() => {
    if (!onCursorChange) return;
    const pages = feedQuery.data?.pages ?? [];
    if (pages.length === 0) {
      onCursorChange(cursor);
      return;
    }
    const latest = pages[pages.length - 1]?.next_cursor;
    onCursorChange(latest);
  }, [feedQuery.data, onCursorChange, cursor]);

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

  if (feedQuery.isError) {
    return (
      <EmptyState
        icon={<Newspaper className="h-8 w-8" />}
        title="Could not load posts"
        description="Please try again in a moment."
      />
    );
  }

  return (
    <div className="space-y-4">
      {showComposer ? <CreatePost /> : null}

      {allPosts.length === 0 ? (
        <EmptyState
          icon={<Newspaper className="h-8 w-8" />}
          title={emptyTitle}
          description={emptyDescription}
        />
      ) : (
        <>
          {allPosts.map((post) => (
            <PostCard key={post.post_id} post={post} />
          ))}

          <div ref={sentinelRef} className="h-4" />

          {feedQuery.isFetchingNextPage && (
            <div className="space-y-3 py-2">
              <Skeleton className="h-20 w-full rounded-xl" />
              <Skeleton className="h-20 w-full rounded-xl" />
              <div className="flex justify-center">
                <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
