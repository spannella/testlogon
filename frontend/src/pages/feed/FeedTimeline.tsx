import { useCallback, useEffect, useMemo, useRef } from "react";
import { Loader2, Newspaper, Repeat2, Sparkles, UserCheck } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { CreatePost } from "./CreatePost";
import { PostCard } from "./PostCard";
import { SponsoredPostCard } from "./SponsoredPostCard";
import { EmptyState } from "@/components/shared/EmptyState";
import { useFeedTimelineQuery } from "@/hooks/useFeedTimelineQuery";
import { useForYouFeedQuery } from "@/hooks/useForYouFeedQuery";
import { mergeFeedPages } from "@/lib/feedPagination";
import { useOfflineStore } from "@/stores/offlineStore";
import { useAuthStore } from "@/stores/authStore";
import type { FeedPost, CreatePostReq } from "@/api/types";

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
  /** NRS-011: when true, render the ranked "For You" feed (GET /feed/for-you). */
  forYou?: boolean;
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
  forYou = false,
}: FeedTimelineProps) {
  const timelineQuery = useFeedTimelineQuery({ authorId, q, from, to, hasMedia, cursor });
  const forYouQuery = useForYouFeedQuery();
  const feedQuery = forYou ? forYouQuery : timelineQuery;
  const forYouSource = forYou ? forYouQuery.data?.pages?.[0]?.source : undefined;
  const userId = useAuthStore((s) => s.userId);
  const offlineQueue = useOfflineStore((s) => s.queue);

  // PWA-005: Build optimistic posts from offline queue
  const offlinePosts = useMemo((): FeedPost[] => {
    return offlineQueue
      .filter((a) => a.type === "create_post")
      .map((a) => {
        const payload = a.payload as CreatePostReq;
        return {
          post_id: `optimistic-post-${a.id}`,
          author_id: userId ?? "",
          body: payload.body_plain ?? (payload as Record<string, unknown>).body as string ?? "",
          body_plain: payload.body_plain,
          body_markdown: payload.body_markdown,
          body_rich: payload.body_rich,
          body_format: payload.body_format ?? "plain",
          image_urls: payload.image_urls ?? [],
          file_attachments: [],
          like_count: 0,
          comment_count: 0,
          tip_total_cents: 0,
          reactions_counts: {},
          my_reactions: [],
          created_at: new Date(a.enqueuedAt).toISOString(),
          status: "published" as const,
          __offline: {
            queueId: a.id,
            status: (a.__status ?? "pending") as "pending" | "sending" | "failed",
            error: a.__error,
            enqueuedAt: a.enqueuedAt,
          },
        };
      });
  }, [offlineQueue, userId]);

  const serverPosts = useMemo(() => mergeFeedPages((feedQuery.data?.pages ?? []) as any), [feedQuery.data?.pages]);
  const allPosts = useMemo(() => [...offlinePosts, ...serverPosts], [offlinePosts, serverPosts]);

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

      {forYou && forYouSource && forYouSource !== "for_you" ? (
        <div
          className="flex items-center gap-2 rounded-lg border border-dashed bg-muted/40 px-4 py-2.5 text-sm text-muted-foreground"
          data-testid="for-you-source-hint"
        >
          <Sparkles className="h-4 w-4 shrink-0" />
          <span>
            {forYouSource === "cold_start"
              ? "Showing popular posts — engage with posts to personalize your feed."
              : "Showing the latest posts. Personalized recommendations will appear as you engage."}
          </span>
        </div>
      ) : null}

      {allPosts.length === 0 ? (
        <EmptyState
          icon={<Newspaper className="h-8 w-8" />}
          title={emptyTitle}
          description={emptyDescription}
        />
      ) : (
        <>
          {allPosts.map((post) => (
            <div key={post.post_id}>
              {post.source === "following" && !post.reposted_by && (
                <div className="flex items-center gap-1 px-4 py-1.5 text-sm text-muted-foreground" data-testid="following-attribution">
                  <UserCheck className="h-3.5 w-3.5" />
                  <span className="font-medium">{post.author_id}</span>
                  <span>posted</span>
                </div>
              )}
              {post.is_sponsored ? (
                <SponsoredPostCard post={post} />
              ) : (
                <>
                  {post.reposted_by && (
                    <div className="flex items-center gap-1 px-4 py-1.5 text-sm text-muted-foreground" data-testid="repost-attribution">
                      <Repeat2 className="h-3.5 w-3.5" />
                      <span className="font-medium">{post.reposted_by.display_name}</span>
                      <span>reposted</span>
                    </div>
                  )}
                  {post.repost_quote && (
                    <div className="px-4 pb-2 text-sm italic text-foreground" data-testid="repost-quote">
                      &ldquo;{post.repost_quote}&rdquo;
                    </div>
                  )}
                  <PostCard post={post} />
                </>
              )}
            </div>
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
