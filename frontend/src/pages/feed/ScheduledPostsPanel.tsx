import { useMemo, useState } from "react";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { cancelScheduledPost, getScheduledPosts } from "@/api/endpoints/newsfeed";
import type { FeedPost } from "@/api/types";
import { EditPostDialog } from "./EditPostDialog";

function formatSchedule(post: FeedPost): string {
  const ts = post.publish_at;
  if (!ts) return "Unscheduled";
  const dt = new Date(ts * 1000);
  const tz = post.schedule_timezone || Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  return dt.toLocaleString(undefined, { timeZone: tz, timeZoneName: "short", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

export function ScheduledPostsPanel() {
  const [open, setOpen] = useState(false);
  const [editingPost, setEditingPost] = useState<FeedPost | null>(null);
  const queryClient = useQueryClient();

  const query = useInfiniteQuery({
    queryKey: ["scheduled-posts"],
    queryFn: ({ pageParam }) => getScheduledPosts(pageParam as string | undefined),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor,
  });

  const cancelMut = useMutation({
    mutationFn: (postId: string) => cancelScheduledPost(postId),
    onSuccess: () => {
      toast.success("Scheduled post cancelled");
      void queryClient.invalidateQueries({ queryKey: ["scheduled-posts"] });
      void queryClient.invalidateQueries({ queryKey: ["feed"] });
    },
    onError: (err: unknown) => {
      toast.error(err instanceof Error ? err.message : "Failed to cancel scheduled post");
    },
  });

  const all = useMemo(
    () =>
      (query.data?.pages ?? [])
        .flatMap((p) => p.items)
        .slice()
        .sort((a, b) => (a.publish_at ?? Number.MAX_SAFE_INTEGER) - (b.publish_at ?? Number.MAX_SAFE_INTEGER)),
    [query.data?.pages],
  );

  return (
    <>
      <div className="flex justify-end">
        <Sheet open={open} onOpenChange={setOpen}>
          <SheetTrigger asChild>
            <Button type="button" variant="outline" size="sm" className="gap-2" aria-label="Open scheduled posts panel">
              <CalendarClock className="h-4 w-4" />
              Scheduled posts
              {all.length > 0 ? <span className="rounded bg-muted px-1.5 py-0.5 text-xs">{all.length}</span> : null}
            </Button>
          </SheetTrigger>
          <SheetContent side="right" className="w-full sm:max-w-xl">
            <SheetHeader>
              <SheetTitle>Scheduled posts</SheetTitle>
              <SheetDescription>
                Upcoming posts sorted by publish time. Edit or cancel before they publish.
              </SheetDescription>
            </SheetHeader>

            <div className="mt-4 space-y-3" aria-live="polite">
              {query.isLoading && (
                <div role="status" className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" /> Loading scheduled posts…
                </div>
              )}

              {!query.isLoading && query.isError && (
                <div role="alert" className="rounded border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
                  Could not load scheduled posts.
                  <div className="mt-2">
                    <Button type="button" size="sm" variant="outline" onClick={() => query.refetch()}>
                      Retry
                    </Button>
                  </div>
                </div>
              )}

              {!query.isLoading && !query.isError && all.length === 0 && (
                <div className="rounded border border-border/60 bg-muted/20 p-4 text-sm text-muted-foreground">
                  You have no upcoming scheduled posts.
                </div>
              )}

              {!query.isLoading && !query.isError && all.length > 0 && (
                <div className="space-y-2">
                  {all.map((post) => (
                    <div key={post.post_id} className="rounded border border-border/60 p-3">
                      <p className="text-xs text-muted-foreground">{formatSchedule(post)}</p>
                      <p className="mt-1 text-sm line-clamp-2">{post.body_plain || post.body}</p>
                      <div className="mt-2 flex gap-2">
                        <Button type="button" size="sm" variant="secondary" onClick={() => setEditingPost(post)}>
                          Edit
                        </Button>
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          disabled={cancelMut.isPending}
                          onClick={() => cancelMut.mutate(post.post_id)}
                        >
                          {cancelMut.isPending ? "Cancelling..." : "Cancel"}
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {query.hasNextPage && !query.isLoading && !query.isError && (
                <div className="pt-2">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => query.fetchNextPage()}
                    disabled={query.isFetchingNextPage}
                  >
                    {query.isFetchingNextPage ? "Loading more..." : "Load more"}
                  </Button>
                </div>
              )}
            </div>
          </SheetContent>
        </Sheet>
      </div>

      {editingPost && (
        <EditPostDialog
          open={!!editingPost}
          onOpenChange={(next) => {
            if (!next) {
              setEditingPost(null);
              void queryClient.invalidateQueries({ queryKey: ["scheduled-posts"] });
            }
          }}
          postId={editingPost.post_id}
          postStatus={editingPost.status}
          initialPublishAt={editingPost.publish_at}
          initialScheduleTimezone={editingPost.schedule_timezone}
          initialScheduledAtLocal={editingPost.scheduled_at_local}
          initialBody={editingPost.body}
          initialImageUrls={editingPost.image_urls}
          initialBodyRich={(editingPost.body_rich as unknown as import("./MarkdownComposer").RichDoc) ?? null}
        />
      )}
    </>
  );
}
