import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Eye } from "lucide-react";
import {
  listHiddenPosts,
  unhidePost,
  type HiddenPostsPageResponse,
  type HiddenPostSummary,
} from "@/api/endpoints/postHide";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";

// FEED-006: viewer's hidden posts with an Unhide affordance.
export default function HiddenPostsPage() {
  const queryClient = useQueryClient();

  const { data, fetchNextPage, hasNextPage, isFetchingNextPage, isLoading } =
    useInfiniteQuery({
      queryKey: ["feed", "hidden"],
      queryFn: ({ pageParam }) =>
        listHiddenPosts(pageParam as string | undefined),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage: HiddenPostsPageResponse) =>
        lastPage.next_cursor ?? undefined,
    });

  const unhideMut = useMutation({
    mutationFn: (postId: string) => unhidePost(postId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["feed", "hidden"] });
      queryClient.invalidateQueries({ queryKey: ["feed"] });
    },
  });

  const posts: HiddenPostSummary[] = (data?.pages ?? []).flatMap(
    (p) => p.items,
  );

  return (
    <div className="mx-auto max-w-2xl py-6">
      <h1 className="mb-4 text-2xl font-bold">Hidden posts</h1>
      {isLoading && <p>Loading…</p>}
      {!isLoading && posts.length === 0 && (
        <p className="text-muted-foreground">No hidden posts.</p>
      )}
      {posts.map((post) => (
        <Card key={post.post_id} className="mb-4">
          <CardHeader className="flex flex-row items-center justify-between">
            <div className="font-semibold">{post.user_id ?? "Unknown"}</div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => unhideMut.mutate(post.post_id)}
              disabled={unhideMut.isPending}
              aria-label="Unhide post"
            >
              <Eye className="mr-2 h-4 w-4" />
              Unhide
            </Button>
          </CardHeader>
          {post.body != null && (
            <CardContent>
              <div className="whitespace-pre-wrap">{String(post.body)}</div>
            </CardContent>
          )}
        </Card>
      ))}
      {hasNextPage && (
        <Button
          onClick={() => fetchNextPage()}
          disabled={isFetchingNextPage}
          className="mt-4 w-full"
        >
          {isFetchingNextPage ? "Loading…" : "Load more"}
        </Button>
      )}
    </div>
  );
}
