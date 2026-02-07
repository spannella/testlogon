import { useState } from "react";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Send } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Skeleton } from "@/components/ui/skeleton";
import { getComments, createComment } from "@/api/endpoints/newsfeed";

interface CommentsThreadProps {
  postId: string;
}

export function CommentsThread({ postId }: CommentsThreadProps) {
  const queryClient = useQueryClient();
  const [body, setBody] = useState("");

  const commentsQuery = useInfiniteQuery({
    queryKey: ["comments", postId],
    queryFn: ({ pageParam }) => getComments(postId, pageParam as string | undefined),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor,
  });

  const sendMutation = useMutation({
    mutationFn: () => createComment(postId, { body }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["comments", postId] });
      queryClient.invalidateQueries({ queryKey: ["feed"] });
      setBody("");
    },
    onError: () => {
      toast.error("Failed to post comment");
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!body.trim()) return;
    sendMutation.mutate();
  };

  const allComments = (commentsQuery.data?.pages ?? []).flatMap((p) => p.items);

  return (
    <div className="space-y-3 pt-2">
      {/* Comments list */}
      {commentsQuery.isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 2 }).map((_, i) => (
            <Skeleton key={i} className="h-10 w-full" />
          ))}
        </div>
      ) : (
        <>
          {allComments.map((comment) => (
            <div key={comment.comment_id} className="flex gap-2">
              <Avatar className="h-6 w-6 shrink-0">
                <AvatarFallback className="text-[10px]">
                  {comment.author_id.slice(0, 2).toUpperCase()}
                </AvatarFallback>
              </Avatar>
              <div className="min-w-0 flex-1">
                <div className="flex items-baseline gap-1.5">
                  <span className="text-xs font-medium">{comment.author_id}</span>
                  <span className="text-[10px] text-muted-foreground">
                    {new Date(comment.created_at).toLocaleDateString()}
                  </span>
                </div>
                <p className="text-sm">{comment.body}</p>
              </div>
            </div>
          ))}

          {commentsQuery.hasNextPage && (
            <Button
              variant="ghost"
              size="sm"
              className="text-xs"
              onClick={() => commentsQuery.fetchNextPage()}
              disabled={commentsQuery.isFetchingNextPage}
            >
              {commentsQuery.isFetchingNextPage ? "Loading..." : "Load more comments"}
            </Button>
          )}
        </>
      )}

      {/* Add comment */}
      <form onSubmit={handleSubmit} className="flex gap-2">
        <Input
          placeholder="Write a comment..."
          value={body}
          onChange={(e) => setBody(e.target.value)}
          className="text-sm"
        />
        <Button
          type="submit"
          size="icon"
          variant="ghost"
          disabled={!body.trim() || sendMutation.isPending}
        >
          <Send className="h-4 w-4" />
        </Button>
      </form>
    </div>
  );
}
