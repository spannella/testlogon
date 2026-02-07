import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Heart, MessageCircle, Lock } from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Separator } from "@/components/ui/separator";
import { likePost, unlikePost, unlockPost } from "@/api/endpoints/newsfeed";
import { useAuthStore } from "@/stores/authStore";
import { CommentsThread } from "./CommentsThread";
import { PostActions } from "./PostActions";
import { EditPostDialog } from "./EditPostDialog";
import type { FeedPost } from "@/api/types";

function formatRelative(dateStr: string): string {
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMin = Math.floor(diffMs / 60_000);

  if (diffMin < 1) return "Just now";
  if (diffMin < 60) return `${diffMin}m`;
  const diffHrs = Math.floor(diffMin / 60);
  if (diffHrs < 24) return `${diffHrs}h`;
  const diffDays = Math.floor(diffHrs / 24);
  if (diffDays < 7) return `${diffDays}d`;
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

interface PostCardProps {
  post: FeedPost;
}

export function PostCard({ post }: PostCardProps) {
  const userId = useAuthStore((s) => s.userId);
  const queryClient = useQueryClient();
  const [showComments, setShowComments] = useState(false);
  const [editOpen, setEditOpen] = useState(false);

  const isOwn = post.author_id === userId;

  const likeMutation = useMutation({
    mutationFn: () => (post.liked_by_me ? unlikePost(post.post_id) : likePost(post.post_id)),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["feed"] });
    },
    onError: () => {
      toast.error("Action failed");
    },
  });

  const unlockMutation = useMutation({
    mutationFn: () => unlockPost(post.post_id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["feed"] });
      toast.success("Post unlocked!");
    },
    onError: () => {
      toast.error("Failed to unlock post");
    },
  });

  const isLocked = !!post.unlock_price_cents && !post.unlocked;
  const initials = post.author_id.slice(0, 2).toUpperCase();

  return (
    <Card>
      <CardContent className="p-4">
        {/* Author header */}
        <div className="flex items-center gap-3">
          <Avatar className="h-9 w-9">
            <AvatarFallback className="text-xs">{initials}</AvatarFallback>
          </Avatar>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium">{post.author_id}</p>
            <p className="text-[10px] text-muted-foreground">
              {formatRelative(post.created_at)}
              {post.updated_at && (
                <span className="ml-1 italic">(edited)</span>
              )}
            </p>
          </div>
          <PostActions
            postId={post.post_id}
            isOwn={isOwn}
            onEdit={() => setEditOpen(true)}
          />
        </div>

        {/* Post body */}
        <div className="mt-3">
          {isLocked ? (
            <div className="relative">
              <p className="whitespace-pre-wrap text-sm blur-sm select-none">
                {post.body}
              </p>
              <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 bg-background/60 rounded">
                <Lock className="h-6 w-6 text-muted-foreground" />
                <Button
                  size="sm"
                  onClick={() => unlockMutation.mutate()}
                  disabled={unlockMutation.isPending}
                >
                  {unlockMutation.isPending
                    ? "Unlocking..."
                    : `Unlock for $${((post.unlock_price_cents ?? 0) / 100).toFixed(2)}`}
                </Button>
              </div>
            </div>
          ) : (
            <p className="whitespace-pre-wrap text-sm">{post.body}</p>
          )}
        </div>

        {/* Image */}
        {post.image_url && (
          <img
            src={post.image_url}
            alt=""
            className="mt-3 w-full rounded-lg object-cover"
          />
        )}

        {/* Action row */}
        <div className="mt-3 flex items-center gap-4">
          <button
            className={cn(
              "flex items-center gap-1 text-sm transition-colors",
              post.liked_by_me
                ? "text-red-500"
                : "text-muted-foreground hover:text-red-500",
            )}
            onClick={() => likeMutation.mutate()}
            disabled={likeMutation.isPending}
          >
            <Heart
              className={cn(
                "h-4 w-4",
                post.liked_by_me && "fill-red-500",
              )}
            />
            <span>{post.like_count}</span>
          </button>
          <button
            className="flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground"
            onClick={() => setShowComments((o) => !o)}
          >
            <MessageCircle className="h-4 w-4" />
            <span>{post.comment_count}</span>
          </button>
        </div>

        {/* Comments thread */}
        {showComments && (
          <>
            <Separator className="my-3" />
            <CommentsThread postId={post.post_id} />
          </>
        )}
      </CardContent>

      {/* Edit dialog */}
      <EditPostDialog
        open={editOpen}
        onOpenChange={setEditOpen}
        postId={post.post_id}
        initialBody={post.body}
      />
    </Card>
  );
}
