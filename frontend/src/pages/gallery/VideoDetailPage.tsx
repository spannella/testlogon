import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Eye, Heart, MessageCircle, Send, Trash2, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
// toast imported if needed for future notifications
import {
  recordView,
  toggleLike,
  checkLike,
  listVideoComments,
  addVideoComment,
  deleteVideoComment,
} from "@/api/endpoints/gallery";
import { getVideoDetail } from "@/api/endpoints/vod";
import { useAuthStore } from "@/stores/authStore";
import SimilarVideos from "@/pages/videos/SimilarVideos";

function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

export default function VideoDetailPage() {
  const { videoId } = useParams<{ videoId: string }>();
  const queryClient = useQueryClient();
  const userId = useAuthStore((s) => s.userId);
  const [commentText, setCommentText] = useState("");

  // Fetch video detail
  const videoQ = useQuery({
    queryKey: ["video", videoId],
    queryFn: () => getVideoDetail(videoId!),
    enabled: !!videoId,
  });

  // Record view on first load
  const viewMut = useMutation({
    mutationFn: () => recordView(videoId!),
  });

  // Fire view recording once on mount
  useState(() => {
    if (videoId) viewMut.mutate();
  });

  // Check like status
  const likeCheckQ = useQuery({
    queryKey: ["video-like", videoId],
    queryFn: () => checkLike(videoId!),
    enabled: !!videoId,
  });

  // Toggle like
  const likeMut = useMutation({
    mutationFn: () => toggleLike(videoId!),
    onSuccess: (data) => {
      queryClient.setQueryData(["video-like", videoId], { liked: data.liked });
      queryClient.invalidateQueries({ queryKey: ["video", videoId] });
    },
  });

  // Comments
  const commentsQ = useQuery({
    queryKey: ["video-comments", videoId],
    queryFn: () => listVideoComments(videoId!, { limit: 50 }),
    enabled: !!videoId,
  });

  const addCommentMut = useMutation({
    mutationFn: (text: string) => addVideoComment(videoId!, text),
    onSuccess: () => {
      setCommentText("");
      queryClient.invalidateQueries({ queryKey: ["video-comments", videoId] });
      queryClient.invalidateQueries({ queryKey: ["video", videoId] });
    },
  });

  const deleteCommentMut = useMutation({
    mutationFn: (commentId: string) => deleteVideoComment(videoId!, commentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["video-comments", videoId] });
      queryClient.invalidateQueries({ queryKey: ["video", videoId] });
    },
  });

  const video = videoQ.data;
  const liked = likeCheckQ.data?.liked ?? false;
  const comments = commentsQ.data?.comments ?? [];

  if (videoQ.isLoading) {
    return (
      <div className="flex items-center justify-center py-32">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!video) {
    return (
      <div className="mx-auto max-w-4xl p-6">
        <p className="text-muted-foreground">Video not found.</p>
        <Link to="/gallery" className="text-primary underline mt-2 inline-block">
          Back to Gallery
        </Link>
      </div>
    );
  }

  return (
    <div className="mx-auto w-full max-w-4xl space-y-4 p-4 md:p-6">
      {/* Back link */}
      <Link to="/gallery" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="h-4 w-4" />
        Back to Gallery
      </Link>

      {/* Video player placeholder */}
      <Card>
        <div className="aspect-video bg-black flex items-center justify-center text-white">
          {video.thumbnail_url ? (
            <img src={video.thumbnail_url} alt={video.title} className="h-full w-full object-contain" />
          ) : (
            <span className="text-muted-foreground">Video Player</span>
          )}
        </div>

        <CardContent className="space-y-4 p-4">
          {/* Title + metadata */}
          <div>
            <h1 className="text-xl font-bold">{video.title}</h1>
            {video.description && (
              <p className="mt-1 text-sm text-muted-foreground">{video.description}</p>
            )}
          </div>

          {/* Engagement bar */}
          <div className="flex items-center gap-4">
            <span className="inline-flex items-center gap-1 text-sm text-muted-foreground">
              <Eye className="h-4 w-4" />
              {formatCount(viewMut.data?.view_count ?? 0)} views
            </span>

            <Button
              size="sm"
              variant={liked ? "default" : "outline"}
              onClick={() => likeMut.mutate()}
              disabled={likeMut.isPending}
              className="gap-1"
            >
              <Heart className={`h-4 w-4 ${liked ? "fill-current" : ""}`} />
              {liked ? "Liked" : "Like"}
              {likeMut.data?.like_count != null && (
                <span className="ml-1">{formatCount(likeMut.data.like_count)}</span>
              )}
            </Button>

            <span className="inline-flex items-center gap-1 text-sm text-muted-foreground">
              <MessageCircle className="h-4 w-4" />
              {comments.length} comments
            </span>
          </div>

          {/* Tags */}
          {video.review_status && (
            <div className="flex flex-wrap gap-1">
              <Badge variant="outline">{video.review_status}</Badge>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Comments section */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Comments</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Add comment form */}
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (commentText.trim()) {
                addCommentMut.mutate(commentText.trim());
              }
            }}
          >
            <Input
              placeholder="Add a comment..."
              value={commentText}
              onChange={(e) => setCommentText(e.target.value)}
              maxLength={2000}
            />
            <Button
              type="submit"
              size="icon"
              disabled={!commentText.trim() || addCommentMut.isPending}
            >
              <Send className="h-4 w-4" />
            </Button>
          </form>

          <Separator />

          {/* Comment list */}
          {comments.length === 0 && (
            <p className="text-sm text-muted-foreground">No comments yet. Be the first!</p>
          )}

          {comments.map((c) => (
            <div key={c.comment_id} className="flex items-start justify-between gap-2">
              <div className="flex-1">
                <p className="text-xs font-medium text-muted-foreground">{c.user_id}</p>
                <p className="text-sm">{c.text}</p>
                <p className="text-[10px] text-muted-foreground">
                  {new Date(c.created_at * 1000).toLocaleString()}
                </p>
              </div>
              {c.user_id === userId && (
                <Button
                  size="icon"
                  variant="ghost"
                  className="h-6 w-6"
                  onClick={() => deleteCommentMut.mutate(c.comment_id)}
                >
                  <Trash2 className="h-3 w-3" />
                </Button>
              )}
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Similar Videos */}
      {videoId && <SimilarVideos videoId={videoId} />}
    </div>
  );
}
