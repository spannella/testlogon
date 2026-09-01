import { useState, useRef } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  Eye,
  Heart,
  MessageCircle,
  Send,
  DollarSign,
  Trash2,
  Loader2,
  Smile,
  Images,
  Sticker as StickerIcon,
  Pencil,
  Check,
  X,
  Flag,
  MoreHorizontal,
  Reply,
  ImagePlus,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { EmojiPicker } from "@/components/shared/EmojiPicker";
import { GifPicker } from "@/components/shared/GifPicker";
import { StickerPicker } from "@/components/shared/StickerPicker";
import {
  ReportContentModal,
  type ReportContentPayload,
} from "@/components/shared/ReportContentModal";
import {
  recordView,
  toggleLike,
  checkLike,
  listVideoComments,
  addVideoComment,
  editVideoComment,
  deleteVideoComment,
  reactToVideoComment,
  unreactFromVideoComment,
  reportVideoComment,
  type VideoComment,
  type AddVideoCommentReq,
} from "@/api/endpoints/gallery";
import { getVideoDetail } from "@/api/endpoints/vod";
import { uploadPostImage } from "@/api/endpoints/newsfeed";
import { useAuthStore } from "@/stores/authStore";
import { cn } from "@/lib/utils";
import SimilarVideos from "@/pages/videos/SimilarVideos";
import { TipDialog } from "@/pages/feed/TipDialog";

const COMMENT_REACTION_EMOJIS = ["👍", "❤️", "😂", "🔥", "😮"];

function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

// ─── Single comment row (mirrors feed CommentsThread CommentRow) ──────────────

function VideoCommentRow({
  comment,
  videoId,
  isOwn,
  depth,
  onReply,
}: {
  comment: VideoComment;
  videoId: string;
  isOwn: boolean;
  depth: number;
  onReply: (commentId: string) => void;
}) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [editText, setEditText] = useState(comment.text ?? "");
  const [reportOpen, setReportOpen] = useState(false);
  const [tipOpen, setTipOpen] = useState(false);

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["video-comments", videoId] });

  const editMut = useMutation({
    mutationFn: (text: string) =>
      editVideoComment(videoId, comment.comment_id, text),
    onSuccess: () => {
      toast.success("Comment updated");
      invalidate();
      setEditing(false);
    },
    onError: () => toast.error("Failed to update comment"),
  });

  const deleteMut = useMutation({
    mutationFn: () => deleteVideoComment(videoId, comment.comment_id),
    onSuccess: () => {
      invalidate();
      queryClient.invalidateQueries({ queryKey: ["video", videoId] });
    },
  });

  const addReactionMut = useMutation({
    mutationFn: (emoji: string) =>
      reactToVideoComment(videoId, comment.comment_id, emoji),
    onSuccess: () => invalidate(),
    onError: () => toast.error("Failed to react"),
  });

  const removeReactionMut = useMutation({
    mutationFn: (emoji: string) =>
      unreactFromVideoComment(videoId, comment.comment_id, emoji),
    onSuccess: () => invalidate(),
    onError: () => toast.error("Failed to remove reaction"),
  });

  const reportMut = useMutation({
    mutationFn: ({ topics, reason_text }: ReportContentPayload) =>
      reportVideoComment({
        videoId,
        commentId: comment.comment_id,
        topics,
        reason_text,
      }),
    onSuccess: () => {
      toast.success("Report received");
      setReportOpen(false);
    },
    onError: () => toast.error("Could not submit report. Please try again."),
  });

  const handleReaction = (emoji: string, isMine: boolean) => {
    if (isMine) removeReactionMut.mutate(emoji);
    else addReactionMut.mutate(emoji);
  };

  const isMedia = comment.kind === "gif" || comment.kind === "sticker" || comment.kind === "image";

  return (
    <>
      <div
        className="group flex items-start justify-between gap-2"
        style={depth > 0 ? { marginLeft: depth * 24 } : undefined}
      >
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline gap-1.5">
            <p className="text-xs font-medium text-muted-foreground">
              {comment.user_id}
            </p>
            <span className="text-[10px] text-muted-foreground">
              {new Date(comment.created_at * 1000).toLocaleString()}
            </span>
            {comment.edited_at != null && (
              <span className="text-[10px] italic text-muted-foreground">
                (edited)
              </span>
            )}
          </div>

          {/* Body */}
          {editing ? (
            <div className="mt-1 flex items-center gap-1">
              <Input
                value={editText}
                onChange={(e) => setEditText(e.target.value)}
                maxLength={2000}
                className="h-8"
              />
              <Button
                size="icon"
                variant="ghost"
                className="h-7 w-7"
                disabled={!editText.trim() || editMut.isPending}
                onClick={() => editText.trim() && editMut.mutate(editText.trim())}
              >
                <Check className="h-3.5 w-3.5" />
              </Button>
              <Button
                size="icon"
                variant="ghost"
                className="h-7 w-7"
                onClick={() => {
                  setEditing(false);
                  setEditText(comment.text ?? "");
                }}
              >
                <X className="h-3.5 w-3.5" />
              </Button>
            </div>
          ) : comment.kind === "gif" && comment.gif_url ? (
            <img
              src={comment.gif_url}
              alt={comment.gif_alt_text || "GIF"}
              className="mt-1 max-w-[200px] rounded"
              loading="lazy"
              data-testid="video-comment-gif"
            />
          ) : comment.kind === "sticker" && comment.sticker_url ? (
            <img
              src={comment.sticker_url}
              alt={comment.sticker_alt_text || "Sticker"}
              className="mt-1 h-20 w-20 object-contain"
              loading="lazy"
              data-testid="video-comment-sticker"
            />
          ) : comment.kind === "image" && comment.image_url ? (
            <img
              src={comment.image_url}
              alt={comment.image_alt_text || "Image"}
              className="mt-1 max-w-[300px] rounded"
              loading="lazy"
              data-testid="video-comment-image"
            />
          ) : (
            <p className="text-sm">{comment.text}</p>
          )}

          {/* TIP-303: tip total + Tip action (non-own comments) */}
          <div className="mt-0.5 flex items-center gap-2">
            {(comment.tip_total_cents ?? 0) > 0 && (
              <span className="text-[10px] text-emerald-600">
                ${((comment.tip_total_cents ?? 0) / 100).toFixed(2)} tipped
              </span>
            )}
            {!isOwn && (
              <button
                type="button"
                onClick={() => setTipOpen(true)}
                className="flex items-center gap-0.5 text-[10px] text-muted-foreground transition-colors hover:text-emerald-600"
              >
                <DollarSign className="h-3 w-3" />
                Tip
              </button>
            )}
          </div>

          {/* Reaction bar */}
          <div className="mt-1 flex flex-wrap items-center gap-1">
            {COMMENT_REACTION_EMOJIS.map((emoji) => {
              const count = (comment.reactions_counts ?? {})[emoji] ?? 0;
              const isMine = (comment.my_reactions ?? []).includes(emoji);
              return (
                <button
                  key={emoji}
                  type="button"
                  onClick={() => handleReaction(emoji, isMine)}
                  disabled={addReactionMut.isPending || removeReactionMut.isPending}
                  className={cn(
                    "flex items-center gap-0.5 rounded-full border px-1.5 py-0.5 text-xs transition-colors",
                    isMine
                      ? "border-primary/40 bg-primary/10 text-primary"
                      : "border-transparent hover:border-border hover:bg-muted text-muted-foreground",
                  )}
                >
                  <span>{emoji}</span>
                  {count > 0 && (
                    <span className="text-[10px] font-medium">{count}</span>
                  )}
                </button>
              );
            })}
            <button
              type="button"
              onClick={() => onReply(comment.comment_id)}
              className="flex items-center gap-0.5 text-[10px] text-muted-foreground hover:text-foreground"
            >
              <Reply className="h-3 w-3" /> Reply
            </button>
          </div>
        </div>

        {/* Actions menu */}
        {!editing && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="h-6 w-6 shrink-0 opacity-0 transition-opacity group-hover:opacity-100"
                aria-label="Comment actions"
              >
                <MoreHorizontal className="h-3.5 w-3.5" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              {isOwn ? (
                <>
                  {!isMedia && (
                    <DropdownMenuItem
                      onClick={() => {
                        setEditText(comment.text ?? "");
                        setEditing(true);
                      }}
                    >
                      <Pencil className="mr-2 h-3.5 w-3.5" /> Edit
                    </DropdownMenuItem>
                  )}
                  <DropdownMenuItem
                    className="text-destructive focus:text-destructive"
                    onClick={() => deleteMut.mutate()}
                  >
                    <Trash2 className="mr-2 h-3.5 w-3.5" /> Delete
                  </DropdownMenuItem>
                </>
              ) : (
                <DropdownMenuItem onClick={() => setReportOpen(true)}>
                  <Flag className="mr-2 h-3.5 w-3.5" /> Report comment
                </DropdownMenuItem>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        )}
      </div>

      {!isOwn && (
        <ReportContentModal
          open={reportOpen}
          onOpenChange={setReportOpen}
          title="Report comment"
          description="Share why this comment should be reviewed."
          isSubmitting={reportMut.isPending}
          onSubmit={async (payload) => {
            await reportMut.mutateAsync(payload);
          }}
        />
      )}

      {!isOwn && (
        <TipDialog
          open={tipOpen}
          onOpenChange={setTipOpen}
          postId={videoId}
          authorId={comment.user_id}
          videoComment={{ videoId, commentId: comment.comment_id }}
        />
      )}
    </>
  );
}

export default function VideoDetailPage() {
  const { videoId } = useParams<{ videoId: string }>();
  const queryClient = useQueryClient();
  const userId = useAuthStore((s) => s.userId);
  const [commentText, setCommentText] = useState("");
  const [replyTo, setReplyTo] = useState<string | null>(null);
  const [emojiOpen, setEmojiOpen] = useState(false);
  const [gifOpen, setGifOpen] = useState(false);
  const [stickerOpen, setStickerOpen] = useState(false);
  // Image comment state
  const [pendingImageUrl, setPendingImageUrl] = useState<string | null>(null);
  const [pendingImageAlt, setPendingImageAlt] = useState<string>("");
  const [imageUploading, setImageUploading] = useState(false);
  const imageInputRef = useRef<HTMLInputElement>(null);

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
    mutationFn: (body: AddVideoCommentReq) => addVideoComment(videoId!, body),
    onSuccess: () => {
      setCommentText("");
      setReplyTo(null);
      setPendingImageUrl(null);
      setPendingImageAlt("");
      queryClient.invalidateQueries({ queryKey: ["video-comments", videoId] });
      queryClient.invalidateQueries({ queryKey: ["video", videoId] });
    },
    onError: () => toast.error("Failed to post comment"),
  });

  const handleVideoImageFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    e.target.value = "";
    setImageUploading(true);
    try {
      const result = await uploadPostImage(file);
      setPendingImageUrl(result.url);
      setPendingImageAlt(file.name.replace(/\.[^.]+$/, ""));
    } catch {
      toast.error("Image upload failed. Please try again.");
    } finally {
      setImageUploading(false);
    }
  };

  const removePendingVideoImage = () => {
    setPendingImageUrl(null);
    setPendingImageAlt("");
  };

  const handleEmojiInsert = (emoji: string) =>
    setCommentText((prev) => prev + emoji);

  const handleGifSelect = (gif: {
    url: string;
    alt_text: string;
    width: number;
    height: number;
  }) => {
    setGifOpen(false);
    addCommentMut.mutate({
      kind: "gif",
      gif_url: gif.url,
      gif_alt_text: gif.alt_text,
      gif_width: gif.width,
      gif_height: gif.height,
      ...(replyTo ? { parent_comment_id: replyTo } : {}),
    });
  };

  const handleStickerSelect = (sticker: {
    id: string;
    collection_id: string;
    url: string;
    alt_text: string;
  }) => {
    setStickerOpen(false);
    addCommentMut.mutate({
      kind: "sticker",
      sticker_id: sticker.id,
      sticker_collection_id: sticker.collection_id,
      sticker_url: sticker.url,
      sticker_alt_text: sticker.alt_text,
      ...(replyTo ? { parent_comment_id: replyTo } : {}),
    });
  };

  const video = videoQ.data;
  const liked = likeCheckQ.data?.liked ?? false;
  const comments = commentsQ.data?.comments ?? [];

  // Group replies under their parent for nested rendering.
  const topLevel = comments.filter((c) => !c.parent_comment_id);
  const repliesByParent = new Map<string, VideoComment[]>();
  for (const c of comments) {
    if (c.parent_comment_id) {
      const arr = repliesByParent.get(c.parent_comment_id) ?? [];
      arr.push(c);
      repliesByParent.set(c.parent_comment_id, arr);
    }
  }

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
      <Link
        to="/gallery"
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to Gallery
      </Link>

      {/* Video player placeholder */}
      <Card>
        <div className="aspect-video bg-black flex items-center justify-center text-white">
          {video.thumbnail_url ? (
            <img
              src={video.thumbnail_url}
              alt={video.title}
              className="h-full w-full object-contain"
            />
          ) : (
            <span className="text-muted-foreground">Video Player</span>
          )}
        </div>

        <CardContent className="space-y-4 p-4">
          {/* Title + metadata */}
          <div>
            <h1 className="text-xl font-bold">{video.title}</h1>
            {video.description && (
              <p className="mt-1 text-sm text-muted-foreground">
                {video.description}
              </p>
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
            className="space-y-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (pendingImageUrl) {
                addCommentMut.mutate({
                  kind: "image",
                  image_url: pendingImageUrl,
                  image_alt_text: pendingImageAlt || undefined,
                  ...(replyTo ? { parent_comment_id: replyTo } : {}),
                });
                return;
              }
              if (commentText.trim()) {
                addCommentMut.mutate({
                  kind: "text",
                  text: commentText.trim(),
                  ...(replyTo ? { parent_comment_id: replyTo } : {}),
                });
              }
            }}
          >
            {replyTo && (
              <div className="flex items-center justify-between rounded bg-muted px-2 py-1 text-xs text-muted-foreground">
                <span>Replying to a comment</span>
                <button
                  type="button"
                  onClick={() => setReplyTo(null)}
                  className="hover:text-foreground"
                >
                  <X className="h-3 w-3" />
                </button>
              </div>
            )}
            {/* Image preview */}
            {pendingImageUrl && (
              <div className="relative inline-block">
                <img
                  src={pendingImageUrl}
                  alt={pendingImageAlt || "Comment image preview"}
                  className="max-h-32 max-w-[200px] rounded border object-cover"
                  data-testid="video-comment-image-preview"
                />
                <button
                  type="button"
                  onClick={removePendingVideoImage}
                  className="absolute -right-2 -top-2 flex h-5 w-5 items-center justify-center rounded-full bg-destructive text-destructive-foreground shadow"
                  aria-label="Remove image"
                >
                  <X className="h-3 w-3" />
                </button>
              </div>
            )}
            {!pendingImageUrl && (
              <div className="flex gap-2">
                <Input
                  placeholder={replyTo ? "Write a reply..." : "Add a comment..."}
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
              </div>
            )}
            {pendingImageUrl && (
              <Button
                type="submit"
                size="sm"
                disabled={addCommentMut.isPending}
                className="w-full"
              >
                <Send className="mr-1 h-4 w-4" />
                Post image
              </Button>
            )}
            {/* emoji / GIF / sticker / image toolbar */}
            <div className="flex items-center gap-1">
              <Popover open={emojiOpen} onOpenChange={setEmojiOpen}>
                <PopoverTrigger asChild>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7"
                    aria-label="Insert emoji"
                    disabled={addCommentMut.isPending || !!pendingImageUrl}
                  >
                    <Smile className="h-4 w-4" />
                  </Button>
                </PopoverTrigger>
                <PopoverContent side="top" align="start" className="w-auto p-0">
                  <EmojiPicker
                    onSelect={handleEmojiInsert}
                    onClose={() => setEmojiOpen(false)}
                  />
                </PopoverContent>
              </Popover>
              <Popover open={gifOpen} onOpenChange={setGifOpen}>
                <PopoverTrigger asChild>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7"
                    aria-label="Add a GIF"
                    disabled={addCommentMut.isPending || !!pendingImageUrl}
                  >
                    <Images className="h-4 w-4" />
                  </Button>
                </PopoverTrigger>
                <PopoverContent side="top" align="start" className="w-auto p-2">
                  <GifPicker onSelect={handleGifSelect} />
                </PopoverContent>
              </Popover>
              <Popover open={stickerOpen} onOpenChange={setStickerOpen}>
                <PopoverTrigger asChild>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7"
                    aria-label="Add a sticker"
                    disabled={addCommentMut.isPending || !!pendingImageUrl}
                  >
                    <StickerIcon className="h-4 w-4" />
                  </Button>
                </PopoverTrigger>
                <PopoverContent side="top" align="start" className="w-auto p-2">
                  <StickerPicker onSelect={handleStickerSelect} />
                </PopoverContent>
              </Popover>
              {/* Image upload button */}
              <input
                ref={imageInputRef}
                type="file"
                accept="image/*"
                className="hidden"
                data-testid="video-comment-image-input"
                onChange={handleVideoImageFileChange}
              />
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="h-7 w-7"
                aria-label="Upload an image"
                data-testid="video-comment-image-button"
                disabled={addCommentMut.isPending || imageUploading || !!pendingImageUrl}
                onClick={() => imageInputRef.current?.click()}
              >
                {imageUploading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <ImagePlus className="h-4 w-4" />
                )}
              </Button>
            </div>
          </form>

          <Separator />

          {/* Comment list (top-level + nested replies) */}
          {comments.length === 0 && (
            <p className="text-sm text-muted-foreground">
              No comments yet. Be the first!
            </p>
          )}

          {topLevel.map((c) => (
            <div key={c.comment_id} className="space-y-2">
              <VideoCommentRow
                comment={c}
                videoId={videoId!}
                isOwn={c.user_id === userId}
                depth={0}
                onReply={setReplyTo}
              />
              {(repliesByParent.get(c.comment_id) ?? []).map((r) => (
                <VideoCommentRow
                  key={r.comment_id}
                  comment={r}
                  videoId={videoId!}
                  isOwn={r.user_id === userId}
                  depth={1}
                  onReply={setReplyTo}
                />
              ))}
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Similar Videos */}
      {videoId && <SimilarVideos videoId={videoId} />}
    </div>
  );
}
