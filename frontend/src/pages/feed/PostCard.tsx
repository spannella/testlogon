import { useState, useCallback, useEffect } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Heart, MessageCircle, Lock, DollarSign, X, ChevronLeft, ChevronRight } from "lucide-react";
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
import { TipDialog } from "./TipDialog";
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

interface PostImageGridProps {
  urls: string[];
  onClickImage: (index: number) => void;
}

function PostImageGrid({ urls, onClickImage }: PostImageGridProps) {
  const count = urls.length;

  if (count === 1) {
    return (
      <button
        type="button"
        className="mt-3 block w-full overflow-hidden rounded-lg"
        onClick={() => onClickImage(0)}
      >
        <img
          src={urls[0]}
          alt=""
          className="max-h-80 w-full rounded-lg object-cover transition-transform hover:scale-[1.02]"
        />
      </button>
    );
  }

  if (count === 2) {
    return (
      <div className="mt-3 grid grid-cols-2 gap-1 rounded-lg overflow-hidden">
        {urls.map((url, i) => (
          <button
            key={i}
            type="button"
            className="aspect-square overflow-hidden"
            onClick={() => onClickImage(i)}
          >
            <img src={url} alt="" className="h-full w-full object-cover transition-transform hover:scale-[1.02]" />
          </button>
        ))}
      </div>
    );
  }

  if (count === 3) {
    return (
      <div className="mt-3 grid grid-cols-2 gap-1 rounded-lg overflow-hidden">
        {/* First image: col-span-2, 16:9 */}
        <button
          type="button"
          className="col-span-2 aspect-video overflow-hidden"
          onClick={() => onClickImage(0)}
        >
          <img src={urls[0]} alt="" className="h-full w-full object-cover transition-transform hover:scale-[1.02]" />
        </button>
        {/* Two square cells below */}
        {urls.slice(1).map((url, i) => (
          <button
            key={i + 1}
            type="button"
            className="aspect-square overflow-hidden"
            onClick={() => onClickImage(i + 1)}
          >
            <img src={url} alt="" className="h-full w-full object-cover transition-transform hover:scale-[1.02]" />
          </button>
        ))}
      </div>
    );
  }

  if (count === 4) {
    return (
      <div className="mt-3 grid grid-cols-2 gap-1 rounded-lg overflow-hidden">
        {urls.map((url, i) => (
          <button
            key={i}
            type="button"
            className="aspect-square overflow-hidden"
            onClick={() => onClickImage(i)}
          >
            <img src={url} alt="" className="h-full w-full object-cover transition-transform hover:scale-[1.02]" />
          </button>
        ))}
      </div>
    );
  }

  // 5+ images: 2×2 grid; cell 3 shows image[3] with +N overlay
  const extra = count - 4;
  return (
    <div className="mt-3 grid grid-cols-2 gap-1 rounded-lg overflow-hidden">
      {urls.slice(0, 4).map((url, i) => (
        <button
          key={i}
          type="button"
          className="relative aspect-square overflow-hidden"
          onClick={() => onClickImage(i)}
        >
          <img src={url} alt="" className="h-full w-full object-cover transition-transform hover:scale-[1.02]" />
          {i === 3 && extra > 0 && (
            <div className="absolute inset-0 flex items-center justify-center bg-black/50 text-white text-xl font-semibold">
              +{extra}
            </div>
          )}
        </button>
      ))}
    </div>
  );
}

interface PostCardProps {
  post: FeedPost;
}

export function PostCard({ post }: PostCardProps) {
  const userId = useAuthStore((s) => s.userId);
  const queryClient = useQueryClient();
  const [showComments, setShowComments] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [tipOpen, setTipOpen] = useState(false);
  const [lightboxIdx, setLightboxIdx] = useState<number | null>(null);

  const imageUrls = post.image_urls ?? [];
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

  const closeLightbox = useCallback(() => setLightboxIdx(null), []);

  const goToPrev = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    setLightboxIdx((idx) => (idx !== null && idx > 0 ? idx - 1 : idx));
  }, []);

  const goToNext = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    setLightboxIdx((idx) => (idx !== null && idx < imageUrls.length - 1 ? idx + 1 : idx));
  }, [imageUrls.length]);

  // Keyboard navigation in lightbox
  useEffect(() => {
    if (lightboxIdx === null) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "ArrowLeft") {
        setLightboxIdx((idx) => (idx !== null && idx > 0 ? idx - 1 : idx));
      } else if (e.key === "ArrowRight") {
        setLightboxIdx((idx) => (idx !== null && idx < imageUrls.length - 1 ? idx + 1 : idx));
      } else if (e.key === "Escape") {
        setLightboxIdx(null);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [lightboxIdx, imageUrls.length]);

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

        {/* Image grid */}
        {imageUrls.length > 0 && (
          <PostImageGrid urls={imageUrls} onClickImage={setLightboxIdx} />
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
          {!isOwn && (
            <button
              className="flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-emerald-600"
              onClick={() => setTipOpen(true)}
            >
              <DollarSign className="h-4 w-4" />
              <span>Tip</span>
            </button>
          )}
          {(post.tip_total_cents ?? 0) > 0 && (
            <span className="ml-auto text-xs text-emerald-600">
              ${((post.tip_total_cents ?? 0) / 100).toFixed(2)} tipped
            </span>
          )}
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
        initialImageUrls={imageUrls}
      />

      {/* Tip dialog */}
      <TipDialog
        open={tipOpen}
        onOpenChange={setTipOpen}
        postId={post.post_id}
        authorId={post.author_id}
      />

      {/* Image lightbox */}
      {lightboxIdx !== null && imageUrls[lightboxIdx] && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80"
          onClick={closeLightbox}
          role="dialog"
          aria-label="Image preview"
        >
          <button
            className="absolute right-4 top-4 flex h-9 w-9 items-center justify-center rounded-full bg-white/10 text-white transition-colors hover:bg-white/20"
            onClick={closeLightbox}
          >
            <X className="h-5 w-5" />
          </button>

          {imageUrls.length > 1 && lightboxIdx > 0 && (
            <button
              className="absolute left-4 top-1/2 -translate-y-1/2 flex h-9 w-9 items-center justify-center rounded-full bg-white/10 text-white transition-colors hover:bg-white/20"
              onClick={goToPrev}
              aria-label="Previous image"
            >
              <ChevronLeft className="h-5 w-5" />
            </button>
          )}

          {imageUrls.length > 1 && lightboxIdx < imageUrls.length - 1 && (
            <button
              className="absolute right-4 top-1/2 -translate-y-1/2 flex h-9 w-9 items-center justify-center rounded-full bg-white/10 text-white transition-colors hover:bg-white/20"
              onClick={goToNext}
              aria-label="Next image"
            >
              <ChevronRight className="h-5 w-5" />
            </button>
          )}

          <img
            src={imageUrls[lightboxIdx]}
            alt=""
            className="max-h-[90vh] max-w-[90vw] rounded-lg object-contain"
            onClick={(e) => e.stopPropagation()}
          />

          {imageUrls.length > 1 && (
            <div className="absolute bottom-4 left-1/2 -translate-x-1/2 text-sm text-white/70">
              {lightboxIdx + 1} / {imageUrls.length}
            </div>
          )}
        </div>
      )}
    </Card>
  );
}
