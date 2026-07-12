import { useState, useCallback, useEffect } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Heart, MessageCircle, Lock, DollarSign, X, ChevronLeft, ChevronRight, CreditCard, Check, Loader2, Share2, FileText, Flag, Bookmark, BookmarkCheck, Hash, Clock, AlertCircle, RotateCcw, Trash2, Sparkles } from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Separator } from "@/components/ui/separator";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { likePost, unlikePost, unlockPost, addPostReaction, removePostReaction, reportFeedContent } from "@/api/endpoints/newsfeed";
import { markPostInteresting, unmarkPostInteresting } from "@/api/endpoints/postInteresting";
import { createBookmark, removeBookmark } from "@/api/endpoints/bookmarks";
import { getPaymentMethods } from "@/api/endpoints/billing";
import { ApiError } from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import { CommentsThread } from "./CommentsThread";
import { PostActions } from "./PostActions";
import { EditPostDialog } from "./EditPostDialog";
import { RichContentRenderer } from "./RichContentRenderer";
import { isEmojiOnly } from "@/utils/emoji";
import { TipDialog } from "./TipDialog";
import { SharePostDialog } from "./SharePostDialog";
import { RepostButton } from "./RepostButton";
import { FilePreview } from "@/pages/files/FilePreview";
import { ReportContentModal, type ReportContentPayload } from "@/components/shared/ReportContentModal";
import { resolveCanonicalProfilePath } from "@/components/shared/UserProfileLink";
import { VideoPostPlayer } from "./VideoPostPlayer";
import type { FeedPost, ImageVariant, PaymentMethod, PostFileAttachment } from "@/api/types";
import { ResponsiveImage } from "@/components/shared/ResponsiveImage";
import { BroadcastPostCard } from "@/components/newsfeed/BroadcastPostCard";
import type { FileEntry } from "@/api/types";
import { isTipLotteryEnabled } from "@/config/featureFlags";
import { PollCard } from "./PollCard";
import { CountdownCard } from "@/components/shared/CountdownCard";
import { FindDateTimePostCard } from "./FindDateTimePostCard";
import { useOfflineStore } from "@/stores/offlineStore";

function formatBytes(bytes?: number): string {
  if (bytes == null) return "";
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + (sizes[i] ?? "TB");
}

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
  imageVariants?: Array<Record<string, ImageVariant>>;
  onClickImage: (index: number) => void;
}

function PostImageGrid({ urls, imageVariants, onClickImage }: PostImageGridProps) {
  const count = urls.length;

  if (count === 1) {
    return (
      <button
        type="button"
        className="mt-3 block w-full overflow-hidden rounded-lg"
        aria-label="Open image 1"
        onClick={() => onClickImage(0)}
      >
        <ResponsiveImage
          src={urls[0]}
          variants={imageVariants?.[0]}
          alt=""
          className="max-h-80 w-full rounded-lg object-cover transition-transform hover:scale-[1.02]"
          sizes="(max-width: 640px) 100vw, 640px"
          loading="lazy"
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
            aria-label={`Open image ${i + 1}`}
            onClick={() => onClickImage(i)}
          >
            <ResponsiveImage src={url} variants={imageVariants?.[i]} alt="" className="h-full w-full object-cover transition-transform hover:scale-[1.02]" loading="lazy" />
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
          aria-label="Open image 1"
          onClick={() => onClickImage(0)}
        >
          <ResponsiveImage src={urls[0]} variants={imageVariants?.[0]} alt="" className="h-full w-full object-cover transition-transform hover:scale-[1.02]" loading="lazy" />
        </button>
        {/* Two square cells below */}
        {urls.slice(1).map((url, i) => (
          <button
            key={i + 1}
            type="button"
            className="aspect-square overflow-hidden"
            aria-label={`Open image ${i + 2}`}
            onClick={() => onClickImage(i + 1)}
          >
            <ResponsiveImage src={url} variants={imageVariants?.[i + 1]} alt="" className="h-full w-full object-cover transition-transform hover:scale-[1.02]" loading="lazy" />
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
            aria-label={`Open image ${i + 1}`}
            onClick={() => onClickImage(i)}
          >
            <ResponsiveImage src={url} variants={imageVariants?.[i]} alt="" className="h-full w-full object-cover transition-transform hover:scale-[1.02]" loading="lazy" />
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
          aria-label={`Open image ${i + 1}`}
          onClick={() => onClickImage(i)}
        >
          <ResponsiveImage src={url} variants={imageVariants?.[i]} alt="" className="h-full w-full object-cover transition-transform hover:scale-[1.02]" loading="lazy" />
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
  defaultShowComments?: boolean;
}

export function PostCard({ post, defaultShowComments = false }: PostCardProps) {
  const userId = useAuthStore((s) => s.userId);
  const queryClient = useQueryClient();
  const [showComments, setShowComments] = useState(defaultShowComments);
  const [editOpen, setEditOpen] = useState(false);
  const [tipOpen, setTipOpen] = useState(false);
  const [shareOpen, setShareOpen] = useState(false);
  const [lightboxIdx, setLightboxIdx] = useState<number | null>(null);
  const [unlockDialogOpen, setUnlockDialogOpen] = useState(false);
  const [unlockPaymentMethodId, setUnlockPaymentMethodId] = useState<string | null>(null);
  const [filePreviewTarget, setFilePreviewTarget] = useState<PostFileAttachment | null>(null);
  const [reportMediaOpen, setReportMediaOpen] = useState(false);
  const [reportMediaIndex, setReportMediaIndex] = useState<number | null>(null);
  const [reportMediaServerError, setReportMediaServerError] = useState<string | null>(null);
  const [isBookmarked, setIsBookmarked] = useState(false);

  const imageUrls = post.image_urls ?? [];
  const isOwn = post.author_id === userId;
  const unlockLimit = typeof post.unlock_limit === "number" && post.unlock_limit > 0 ? post.unlock_limit : undefined;
  const unlockCountRaw = typeof post.unlock_count === "number" ? post.unlock_count : 0;
  const unlockCount = Math.max(0, unlockCountRaw);
  const soldOut = !!post.unlock_limit_reached || (unlockLimit != null && unlockCount >= unlockLimit);
  const remainingUnlockSlots = unlockLimit != null ? Math.max(0, unlockLimit - unlockCount) : undefined;
  const lockExpired = !!post.lock_expired;

  const { data: paymentMethods = [] } = useQuery<PaymentMethod[]>({
    queryKey: ["billing", "payment-methods"],
    queryFn: getPaymentMethods,
    staleTime: 5 * 60 * 1000,
    enabled: !isOwn,
  });

  const likeMutation = useMutation({
    mutationFn: () => (post.liked_by_me ? unlikePost(post.post_id) : likePost(post.post_id)),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["feed"] });
    },
    onError: () => {
      toast.error("Action failed");
    },
  });

  const bookmarkMutation = useMutation({
    mutationFn: () =>
      isBookmarked
        ? removeBookmark("post", post.post_id)
        : createBookmark({ content_type: "post", content_id: post.post_id }),
    onMutate: () => {
      setIsBookmarked((prev) => !prev);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["bookmarks"] });
      toast.success(isBookmarked ? "Saved" : "Removed from saved");
    },
    onError: (error) => {
      // 409 = already bookmarked — treat as success (idempotent)
      const status = error instanceof ApiError ? error.status : 0;
      if (status === 409) {
        setIsBookmarked(true);
        queryClient.invalidateQueries({ queryKey: ["bookmarks"] });
        toast.success("Saved");
        return;
      }
      // 404 on delete = already removed — treat as success
      if (status === 404) {
        setIsBookmarked(false);
        queryClient.invalidateQueries({ queryKey: ["bookmarks"] });
        return;
      }
      setIsBookmarked((prev) => !prev);
      toast.error("Action failed");
    },
  });

  // FEED-007: per-viewer "interesting" signal (more-like-this)
  const [isInteresting, setIsInteresting] = useState(post.is_interesting ?? false);
  useEffect(() => {
    setIsInteresting(post.is_interesting ?? false);
  }, [post.is_interesting]);
  const interestingMutation = useMutation({
    mutationFn: () =>
      isInteresting
        ? unmarkPostInteresting(post.post_id)
        : markPostInteresting(post.post_id),
    onMutate: () => {
      setIsInteresting((prev) => !prev);
    },
    onSuccess: (res) => {
      setIsInteresting(res.is_interesting);
      queryClient.invalidateQueries({ queryKey: ["feed"] });
      toast.success(res.is_interesting ? "Marked interesting" : "Removed");
    },
    onError: () => {
      setIsInteresting((prev) => !prev);
      toast.error("Action failed");
    },
  });

  const unlockMutation = useMutation({
    mutationFn: (paymentMethodId?: string | null) => unlockPost(post.post_id, paymentMethodId ?? undefined),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["feed"] });
      toast.success("Post unlocked!");
      setUnlockDialogOpen(false);
    },
    onError: (error) => {
      const detail = error instanceof ApiError && error.body && typeof error.body === "object"
        ? (error.body as { detail?: unknown }).detail
        : null;
      const code = detail && typeof detail === "object" ? (detail as { code?: unknown }).code : null;

      if (code === "unlock_limit_reached") {
        toast.error("This post is sold out and can no longer be unlocked.");
        queryClient.invalidateQueries({ queryKey: ["feed"] });
        setUnlockDialogOpen(false);
        return;
      }
      if (code === "post_lock_expired") {
        toast.error("This post’s lock has expired and can no longer be unlocked.");
        queryClient.invalidateQueries({ queryKey: ["feed"] });
        setUnlockDialogOpen(false);
        return;
      }
      if (code === "unlock_attempt_throttled") {
        toast.error("Please wait a moment before trying to unlock again.");
        return;
      }
      toast.error("Failed to unlock post");
    },
  });


  const reportMediaMut = useMutation({
    mutationFn: ({ topics, reason_text }: ReportContentPayload) => reportFeedContent({
      content_type: "feed_media",
      content_id: `${post.post_id}:${reportMediaIndex ?? 0}` ,
      topics,
      reason_text,
      post_id: post.post_id,
      media_index: reportMediaIndex ?? undefined,
    }),
    onSuccess: () => {
      toast.success("Report received");
      setReportMediaOpen(false);
      setReportMediaServerError(null);
    },
    onError: (error) => {
      if (error instanceof ApiError && typeof error.message === "string" && error.message.trim()) {
        setReportMediaServerError(error.message);
      } else {
        setReportMediaServerError("Could not submit report. Please try again.");
      }
      toast.error("Could not submit report. Please try again.");
    },
  });

  const lotteryFeatureEnabled = isTipLotteryEnabled();
  const isLotteryLock = lotteryFeatureEnabled && post.lock_type === "tip_lottery";
  const isFixedPriceLock = post.lock_type === "fixed_price" || (!!post.unlock_price_cents && post.lock_type !== "tip_lottery");
  const isLocked = !!post.locked && !post.unlocked;
  const lotteryTipText = post.lottery_tip_cents != null ? `$${(post.lottery_tip_cents / 100).toFixed(2)}` : "N/A";
  const lotteryQuietText = post.lottery_quiet_period_seconds != null ? `${post.lottery_quiet_period_seconds}s` : "N/A";
  const lotteryStateText = post.lottery_state ?? "open";
  const authorName = post.author_display_name || post.author_id;
  const initials = authorName.slice(0, 2).toUpperCase();
  const authorProfilePath = resolveCanonicalProfilePath({ userId: post.author_id, displayName: authorName });

  const REACTION_EMOJIS = ["👍", "❤️", "😂", "🔥", "😮"];

  const addReactionMut = useMutation({
    mutationFn: (emoji: string) => addPostReaction(post.post_id, emoji),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["feed"] }),
    onError: () => toast.error("Failed to react"),
  });

  const removeReactionMut = useMutation({
    mutationFn: (emoji: string) => removePostReaction(post.post_id, emoji),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["feed"] }),
    onError: () => toast.error("Failed to remove reaction"),
  });

  const handleReaction = (emoji: string, isMine: boolean) => {
    if (isMine) {
      removeReactionMut.mutate(emoji);
    } else {
      addReactionMut.mutate(emoji);
    }
  };

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

  const isOfflinePost = !!post.__offline;

  return (
    <Card className={cn(
      isOfflinePost && "opacity-70",
      post.__offline?.status === "failed" && "ring-1 ring-destructive/30 opacity-90",
    )}>
      <CardContent className="p-4">
        {/* Author header */}
        <div className="flex items-center gap-3">
          <a
            href={authorProfilePath ?? "#"}
            aria-label={`Open ${authorName} profile`}
            className="rounded-full hover:opacity-90"
          >
            <Avatar className="h-9 w-9">
              <AvatarFallback className="text-xs">{initials}</AvatarFallback>
            </Avatar>
          </a>
          <div className="min-w-0 flex-1">
            <a
              href={authorProfilePath ?? "#"}
              aria-label={`Open ${authorName} profile`}
              className="text-sm font-medium hover:underline"
            >
              {authorName}
            </a>
            <p className="text-[10px] text-muted-foreground">
              {formatRelative(post.created_at)}
              {post.updated_at && (
                <span className="ml-1 italic">(edited)</span>
              )}
            </p>
          </div>
          <PostActions
            postId={post.post_id}
            postStatus={post.status}
            isOwn={isOwn}
            onEdit={() => setEditOpen(true)}
          />
        </div>

        {/* BCAST-010: Broadcast post card */}
        {post.broadcast_meta && (
          <BroadcastPostCard broadcastMeta={post.broadcast_meta} />
        )}

        {/* ADS-013: FTC sponsorship disclosure (set server-side, immutable) */}
        {post.ftc_disclosure && (
          <div
            className="mt-2 flex items-center gap-1 text-xs text-muted-foreground"
            data-testid="ftc-disclosure"
          >
            <Check className="h-3 w-3" />
            <span>{post.ftc_disclosure}</span>
          </div>
        )}

        {/* Post body */}
        <div className="mt-3">
          {unlockLimit != null && (
            <div className="mb-2 flex flex-wrap items-center gap-1.5 text-[11px]">
              <span className="rounded-full border border-border bg-muted px-2 py-0.5 text-muted-foreground">
                Unlocks {Math.min(unlockCount, unlockLimit)}/{unlockLimit}
              </span>
              <span
                className={cn(
                  "rounded-full px-2 py-0.5",
                  soldOut ? "bg-destructive/15 text-destructive" : "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
                )}
              >
                {soldOut ? "Sold out" : `${remainingUnlockSlots ?? 0} remaining`}
              </span>
            </div>
          )}
          {isLotteryLock && (
            <div className="mb-2 rounded-md border border-amber-300/40 bg-amber-50/40 px-2.5 py-1.5 text-xs text-amber-900 dark:border-amber-700/60 dark:bg-amber-900/20 dark:text-amber-200">
              <span className="font-medium">Lottery lock</span>
              <span>{` • Tip ${lotteryTipText}`}</span>
              <span>{` • Quiet period ${lotteryQuietText}`}</span>
              <span>{` • State ${lotteryStateText}`}</span>
            </div>
          )}
          {isLocked ? (
            <div className="relative">
              <div className="blur-sm select-none">
                <RichContentRenderer
                  body={post.body}
                  bodyPlain={post.body_plain}
                  bodyMarkdown={post.body_markdown}
                  bodyMarkdownHtml={post.body_markdown_html}
                  bodyRich={(post.body_rich as Record<string, unknown> | null) ?? null}
                  bodyFormat={post.body_format}
                />
              </div>
              <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 bg-background/60 rounded">
                <Lock className="h-6 w-6 text-muted-foreground" />
                {lockExpired ? (
                  <p className="text-xs text-muted-foreground px-4 text-center">
                    Lock expired — this post can no longer be unlocked.
                  </p>
                ) : soldOut ? (
                  <p className="text-xs text-destructive px-4 text-center">
                    Sold out — no unlock slots remaining.
                  </p>
                ) : isFixedPriceLock ? (
                  paymentMethods.length === 0 ? (
                    <p className="text-xs text-muted-foreground px-4 text-center">
                      Add a payment method in Billing to unlock this post
                    </p>
                  ) : (
                    <Button
                      size="sm"
                      onClick={() => {
                        const def = paymentMethods.find((m) => m.is_default) ?? paymentMethods[0];
                        setUnlockPaymentMethodId(def?.payment_method_id ?? null);
                        setUnlockDialogOpen(true);
                      }}
                    >
                      {`Unlock for $${((post.unlock_price_cents ?? 0) / 100).toFixed(2)}`}
                    </Button>
                  )
                ) : isLotteryLock ? (
                  <p className="text-xs text-muted-foreground px-4 text-center">
                    Lottery lock: tip {lotteryTipText} and stay uncontested for {lotteryQuietText} to unlock.
                  </p>
                ) : (
                  <p className="text-xs text-muted-foreground px-4 text-center">
                    This post is locked.
                  </p>
                )}
              </div>
            </div>
          ) : (
            <RichContentRenderer
              body={post.body}
              bodyPlain={post.body_plain}
              bodyMarkdown={post.body_markdown}
              bodyMarkdownHtml={post.body_markdown_html}
              bodyRich={(post.body_rich as Record<string, unknown> | null) ?? null}
              bodyFormat={post.body_format}
              className={
                // MSG-006: render emoji-only posts at larger size.
                isEmojiOnly(post.body_plain ?? post.body) ? "text-5xl leading-relaxed py-1" : ""
              }
            />
          )}
        </div>

        {/* SOCIAL-006: Tag chips */}
        {(post.tags ?? []).length > 0 && !isLocked && (
          <div className="mt-2 flex flex-wrap gap-1.5" data-testid="post-tags">
            {(post.tags ?? []).map((tag) => (
              <Link key={tag} to={`/discover/tags/${tag}`}>
                <Badge variant="outline" className="text-xs cursor-pointer hover:bg-accent">
                  #{tag}
                </Badge>
              </Link>
            ))}
          </div>
        )}

        {/* FEED-005: Countdown card */}
        {post.post_kind === "countdown" && post.countdown_title && post.target_datetime && !isLocked && (
          <div className="mt-3">
            <CountdownCard
              title={post.countdown_title}
              targetDatetime={post.target_datetime}
              associatedEventType={post.associated_event_type ?? "custom"}
              associatedEventId={post.associated_event_id}
            />
          </div>
        )}

        {/* FEED-003: Find-a-DateTime card */}
        {post.post_kind === "find_datetime" && post.find_datetime_id && !isLocked && (
          <FindDateTimePostCard post={post} isOwn={isOwn} />
        )}

        {/* ENGAGE-002: Poll/Survey card */}
        {post.poll_data && !isLocked && (post.post_type === "poll" || post.post_type === "survey") && (
          <PollCard
            postId={post.post_id}
            pollData={post.poll_data}
            voteCounts={post.poll_vote_counts ?? {}}
            myVotes={post.poll_my_votes}
            authorId={post.author_id}
          />
        )}

        {/* Video embed */}
        {post.video && !isLocked && (
          <VideoPostPlayer postId={post.post_id} video={post.video} className="mt-3" />
        )}
        {post.video && isLocked && (
          <div className="mt-3 relative aspect-video rounded-lg overflow-hidden">
            {post.video.thumbnail_url ? (
              <img src={post.video.thumbnail_url} alt="" className="w-full h-full object-cover blur-lg" />
            ) : (
              <div className="w-full h-full bg-muted" />
            )}
            <div className="absolute inset-0 flex flex-col items-center justify-center bg-black/50">
              <Lock className="h-8 w-8 text-white mb-2" />
              <p className="text-white text-sm font-medium">
                Unlock for ${((post.unlock_price_cents ?? 0) / 100).toFixed(2)}
              </p>
            </div>
          </div>
        )}

        {/* Image grid */}
        {imageUrls.length > 0 && (
          <PostImageGrid urls={imageUrls} imageVariants={post.image_variants} onClickImage={setLightboxIdx} />
        )}

        {/* File attachment cards */}
        {!isLocked && (post.file_attachments ?? []).length > 0 && (
          <div className="mt-3 space-y-1.5">
            {(post.file_attachments ?? []).map((fa, i) => (
              <button
                key={i}
                type="button"
                onClick={() => setFilePreviewTarget(fa)}
                className="flex w-full items-center gap-2 rounded-lg border bg-muted/40 px-3 py-2 text-left hover:bg-muted/70 transition-colors"
              >
                <FileText className="h-5 w-5 shrink-0 text-muted-foreground" />
                <span className="min-w-0 flex-1 truncate text-sm font-medium">{fa.name}</span>
                {fa.size != null && (
                  <span className="shrink-0 text-xs text-muted-foreground">{formatBytes(fa.size)}</span>
                )}
              </button>
            ))}
          </div>
        )}

        {/* Action row */}
        <div className="mt-3 flex items-center gap-4">
          <button
            aria-label="Like"
            className={cn(
              "flex items-center gap-1 text-sm transition-colors",
              post.liked_by_me
                ? "text-red-500"
                : "text-muted-foreground hover:text-red-500",
            )}
            onClick={() => likeMutation.mutate()}
            disabled={isOfflinePost || likeMutation.isPending}
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
            disabled={isOfflinePost}
            aria-label={showComments ? "Hide comments" : "Show comments"}
            aria-expanded={showComments}
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
          <RepostButton
            postId={post.post_id}
            authorId={post.author_id}
            repostCount={post.repost_count ?? 0}
            repostedByMe={post.reposted_by_me ?? false}
            isLocked={post.unlock_price_cents != null && post.unlock_price_cents > 0 && !!post.locked}
            isOwn={isOwn}
          />
          <button
            className="flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground"
            onClick={() => setShareOpen(true)}
            aria-label="Share post"
          >
            <Share2 className="h-4 w-4" />
          </button>
          <button
            className={cn(
              "flex items-center gap-1 text-sm transition-colors",
              isBookmarked
                ? "text-amber-500"
                : "text-muted-foreground hover:text-amber-500",
            )}
            onClick={() => bookmarkMutation.mutate()}
            disabled={bookmarkMutation.isPending}
            aria-label={isBookmarked ? "Remove bookmark" : "Bookmark post"}
          >
            {isBookmarked ? (
              <BookmarkCheck className="h-4 w-4 fill-amber-500" />
            ) : (
              <Bookmark className="h-4 w-4" />
            )}
          </button>
          {!isOwn && (
            <button
              className={cn(
                "flex items-center gap-1 text-sm transition-colors",
                isInteresting
                  ? "text-sky-500"
                  : "text-muted-foreground hover:text-sky-500",
              )}
              onClick={() => interestingMutation.mutate()}
              disabled={interestingMutation.isPending || isOfflinePost}
              aria-label={isInteresting ? "Unmark interesting" : "Mark interesting"}
              data-testid="interesting-toggle"
            >
              <Sparkles className={cn("h-4 w-4", isInteresting && "fill-sky-500")} />
              <span>Interesting</span>
            </button>
          )}
          {(post.tip_total_cents ?? 0) > 0 && (
            <span className="ml-auto text-xs text-emerald-600">
              ${((post.tip_total_cents ?? 0) / 100).toFixed(2)} tipped
            </span>
          )}
        </div>

        {/* Reaction bar */}
        <div className="mt-2 flex items-center flex-wrap gap-1">
          {REACTION_EMOJIS.map((emoji) => {
            const count = (post.reactions_counts ?? {})[emoji] ?? 0;
            const isMine = (post.my_reactions ?? []).includes(emoji);
            return (
              <button
                key={emoji}
                type="button"
                onClick={() => handleReaction(emoji, isMine)}
                disabled={addReactionMut.isPending || removeReactionMut.isPending}
                className={cn(
                  "flex items-center gap-0.5 rounded-full border px-2 py-0.5 text-sm transition-colors",
                  isMine
                    ? "border-primary/40 bg-primary/10 text-primary"
                    : "border-transparent hover:border-border hover:bg-muted text-muted-foreground",
                )}
              >
                <span>{emoji}</span>
                {count > 0 && <span className="text-xs font-medium">{count}</span>}
              </button>
            );
          })}
        </div>

        {/* Comments thread */}
        {showComments && !isOfflinePost && (
          <>
            <Separator className="my-3" />
            <CommentsThread postId={post.post_id} />
          </>
        )}

        {/* PWA-005: Offline status indicator */}
        {post.__offline && (
          <div className="flex items-center gap-1 text-xs text-muted-foreground border-t pt-2 mt-2">
            {post.__offline.status === "pending" && (
              <>
                <Clock className="h-3 w-3 animate-pulse" />
                <span>Waiting to publish...</span>
              </>
            )}
            {post.__offline.status === "sending" && (
              <>
                <Loader2 className="h-3 w-3 animate-spin" />
                <span>Publishing...</span>
              </>
            )}
            {post.__offline.status === "failed" && (
              <>
                <AlertCircle className="h-3 w-3 text-destructive" />
                <span className="text-destructive">{post.__offline.error ?? "Failed to publish"}</span>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-5 px-1.5 text-xs"
                  onClick={() => {
                    useOfflineStore.getState().retryAction(post.__offline!.queueId);
                    toast.info("Post re-queued");
                  }}
                >
                  <RotateCcw className="h-3 w-3 mr-0.5" />
                  Retry
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-5 px-1.5 text-xs text-muted-foreground hover:text-destructive"
                  onClick={() => {
                    useOfflineStore.getState().removeFromQueue(post.__offline!.queueId);
                    toast.info("Queued post discarded");
                  }}
                >
                  <Trash2 className="h-3 w-3 mr-0.5" />
                  Discard
                </Button>
              </>
            )}
          </div>
        )}
      </CardContent>

      {/* Edit dialog */}
      <EditPostDialog
        open={editOpen}
        onOpenChange={setEditOpen}
        postId={post.post_id}
        postStatus={post.status}
        initialPublishAt={post.publish_at}
        initialScheduleTimezone={post.schedule_timezone}
        initialScheduledAtLocal={post.scheduled_at_local}
        initialBody={post.body}
        initialImageUrls={imageUrls}
        initialBodyRich={(post.body_rich as any) ?? null}
        initialUnlockPriceCents={post.unlock_price_cents}
        initialUnlockLimit={post.unlock_limit ?? null}
      />

      {/* Tip dialog */}
      <TipDialog
        open={tipOpen}
        onOpenChange={setTipOpen}
        postId={post.post_id}
        authorId={post.author_id}
      />

      {/* Share dialog */}
      <SharePostDialog
        open={shareOpen}
        onClose={() => setShareOpen(false)}
        post={post}
      />

      {/* Unlock dialog */}
      <Dialog
        open={unlockDialogOpen}
        onOpenChange={(open) => { if (!open) { setUnlockDialogOpen(false); setUnlockPaymentMethodId(null); } }}
      >
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Lock className="h-4 w-4" />
              Unlock post
            </DialogTitle>
            <DialogDescription>
              {lockExpired
                ? "This lock has expired, so this post can no longer be unlocked."
                : soldOut
                ? "This post is sold out and has no unlock slots remaining."
                : `Pay $${((post.unlock_price_cents ?? 0) / 100).toFixed(2)} to unlock this post.`}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Payment method</label>
              <div className="space-y-2">
                {paymentMethods.map((pm) => {
                  const label = pm.brand
                    ? `${pm.brand.charAt(0).toUpperCase() + pm.brand.slice(1)} •••• ${pm.last4}`
                    : (pm.label ?? pm.method_type);
                  const isSelected = unlockPaymentMethodId === pm.payment_method_id;
                  return (
                    <button
                      key={pm.payment_method_id}
                      type="button"
                      onClick={() => setUnlockPaymentMethodId(pm.payment_method_id)}
                      className={cn(
                        "flex w-full items-center gap-3 rounded-lg border px-3 py-2.5 text-sm transition-colors hover:bg-accent",
                        isSelected ? "border-primary bg-primary/5" : "border-border",
                      )}
                    >
                      <CreditCard className="h-4 w-4 shrink-0 text-muted-foreground" />
                      <span className="flex-1 text-left">{label}</span>
                      {pm.is_default && (
                        <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">Default</span>
                      )}
                      {isSelected && <Check className="h-4 w-4 text-primary" />}
                    </button>
                  );
                })}
              </div>
            </div>
            <div className="rounded-lg border border-border bg-muted/40 p-3 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Total charge</span>
                <span className="font-semibold">${((post.unlock_price_cents ?? 0) / 100).toFixed(2)} USD</span>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setUnlockDialogOpen(false)} disabled={unlockMutation.isPending}>
              Cancel
            </Button>
            <Button
              onClick={() => unlockMutation.mutate(unlockPaymentMethodId)}
              disabled={unlockMutation.isPending || !unlockPaymentMethodId || soldOut || lockExpired}
            >
              {unlockMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : lockExpired ? "Expired" : soldOut ? "Sold out" : "Pay & Unlock"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* File preview modal */}
      {filePreviewTarget && (
        <FilePreview
          file={{
            name: filePreviewTarget.name,
            path: "",
            type: "file",
            size: filePreviewTarget.size,
            content_type: filePreviewTarget.content_type,
          } as FileEntry}
          files={[]}
          previewSrcUrl={filePreviewTarget.url}
          onClose={() => setFilePreviewTarget(null)}
          onNavigate={() => {}}
          onDownload={() => window.open(filePreviewTarget.url, "_blank", "noopener,noreferrer")}
        />
      )}

      {!isOwn && (
        <ReportContentModal
          open={reportMediaOpen}
          onOpenChange={(open) => {
            setReportMediaOpen(open);
            if (!open && !reportMediaMut.isPending) {
              setReportMediaServerError(null);
            }
          }}
          title="Report image"
          description="Share why this image should be reviewed."
          serverError={reportMediaServerError}
          isSubmitting={reportMediaMut.isPending}
          onSubmit={async (payload) => {
            setReportMediaServerError(null);
            await reportMediaMut.mutateAsync(payload);
          }}
        />
      )}

      {/* Image lightbox */}
      {lightboxIdx !== null && imageUrls[lightboxIdx] && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80"
          onClick={closeLightbox}
          role="dialog"
          aria-label="Image preview"
        >
          {!isOwn && (
            <button
              className="absolute left-4 top-4 inline-flex items-center gap-1 rounded-full bg-white/10 px-3 py-1.5 text-xs text-white transition-colors hover:bg-white/20"
              onClick={(e) => {
                e.stopPropagation();
                if (lightboxIdx === null) return;
                setReportMediaIndex(lightboxIdx);
                setReportMediaServerError(null);
                setReportMediaOpen(true);
              }}
            >
              <Flag className="h-3.5 w-3.5" /> Report image
            </button>
          )}

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
