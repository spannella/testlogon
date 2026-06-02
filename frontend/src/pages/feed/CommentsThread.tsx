import { useState } from "react";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Send, MoreHorizontal, Pencil, Trash2, X, Check, DollarSign, Flag, Smile, Images, Sticker as StickerIcon } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Skeleton } from "@/components/ui/skeleton";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { ReportContentModal, type ReportContentPayload } from "@/components/shared/ReportContentModal";
import { EmojiPicker } from "@/components/shared/EmojiPicker";
import { GifPicker } from "@/components/shared/GifPicker";
import { StickerPicker } from "@/components/shared/StickerPicker";
import {
  getComments,
  createComment,
  editComment,
  deleteComment,
  reportFeedContent,
} from "@/api/endpoints/newsfeed";
import { useAuthStore } from "@/stores/authStore";
import { ApiError } from "@/api/client";
import type { FeedComment, CreateCommentReq } from "@/api/types";
import { isEmojiOnly } from "@/utils/emoji";
import { TipDialog } from "./TipDialog";
import { resolveCanonicalProfilePath } from "@/components/shared/UserProfileLink";
import { MarkdownComposer, type EditorMode, type RichDoc, richDocToPlain, buildContentPayload } from "./MarkdownComposer";
import { RichContentRenderer } from "./RichContentRenderer";

interface CommentsThreadProps {
  postId: string;
}

export function CommentsThread({ postId }: CommentsThreadProps) {
  const userId = useAuthStore((s) => s.userId);
  const queryClient = useQueryClient();
  const [body, setBody] = useState("");
  const [editorMode, setEditorMode] = useState<EditorMode>("plain");
  const [richDoc, setRichDoc] = useState<RichDoc | null>(null);
  const [emojiOpen, setEmojiOpen] = useState(false);
  const [gifOpen, setGifOpen] = useState(false);
  const [stickerOpen, setStickerOpen] = useState(false);

  const commentsQuery = useInfiniteQuery({
    queryKey: ["comments", postId],
    queryFn: ({ pageParam }) => getComments(postId, pageParam as string | undefined),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor,
  });

  const sendMutation = useMutation({
    mutationFn: (payload: CreateCommentReq) => createComment(postId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["comments", postId] });
      queryClient.invalidateQueries({ queryKey: ["feed"] });
      setBody("");
      setEditorMode("plain");
      setRichDoc(null);
    },
    onError: (err: unknown) => {
      toast.error(err instanceof Error ? err.message : "Failed to post comment");
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!body.trim()) return;
    sendMutation.mutate({ kind: "text", ...buildContentPayload(body, editorMode, richDoc) });
  };

  // FEED-004: insert an emoji at the end of the comment draft (plain mode).
  const handleEmojiInsert = (emoji: string) => {
    setBody((prev) => prev + emoji);
  };

  // FEED-004: GIF / sticker comments send immediately (one-click).
  const handleGifSelect = (gif: { url: string; alt_text: string; width: number; height: number }) => {
    setGifOpen(false);
    sendMutation.mutate({
      kind: "gif",
      gif_url: gif.url,
      gif_alt_text: gif.alt_text,
      gif_width: gif.width,
      gif_height: gif.height,
    });
  };

  const handleStickerSelect = (sticker: { id: string; collection_id: string; url: string; alt_text: string }) => {
    setStickerOpen(false);
    sendMutation.mutate({
      kind: "sticker",
      sticker_id: sticker.id,
      sticker_collection_id: sticker.collection_id,
      sticker_url: sticker.url,
      sticker_alt_text: sticker.alt_text,
    });
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
            <CommentRow
              key={comment.comment_id}
              comment={comment}
              postId={postId}
              isOwn={comment.author_id === userId}
            />
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
      <form onSubmit={handleSubmit} className="space-y-2">
        <MarkdownComposer
          mode={editorMode}
          onModeChange={setEditorMode}
          value={body}
          onChange={setBody}
          richDoc={richDoc}
          onRichDocChange={setRichDoc}
          placeholder="Write a comment..."
          rows={2}
        />
        <div className="flex items-center justify-between">
          {/* FEED-004: emoji / GIF / sticker toolbar */}
          <div className="flex items-center gap-1">
            <Popover open={emojiOpen} onOpenChange={setEmojiOpen}>
              <PopoverTrigger asChild>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7"
                  aria-label="Insert emoji"
                  data-testid="comment-emoji-button"
                  disabled={sendMutation.isPending}
                >
                  <Smile className="h-4 w-4" />
                </Button>
              </PopoverTrigger>
              <PopoverContent side="top" align="start" className="w-auto p-0">
                <EmojiPicker onSelect={handleEmojiInsert} onClose={() => setEmojiOpen(false)} />
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
                  data-testid="comment-gif-button"
                  disabled={sendMutation.isPending}
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
                  data-testid="comment-sticker-button"
                  disabled={sendMutation.isPending}
                >
                  <StickerIcon className="h-4 w-4" />
                </Button>
              </PopoverTrigger>
              <PopoverContent side="top" align="start" className="w-auto p-2">
                <StickerPicker onSelect={handleStickerSelect} />
              </PopoverContent>
            </Popover>
          </div>
          <Button
            type="submit"
            size="sm"
            variant="ghost"
            disabled={!body.trim() || sendMutation.isPending}
          >
            <Send className="mr-1 h-4 w-4" />
            Post
          </Button>
        </div>
      </form>
    </div>
  );
}

// ─── Single comment row with edit / delete ──────────────────────

interface CommentRowProps {
  comment: FeedComment;
  postId: string;
  isOwn: boolean;
}


function commentMode(comment: FeedComment): EditorMode {
  if (comment.body_format === "rich" && comment.body_rich) return "rich";
  if (comment.body_format === "markdown" && (comment.body_markdown || comment.body_plain || comment.body)) return "markdown";
  return "plain";
}

function commentDraftText(comment: FeedComment): string {
  if (comment.kind === "gif" || comment.kind === "sticker") return "";
  if (comment.body_format === "markdown") return comment.body_markdown ?? comment.body_plain ?? comment.body ?? "";
  if (comment.body_format === "rich") {
    const doc = (comment.body_rich as RichDoc | undefined) ?? null;
    return doc ? (richDocToPlain(doc) || comment.body_plain || comment.body || "") : (comment.body_plain || comment.body || "");
  }
  return comment.body_plain ?? comment.body ?? "";
}

// FEED-004: media comments (gif/sticker) cannot be edited via the text editor.
function isMediaComment(comment: FeedComment): boolean {
  return comment.kind === "gif" || comment.kind === "sticker";
}

function CommentBodyView({ comment }: { comment: FeedComment }) {
  // FEED-004: GIF comment
  if (comment.kind === "gif" && comment.gif_url) {
    return (
      <img
        src={comment.gif_url}
        alt={comment.gif_alt_text || "GIF"}
        className="mt-1 max-w-[200px] rounded"
        loading="lazy"
        data-testid="comment-gif"
      />
    );
  }
  // FEED-004: sticker comment
  if (comment.kind === "sticker" && comment.sticker_url) {
    return (
      <img
        src={comment.sticker_url}
        alt={comment.sticker_alt_text || "Sticker"}
        className="mt-1 h-20 w-20 object-contain"
        loading="lazy"
        data-testid="comment-sticker"
      />
    );
  }
  // FEED-004: emoji-only text renders jumbo (3x)
  const plain = comment.body_plain ?? comment.body;
  if (
    (comment.body_format ?? "plain") === "plain" &&
    isEmojiOnly(plain)
  ) {
    return (
      <p className="text-3xl leading-relaxed" data-testid="comment-emoji-jumbo">
        {plain}
      </p>
    );
  }
  return (
    <RichContentRenderer
      body={comment.body}
      bodyPlain={comment.body_plain}
      bodyMarkdown={comment.body_markdown}
      bodyMarkdownHtml={comment.body_markdown_html}
      bodyRich={(comment.body_rich as Record<string, unknown> | null) ?? null}
      bodyFormat={comment.body_format}
    />
  );
}

function CommentRow({ comment, postId, isOwn }: CommentRowProps) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [editBody, setEditBody] = useState(commentDraftText(comment));
  const [editMode, setEditMode] = useState<EditorMode>(commentMode(comment));
  const [editRichDoc, setEditRichDoc] = useState<RichDoc | null>((comment.body_rich as RichDoc | undefined) ?? null);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [tipOpen, setTipOpen] = useState(false);
  const authorProfilePath = resolveCanonicalProfilePath({ userId: comment.author_id, displayName: comment.author_id });
  const [reportOpen, setReportOpen] = useState(false);
  const [reportServerError, setReportServerError] = useState<string | null>(null);

  const editMut = useMutation({
    mutationFn: () => editComment(postId, comment.comment_id, buildContentPayload(editBody, editMode, editRichDoc)),
    onSuccess: () => {
      toast.success("Comment updated");
      void queryClient.invalidateQueries({ queryKey: ["comments", postId] });
      setEditing(false);
    },
    onError: (err: unknown) => toast.error(err instanceof Error ? err.message : "Failed to update comment"),
  });


  const reportMut = useMutation({
    mutationFn: ({ topics, reason_text }: ReportContentPayload) => reportFeedContent({
      content_type: "feed_comment",
      content_id: comment.comment_id,
      topics,
      reason_text,
      post_id: postId,
      comment_id: comment.comment_id,
    }),
    onSuccess: () => {
      toast.success("Report received");
      setReportOpen(false);
      setReportServerError(null);
    },
    onError: (error) => {
      if (error instanceof ApiError && typeof error.message === "string" && error.message.trim()) {
        setReportServerError(error.message);
      } else {
        setReportServerError("Could not submit report. Please try again.");
      }
      toast.error("Could not submit report. Please try again.");
    },
  });

  const deleteMut = useMutation({
    mutationFn: () => deleteComment(postId, comment.comment_id),
    onSuccess: () => {
      toast.success("Comment deleted");
      void queryClient.invalidateQueries({ queryKey: ["comments", postId] });
      void queryClient.invalidateQueries({ queryKey: ["feed"] });
      setDeleteOpen(false);
    },
    onError: () => toast.error("Failed to delete comment"),
  });

  if (comment.deleted) {
    return (
      <div className="flex gap-2">
        <Avatar className="h-6 w-6 shrink-0">
          <AvatarFallback className="text-[10px]">--</AvatarFallback>
        </Avatar>
        <p className="text-sm italic text-muted-foreground">Comment deleted</p>
      </div>
    );
  }

  const startEdit = () => {
    const existingRich = (comment.body_rich as RichDoc | undefined) ?? null;
    setEditBody(commentDraftText(comment));
    setEditMode(commentMode(comment));
    setEditRichDoc(existingRich);
    setEditing(true);
  };

  const cancelEdit = () => {
    setEditing(false);
    const existingRich = (comment.body_rich as RichDoc | undefined) ?? null;
    setEditBody(commentDraftText(comment));
    setEditMode(commentMode(comment));
    setEditRichDoc(existingRich);
  };

  const saveEdit = () => {
    if (!editBody.trim()) return;
    editMut.mutate();
  };

  return (
    <>
      <div className="group flex gap-2">
        <a
          href={authorProfilePath ?? "#"}
          aria-label={`Open ${comment.author_id} profile`}
          className="shrink-0 rounded-full hover:opacity-90"
        >
          <Avatar className="h-6 w-6 shrink-0">
            <AvatarFallback className="text-[10px]">
              {comment.author_id.slice(0, 2).toUpperCase()}
            </AvatarFallback>
          </Avatar>
        </a>
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline gap-1.5">
            <a
              href={authorProfilePath ?? "#"}
              aria-label={`Open ${comment.author_id} profile`}
              className="text-xs font-medium hover:underline"
            >
              {comment.author_id}
            </a>
            <span className="text-[10px] text-muted-foreground">
              {new Date(comment.created_at).toLocaleDateString()}
            </span>
            {comment.updated_at && (
              <span className="text-[10px] italic text-muted-foreground">(edited)</span>
            )}
          </div>

          {editing ? (
            <div className="mt-1 space-y-2">
              <MarkdownComposer
                mode={editMode}
                onModeChange={setEditMode}
                value={editBody}
                onChange={setEditBody}
                richDoc={editRichDoc}
                onRichDocChange={setEditRichDoc}
                placeholder="Write a comment..."
                rows={2}
              />
              <div className="flex items-center justify-end gap-1">
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 shrink-0"
                  onClick={saveEdit}
                  disabled={!editBody.trim() || editMut.isPending}
                >
                  <Check className="h-3.5 w-3.5" />
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 shrink-0"
                  onClick={cancelEdit}
                >
                  <X className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          ) : (
            <CommentBodyView comment={comment} />
          )}

          {/* Tip total + tip button for non-own comments */}
          {!comment.deleted && (
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
                  className="flex items-center gap-0.5 text-[10px] text-muted-foreground hover:text-emerald-600 transition-colors opacity-0 group-hover:opacity-100"
                >
                  <DollarSign className="h-3 w-3" />
                  Tip
                </button>
              )}
            </div>
          )}
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
                  {!isMediaComment(comment) && (
                    <DropdownMenuItem onClick={startEdit}>
                      <Pencil className="mr-2 h-3.5 w-3.5" /> Edit
                    </DropdownMenuItem>
                  )}
                  <DropdownMenuItem
                    className="text-destructive focus:text-destructive"
                    onClick={() => setDeleteOpen(true)}
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

      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title="Delete Comment"
        description="This comment will be permanently deleted."
        confirmLabel="Delete"
        variant="danger"
        onConfirm={() => deleteMut.mutate()}
        loading={deleteMut.isPending}
      />

      {!isOwn && (
        <ReportContentModal
          open={reportOpen}
          onOpenChange={(open) => {
            setReportOpen(open);
            if (!open && !reportMut.isPending) {
              setReportServerError(null);
            }
          }}
          title="Report comment"
          description="Share why this comment should be reviewed."
          serverError={reportServerError}
          isSubmitting={reportMut.isPending}
          onSubmit={async (payload) => {
            setReportServerError(null);
            await reportMut.mutateAsync(payload);
          }}
        />
      )}

      {!isOwn && (
        <TipDialog
          open={tipOpen}
          onOpenChange={setTipOpen}
          postId={postId}
          authorId={comment.author_id}
          commentId={comment.comment_id}
        />
      )}
    </>
  );
}
