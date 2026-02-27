import { useState } from "react";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Send, MoreHorizontal, Pencil, Trash2, X, Check, DollarSign } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Skeleton } from "@/components/ui/skeleton";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import {
  getComments,
  createComment,
  editComment,
  deleteComment,
} from "@/api/endpoints/newsfeed";
import { useAuthStore } from "@/stores/authStore";
import type { FeedComment } from "@/api/types";
import { TipDialog } from "./TipDialog";

interface CommentsThreadProps {
  postId: string;
}

export function CommentsThread({ postId }: CommentsThreadProps) {
  const userId = useAuthStore((s) => s.userId);
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

// ─── Single comment row with edit / delete ──────────────────────

interface CommentRowProps {
  comment: FeedComment;
  postId: string;
  isOwn: boolean;
}

function CommentRow({ comment, postId, isOwn }: CommentRowProps) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [editBody, setEditBody] = useState(comment.body);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [tipOpen, setTipOpen] = useState(false);

  const editMut = useMutation({
    mutationFn: () => editComment(postId, comment.comment_id, { body: editBody }),
    onSuccess: () => {
      toast.success("Comment updated");
      void queryClient.invalidateQueries({ queryKey: ["comments", postId] });
      setEditing(false);
    },
    onError: () => toast.error("Failed to update comment"),
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
    setEditBody(comment.body);
    setEditing(true);
  };

  const cancelEdit = () => {
    setEditing(false);
    setEditBody(comment.body);
  };

  const saveEdit = () => {
    if (!editBody.trim()) return;
    editMut.mutate();
  };

  return (
    <>
      <div className="group flex gap-2">
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
            {comment.updated_at && (
              <span className="text-[10px] italic text-muted-foreground">(edited)</span>
            )}
          </div>

          {editing ? (
            <div className="mt-1 flex items-center gap-1">
              <Input
                value={editBody}
                onChange={(e) => setEditBody(e.target.value)}
                className="h-7 text-sm"
                autoFocus
                onKeyDown={(e) => {
                  if (e.key === "Enter") saveEdit();
                  if (e.key === "Escape") cancelEdit();
                }}
              />
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
          ) : (
            <p className="text-sm">{comment.body}</p>
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

        {/* Actions menu — own comments only, when not editing */}
        {isOwn && !editing && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="h-6 w-6 shrink-0 opacity-0 transition-opacity group-hover:opacity-100"
              >
                <MoreHorizontal className="h-3.5 w-3.5" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={startEdit}>
                <Pencil className="mr-2 h-3.5 w-3.5" /> Edit
              </DropdownMenuItem>
              <DropdownMenuItem
                className="text-destructive focus:text-destructive"
                onClick={() => setDeleteOpen(true)}
              >
                <Trash2 className="mr-2 h-3.5 w-3.5" /> Delete
              </DropdownMenuItem>
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
