import { useState } from "react";
import { MoreHorizontal, Pencil, Trash2, EyeOff, Flag, Link2 } from "lucide-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { ReportContentModal, type ReportContentPayload } from "@/components/shared/ReportContentModal";
import { cancelScheduledPost, deletePost, hidePost, reportFeedContent } from "@/api/endpoints/newsfeed";
import { ApiError } from "@/api/client";
import { invalidateFeedCaches } from "@/lib/feedCacheInvalidation";

interface PostActionsProps {
  postId: string;
  postStatus?: "scheduled" | "published" | "cancelled";
  isOwn: boolean;
  onEdit: () => void;
}

export function PostActions({ postId, postStatus, isOwn, onEdit }: PostActionsProps) {
  const queryClient = useQueryClient();
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [reportOpen, setReportOpen] = useState(false);
  const [reportServerError, setReportServerError] = useState<string | null>(null);

  const deleteMut = useMutation({
    mutationFn: async () => {
      if (postStatus === "scheduled") {
        await cancelScheduledPost(postId);
      } else {
        await deletePost(postId);
      }
    },
    onSuccess: () => {
      toast.success(postStatus === "scheduled" ? "Scheduled post cancelled" : "Post deleted");
      void invalidateFeedCaches(queryClient);
      void queryClient.invalidateQueries({ queryKey: ["scheduled-posts"] });
      setDeleteOpen(false);
    },
    onError: () => toast.error("Failed to delete post"),
  });

  const hideMut = useMutation({
    mutationFn: () => hidePost({ post_id: postId }),
    onSuccess: () => {
      toast.success("Post hidden from your feed");
      void invalidateFeedCaches(queryClient);
    },
    onError: () => toast.error("Failed to hide post"),
  });

  const reportMut = useMutation({
    mutationFn: ({ topics, reason_text }: ReportContentPayload) => reportFeedContent({
      content_type: "feed_post",
      content_id: postId,
      topics,
      reason_text,
      post_id: postId,
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

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon" className="h-7 w-7 shrink-0">
            <MoreHorizontal className="h-4 w-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem
            onClick={() => {
              navigator.clipboard.writeText(`${window.location.origin}/posts/${postId}`);
              toast.success("Link copied");
            }}
          >
            <Link2 className="mr-2 h-4 w-4" /> Copy link
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          {isOwn ? (
            <>
              <DropdownMenuItem onClick={onEdit}>
                <Pencil className="mr-2 h-4 w-4" /> Edit
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                className="text-destructive focus:text-destructive"
                onClick={() => setDeleteOpen(true)}
              >
                <Trash2 className="mr-2 h-4 w-4" /> Delete
              </DropdownMenuItem>
            </>
          ) : (
            <>
              <DropdownMenuItem onClick={() => hideMut.mutate()}>
                <EyeOff className="mr-2 h-4 w-4" /> Hide
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setReportOpen(true)}>
                <Flag className="mr-2 h-4 w-4" /> Report
              </DropdownMenuItem>
            </>
          )}
        </DropdownMenuContent>
      </DropdownMenu>

      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title="Delete Post"
        description="This post will be permanently deleted. This cannot be undone."
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
          title="Report post"
          description="Share why this post should be reviewed."
          serverError={reportServerError}
          isSubmitting={reportMut.isPending}
          onSubmit={async (payload) => {
            setReportServerError(null);
            await reportMut.mutateAsync(payload);
          }}
        />
      )}
    </>
  );
}
