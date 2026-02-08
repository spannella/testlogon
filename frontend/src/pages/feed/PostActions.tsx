import { useState } from "react";
import { MoreHorizontal, Pencil, Trash2, EyeOff, Flag } from "lucide-react";
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
import { deletePost, hidePost } from "@/api/endpoints/newsfeed";

interface PostActionsProps {
  postId: string;
  isOwn: boolean;
  onEdit: () => void;
}

export function PostActions({ postId, isOwn, onEdit }: PostActionsProps) {
  const queryClient = useQueryClient();
  const [deleteOpen, setDeleteOpen] = useState(false);

  const deleteMut = useMutation({
    mutationFn: () => deletePost(postId),
    onSuccess: () => {
      toast.success("Post deleted");
      void queryClient.invalidateQueries({ queryKey: ["feed"] });
      setDeleteOpen(false);
    },
    onError: () => toast.error("Failed to delete post"),
  });

  const hideMut = useMutation({
    mutationFn: () => hidePost({ post_id: postId }),
    onSuccess: () => {
      toast.success("Post hidden from your feed");
      void queryClient.invalidateQueries({ queryKey: ["feed"] });
    },
    onError: () => toast.error("Failed to hide post"),
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
              <DropdownMenuItem
                onClick={() => toast.info("Report submitted")}
              >
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
    </>
  );
}
