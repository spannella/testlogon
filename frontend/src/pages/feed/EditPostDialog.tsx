import { useState, useEffect } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { editPost } from "@/api/endpoints/newsfeed";

interface EditPostDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  postId: string;
  initialBody: string;
}

export function EditPostDialog({
  open,
  onOpenChange,
  postId,
  initialBody,
}: EditPostDialogProps) {
  const queryClient = useQueryClient();
  const [body, setBody] = useState(initialBody);

  // Sync with prop when dialog opens
  useEffect(() => {
    if (open) setBody(initialBody);
  }, [open, initialBody]);

  const mutation = useMutation({
    mutationFn: () => editPost(postId, { body }),
    onSuccess: () => {
      toast.success("Post updated");
      void queryClient.invalidateQueries({ queryKey: ["feed"] });
      onOpenChange(false);
    },
    onError: () => toast.error("Failed to update post"),
  });

  const handleSave = () => {
    if (!body.trim()) return;
    mutation.mutate();
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Edit Post</DialogTitle>
        </DialogHeader>

        <Textarea
          value={body}
          onChange={(e) => setBody(e.target.value)}
          rows={5}
          className="resize-none"
          placeholder="Write something..."
        />

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={handleSave}
            disabled={!body.trim() || mutation.isPending}
          >
            {mutation.isPending ? "Saving..." : "Save"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
