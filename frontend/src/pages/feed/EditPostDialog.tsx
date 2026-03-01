import { useState, useEffect, useRef } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ImagePlus, Loader2, X } from "lucide-react";
import { toast } from "sonner";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { MarkdownComposer, type EditorMode, type RichDoc, richDocToPlain, buildContentPayload } from "./MarkdownComposer";
import { editPost, uploadPostImage } from "@/api/endpoints/newsfeed";

const MAX_IMAGES = 10;

interface EditPostDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  postId: string;
  initialBody: string;
  initialImageUrls?: string[];
  initialBodyRich?: RichDoc | null;
}

export function EditPostDialog({
  open,
  onOpenChange,
  postId,
  initialBody,
  initialImageUrls,
  initialBodyRich,
}: EditPostDialogProps) {
  const queryClient = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const [body, setBody] = useState(initialBody);
  const [editorMode, setEditorMode] = useState<EditorMode>(initialBodyRich ? "rich" : "plain");
  const [richDoc, setRichDoc] = useState<RichDoc | null>(initialBodyRich ?? null);
  const [imageUrls, setImageUrls] = useState<string[]>(initialImageUrls ?? []);
  const [uploading, setUploading] = useState(false);

  // Sync with props when dialog opens
  useEffect(() => {
    if (open) {
      setBody(initialBodyRich ? richDocToPlain(initialBodyRich) || initialBody : initialBody);
      setImageUrls(initialImageUrls ?? []);
      setEditorMode(initialBodyRich ? "rich" : "plain");
      setRichDoc(initialBodyRich ?? null);
    }
  }, [open, initialBody, initialImageUrls, initialBodyRich]);

  const mutation = useMutation({
    mutationFn: () => editPost(postId, { ...buildContentPayload(body, editorMode, richDoc), image_urls: imageUrls }),
    onSuccess: () => {
      toast.success("Post updated");
      void queryClient.invalidateQueries({ queryKey: ["feed"] });
      onOpenChange(false);
    },
    onError: (err: unknown) => toast.error(err instanceof Error ? err.message : "Failed to update post"),
  });

  const handleSave = () => {
    if (!body.trim() && imageUrls.length === 0) return;
    mutation.mutate();
  };

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    e.target.value = "";

    if (!file.type.startsWith("image/")) {
      toast.error("Please select an image file");
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      toast.error("Image must be under 10 MB");
      return;
    }

    setUploading(true);
    try {
      const result = await uploadPostImage(file);
      setImageUrls((prev) => [...prev, result.url]);
      toast.success("Image uploaded");
    } catch {
      toast.error("Failed to upload image");
    } finally {
      setUploading(false);
    }
  };

  const removeImage = (index: number) => {
    setImageUrls((prev) => prev.filter((_, i) => i !== index));
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Edit Post</DialogTitle>
        </DialogHeader>

        <MarkdownComposer
          mode={editorMode}
          onModeChange={setEditorMode}
          value={body}
          onChange={setBody}
          richDoc={richDoc}
          onRichDocChange={setRichDoc}
          rows={5}
          placeholder="Write something..."
        />

        {/* Upload progress */}
        {uploading && (
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Loader2 className="h-3 w-3 animate-spin" />
            Uploading image...
          </div>
        )}

        {/* Image thumbnails */}
        {imageUrls.length > 0 && !uploading && (
          <div className="flex flex-wrap gap-2">
            {imageUrls.map((url, i) => (
              <div key={i} className="relative inline-block">
                <img
                  src={url}
                  alt={`Attachment ${i + 1}`}
                  className="h-24 w-24 rounded-lg object-cover"
                />
                <button
                  type="button"
                  onClick={() => removeImage(i)}
                  className="absolute -right-1.5 -top-1.5 flex h-5 w-5 items-center justify-center rounded-full bg-destructive text-destructive-foreground shadow-sm"
                >
                  <X className="h-3 w-3" />
                </button>
              </div>
            ))}
          </div>
        )}

        <DialogFooter className="flex items-center justify-between sm:justify-between">
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => fileRef.current?.click()}
            disabled={uploading || imageUrls.length >= MAX_IMAGES}
          >
            <ImagePlus className="mr-1 h-3.5 w-3.5" />
            Photo
            {imageUrls.length > 0 && (
              <span className="ml-1 text-xs text-muted-foreground">
                ({imageUrls.length}/{MAX_IMAGES})
              </span>
            )}
          </Button>
          <input
            ref={fileRef}
            type="file"
            accept="image/*"
            className="hidden"
            onChange={handleFileSelect}
          />
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleSave}
              disabled={(!body.trim() && imageUrls.length === 0) || mutation.isPending || uploading}
            >
              {mutation.isPending ? "Saving..." : "Save"}
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
