import { useState, useRef } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Send, ImagePlus, X, Loader2, FolderOpen, Lock, Paperclip } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent } from "@/components/ui/card";
import { createPost, uploadPostImage } from "@/api/endpoints/newsfeed";
import { downloadUrl } from "@/api/endpoints/files";
import { FilePickerDialog } from "@/pages/messages/FilePickerDialog";
import type { FileEntry } from "@/api/types";

const MAX_IMAGES = 10;
const MAX_FILES = 5;

export function CreatePost() {
  const queryClient = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const [body, setBody] = useState("");
  const [imageUrls, setImageUrls] = useState<string[]>([]);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [filePickerOpen, setFilePickerOpen] = useState(false);
  const [attachFilePickerOpen, setAttachFilePickerOpen] = useState(false);
  const [pendingFiles, setPendingFiles] = useState<FileEntry[]>([]);
  const [lockEnabled, setLockEnabled] = useState(false);
  const [lockPrice, setLockPrice] = useState("");

  const unlockPriceCents = (() => {
    if (!lockEnabled || !lockPrice.trim()) return undefined;
    const cents = Math.round(parseFloat(lockPrice) * 100);
    return isNaN(cents) || cents <= 0 ? undefined : cents;
  })();

  const mutation = useMutation({
    mutationFn: () =>
      createPost({
        body,
        ...(imageUrls.length > 0 ? { image_urls: imageUrls } : {}),
        ...(pendingFiles.length > 0 ? { file_paths: pendingFiles.map((f) => f.path) } : {}),
        ...(unlockPriceCents ? { unlock_price_cents: unlockPriceCents } : {}),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["feed"] });
      setBody("");
      setImageUrls([]);
      setPendingFiles([]);
      setLockEnabled(false);
      setLockPrice("");
      toast.success("Post published");
    },
    onError: () => {
      toast.error("Failed to create post");
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!body.trim() && imageUrls.length === 0 && pendingFiles.length === 0) return;
    mutation.mutate();
  };

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Reset input so re-selecting same file works
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
    setUploadProgress(50);

    try {
      const result = await uploadPostImage(file);
      setUploadProgress(100);
      setImageUrls((prev) => [...prev, result.url]);
      toast.success("Image uploaded");
    } catch {
      toast.error("Failed to upload image");
    } finally {
      setUploading(false);
      setUploadProgress(0);
    }
  };

  const removeImage = (index: number) => {
    setImageUrls((prev) => prev.filter((_, i) => i !== index));
  };

  const handleFileManagerSelect = async (entry: FileEntry) => {
    if (entry.type === "folder") return;
    const ct = entry.content_type ?? "";
    if (!ct.startsWith("image/")) {
      toast.error("Only image files can be attached to posts");
      return;
    }
    if (imageUrls.length >= MAX_IMAGES) {
      toast.error(`Maximum ${MAX_IMAGES} images per post`);
      return;
    }

    setFilePickerOpen(false);
    setUploading(true);
    setUploadProgress(30);

    try {
      const resp = await fetch(downloadUrl(entry.path), { credentials: "include" });
      if (!resp.ok) throw new Error("Failed to fetch file");
      setUploadProgress(60);
      const blob = await resp.blob();
      const file = new File([blob], entry.name, { type: ct });
      if (file.size > 10 * 1024 * 1024) {
        toast.error("Image must be under 10 MB");
        return;
      }
      const result = await uploadPostImage(file);
      setUploadProgress(100);
      setImageUrls((prev) => [...prev, result.url]);
      toast.success("Image attached from Files");
    } catch {
      toast.error("Failed to attach image from Files");
    } finally {
      setUploading(false);
      setUploadProgress(0);
    }
  };

  const handleAttachFileSelect = (entry: FileEntry) => {
    if (entry.type === "folder") return;
    if (pendingFiles.length >= MAX_FILES) {
      toast.error(`Maximum ${MAX_FILES} file attachments per post`);
      return;
    }
    if (pendingFiles.some((f) => f.path === entry.path)) {
      toast.error("File already attached");
      return;
    }
    setPendingFiles((prev) => [...prev, entry]);
    setAttachFilePickerOpen(false);
  };

  return (
    <Card>
      <CardContent className="p-4">
        <form onSubmit={handleSubmit} className="space-y-3">
          <Textarea
            placeholder="What's on your mind?"
            value={body}
            onChange={(e) => setBody(e.target.value)}
            rows={3}
          />

          {/* Upload progress */}
          {uploading && (
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Loader2 className="h-3 w-3 animate-spin" />
                Uploading image...
              </div>
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
                <div
                  className="h-full rounded-full bg-primary transition-all duration-300"
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
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

          {/* Pending non-image file attachments */}
          {pendingFiles.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {pendingFiles.map((f, i) => (
                <div
                  key={f.path}
                  className="flex items-center gap-1 rounded-full border bg-muted/50 px-2.5 py-1 text-xs"
                >
                  <Paperclip className="h-3 w-3 text-muted-foreground shrink-0" />
                  <span className="max-w-[140px] truncate">{f.name}</span>
                  <button
                    type="button"
                    onClick={() => setPendingFiles((prev) => prev.filter((_, idx) => idx !== i))}
                    className="ml-0.5 text-muted-foreground hover:text-destructive"
                    aria-label={`Remove ${f.name}`}
                  >
                    <X className="h-3 w-3" />
                  </button>
                </div>
              ))}
            </div>
          )}

          {/* Lock price panel */}
          {lockEnabled && (
            <div className="rounded-md border border-border bg-muted/30 p-2 text-xs space-y-1.5">
              <div className="flex items-center gap-2">
                <label className="text-muted-foreground shrink-0">Lock price ($)</label>
                <input
                  type="number"
                  min="0.01"
                  step="0.01"
                  value={lockPrice}
                  onChange={(e) => setLockPrice(e.target.value)}
                  placeholder="e.g. 2.99"
                  className="flex-1 rounded border border-input bg-background px-2 py-1 text-xs"
                />
              </div>
              <p className="text-muted-foreground">Viewers must pay this amount to unlock the post.</p>
            </div>
          )}

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1">
              {/* Image attach from device */}
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

              {/* Image attach from file manager */}
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => setFilePickerOpen(true)}
                disabled={uploading || imageUrls.length >= MAX_IMAGES}
              >
                <FolderOpen className="mr-1 h-3.5 w-3.5" />
                From Files
              </Button>

              {/* Non-image file attach */}
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => setAttachFilePickerOpen(true)}
                disabled={uploading || pendingFiles.length >= MAX_FILES}
              >
                <Paperclip className="mr-1 h-3.5 w-3.5" />
                Attach File
                {pendingFiles.length > 0 && (
                  <span className="ml-1 text-xs text-muted-foreground">
                    ({pendingFiles.length}/{MAX_FILES})
                  </span>
                )}
              </Button>

              {/* Lock toggle */}
              <Button
                type="button"
                variant={lockEnabled ? "secondary" : "ghost"}
                size="sm"
                onClick={() => setLockEnabled((v) => !v)}
                disabled={mutation.isPending}
              >
                <Lock className="mr-1 h-3.5 w-3.5" />
                {lockEnabled ? `Lock · $${lockPrice || "0"}` : "Lock"}
              </Button>
            </div>

            <input
              ref={fileRef}
              type="file"
              accept="image/*"
              className="hidden"
              onChange={handleFileSelect}
            />

            <Button
              type="submit"
              size="sm"
              disabled={(!body.trim() && imageUrls.length === 0 && pendingFiles.length === 0) || mutation.isPending || uploading}
            >
              <Send className="mr-1 h-3.5 w-3.5" />
              {mutation.isPending ? "Posting..." : "Post"}
            </Button>
          </div>

          <FilePickerDialog
            open={filePickerOpen}
            onClose={() => setFilePickerOpen(false)}
            onSelect={(entry) => void handleFileManagerSelect(entry)}
            showPermission={false}
          />

          <FilePickerDialog
            open={attachFilePickerOpen}
            onClose={() => setAttachFilePickerOpen(false)}
            onSelect={handleAttachFileSelect}
            showPermission={false}
          />
        </form>
      </CardContent>
    </Card>
  );
}
