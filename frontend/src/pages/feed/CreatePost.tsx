import { useState, useRef } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Send, ImagePlus, X, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent } from "@/components/ui/card";
import { createPost, presignUpload } from "@/api/endpoints/newsfeed";

export function CreatePost() {
  const queryClient = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const [body, setBody] = useState("");
  const [imageUrl, setImageUrl] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);

  const mutation = useMutation({
    mutationFn: () =>
      createPost({
        body,
        ...(imageUrl ? { image_url: imageUrl } : {}),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["feed"] });
      setBody("");
      setImageUrl(null);
      toast.success("Post published");
    },
    onError: () => {
      toast.error("Failed to create post");
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!body.trim() && !imageUrl) return;
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
    setUploadProgress(0);

    try {
      // 1. Get presigned URL
      const presign = await presignUpload({
        filename: file.name,
        content_type: file.type,
      });

      setUploadProgress(30);

      // 2. Upload to S3 via PUT
      const headers: Record<string, string> = {
        "Content-Type": file.type,
        ...presign.put_headers,
      };

      const uploadResp = await fetch(presign.put_url, {
        method: "PUT",
        headers,
        body: file,
      });

      if (!uploadResp.ok) {
        throw new Error("Upload failed");
      }

      setUploadProgress(100);

      // 3. Use the public URL from the attachment, or derive from put_url
      const publicUrl = presign.attachment.url ?? presign.put_url.split("?")[0];
      setImageUrl(publicUrl ?? null);
      toast.success("Image uploaded");
    } catch {
      toast.error("Failed to upload image");
      setImageUrl(null);
    } finally {
      setUploading(false);
      setUploadProgress(0);
    }
  };

  const removeImage = () => {
    setImageUrl(null);
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

          {/* Image preview */}
          {imageUrl && !uploading && (
            <div className="relative inline-block">
              <img
                src={imageUrl}
                alt="Attachment preview"
                className="h-24 w-24 rounded-lg object-cover"
              />
              <button
                type="button"
                onClick={removeImage}
                className="absolute -right-1.5 -top-1.5 flex h-5 w-5 items-center justify-center rounded-full bg-destructive text-destructive-foreground shadow-sm"
              >
                <X className="h-3 w-3" />
              </button>
            </div>
          )}

          <div className="flex items-center justify-between">
            {/* Image attach button */}
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => fileRef.current?.click()}
              disabled={uploading || !!imageUrl}
            >
              <ImagePlus className="mr-1 h-3.5 w-3.5" />
              Photo
            </Button>

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
              disabled={(!body.trim() && !imageUrl) || mutation.isPending || uploading}
            >
              <Send className="mr-1 h-3.5 w-3.5" />
              {mutation.isPending ? "Posting..." : "Post"}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
