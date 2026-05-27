import { useState, useRef } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ImagePlus, Link2, Type, X, Loader2 } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { createStory, uploadStoryImage } from "@/api/endpoints/stories";
import type { CreateStoryReq } from "@/api/types";

interface StoryComposerProps {
  open: boolean;
  onClose: () => void;
}

export function StoryComposer({ open, onClose }: StoryComposerProps) {
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [mediaUrl, setMediaUrl] = useState<string>("");
  const [mediaType, setMediaType] = useState<"image" | "video">("image");
  const [textOverlay, setTextOverlay] = useState("");
  const [linkUrl, setLinkUrl] = useState("");
  const [linkLabel, setLinkLabel] = useState("");
  const [showLinkFields, setShowLinkFields] = useState(false);
  const [uploading, setUploading] = useState(false);

  const createMut = useMutation({
    mutationFn: (body: CreateStoryReq) => createStory(body),
    onSuccess: () => {
      toast.success("Story posted!");
      queryClient.invalidateQueries({ queryKey: ["stories", "bar"] });
      onClose();
    },
    onError: (err: any) => {
      const detail = err?.response?.data?.detail || err?.message || "Failed to create story";
      toast.error(String(detail));
    },
  });

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const isVideo = file.type.startsWith("video/");
    setMediaType(isVideo ? "video" : "image");

    // Preview
    const reader = new FileReader();
    reader.onload = () => setPreview(reader.result as string);
    reader.readAsDataURL(file);

    // Upload
    setUploading(true);
    try {
      const resp = await uploadStoryImage(file);
      setMediaUrl(resp.url);
    } catch (err: any) {
      toast.error("Failed to upload media");
      setPreview(null);
    } finally {
      setUploading(false);
    }
  };

  const handleSubmit = () => {
    if (!mediaUrl) {
      toast.error("Please select an image or video");
      return;
    }

    const body: CreateStoryReq = {
      media_type: mediaType,
      media_url: mediaUrl,
    };
    if (textOverlay.trim()) body.text_overlay = textOverlay.trim();
    if (linkUrl.trim()) body.link_url = linkUrl.trim();
    if (linkLabel.trim()) body.link_label = linkLabel.trim();

    createMut.mutate(body);
  };

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-md" data-testid="story-composer">
        <DialogHeader>
          <DialogTitle>Create Story</DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          {/* Media picker */}
          {!preview ? (
            <button
              onClick={() => fileInputRef.current?.click()}
              className="flex h-64 w-full items-center justify-center rounded-lg border-2 border-dashed border-muted-foreground/30 bg-muted/30 transition hover:border-primary/50 hover:bg-muted/50"
              data-testid="story-media-picker"
            >
              <div className="text-center">
                <ImagePlus className="mx-auto h-8 w-8 text-muted-foreground" />
                <p className="mt-2 text-sm text-muted-foreground">
                  Tap to select a photo or video
                </p>
              </div>
            </button>
          ) : (
            <div className="relative">
              {mediaType === "video" ? (
                <video
                  src={preview}
                  className="h-64 w-full rounded-lg object-cover"
                  controls
                />
              ) : (
                <img
                  src={preview}
                  alt="Story preview"
                  className="h-64 w-full rounded-lg object-cover"
                />
              )}
              {uploading && (
                <div className="absolute inset-0 flex items-center justify-center rounded-lg bg-black/50">
                  <Loader2 className="h-8 w-8 animate-spin text-white" />
                </div>
              )}
              <Button
                variant="ghost"
                size="icon"
                className="absolute right-2 top-2 bg-black/50 text-white hover:bg-black/70"
                onClick={() => {
                  setPreview(null);
                  setMediaUrl("");
                }}
              >
                <X className="h-4 w-4" />
              </Button>

              {/* Text overlay on preview */}
              {textOverlay && (
                <div className="absolute bottom-4 left-2 right-2 text-center">
                  <p className="rounded bg-black/50 px-2 py-1 text-sm text-white">
                    {textOverlay}
                  </p>
                </div>
              )}
            </div>
          )}

          <input
            ref={fileInputRef}
            type="file"
            accept="image/*,video/*"
            className="hidden"
            onChange={handleFileSelect}
          />

          {/* Text overlay */}
          <div>
            <Label htmlFor="text-overlay" className="flex items-center gap-1 text-sm">
              <Type className="h-3.5 w-3.5" />
              Text overlay (optional)
            </Label>
            <Textarea
              id="text-overlay"
              placeholder="Add text to your story..."
              maxLength={200}
              value={textOverlay}
              onChange={(e) => setTextOverlay(e.target.value)}
              className="mt-1"
              rows={2}
            />
            <p className="mt-1 text-xs text-muted-foreground">
              {textOverlay.length}/200
            </p>
          </div>

          {/* Link sticker toggle */}
          <div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowLinkFields(!showLinkFields)}
              className="flex items-center gap-1"
            >
              <Link2 className="h-3.5 w-3.5" />
              {showLinkFields ? "Remove link" : "Add link sticker"}
            </Button>

            {showLinkFields && (
              <div className="mt-2 space-y-2">
                <Input
                  placeholder="https://example.com"
                  value={linkUrl}
                  onChange={(e) => setLinkUrl(e.target.value)}
                />
                <Input
                  placeholder="Button label (e.g., Learn More)"
                  value={linkLabel}
                  onChange={(e) => setLinkLabel(e.target.value)}
                  maxLength={100}
                />
              </div>
            )}
          </div>

          {/* Submit */}
          <Button
            className="w-full"
            onClick={handleSubmit}
            disabled={!mediaUrl || uploading || createMut.isPending}
            data-testid="post-story-button"
          >
            {createMut.isPending ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Posting...
              </>
            ) : (
              "Post Story"
            )}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
