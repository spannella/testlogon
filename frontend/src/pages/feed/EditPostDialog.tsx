import { useState, useEffect, useRef } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ImagePlus, Loader2, X, Clock, Globe } from "lucide-react";
import { toast } from "sonner";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { newsfeedSchedulingUiEnabled } from "@/lib/featureFlags";
import { MarkdownComposer, type EditorMode, type RichDoc, richDocToPlain, buildContentPayload } from "./MarkdownComposer";
import { editPost, editScheduledPost, uploadPostImage } from "@/api/endpoints/newsfeed";

const MAX_IMAGES = 10;

interface EditPostDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  postId: string;
  postStatus?: "scheduled" | "published" | "cancelled";
  initialPublishAt?: number;
  initialScheduleTimezone?: string;
  initialScheduledAtLocal?: string;
  initialBody: string;
  initialImageUrls?: string[];
  initialBodyRich?: RichDoc | null;
}

export function EditPostDialog({
  open,
  onOpenChange,
  postId,
  postStatus,
  initialPublishAt,
  initialScheduleTimezone,
  initialScheduledAtLocal,
  initialBody,
  initialImageUrls,
  initialBodyRich,
}: EditPostDialogProps) {
  const schedulingUiEnabled = newsfeedSchedulingUiEnabled;
  const queryClient = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const [body, setBody] = useState(initialBody);
  const [editorMode, setEditorMode] = useState<EditorMode>(initialBodyRich ? "rich" : "plain");
  const [richDoc, setRichDoc] = useState<RichDoc | null>(initialBodyRich ?? null);
  const [imageUrls, setImageUrls] = useState<string[]>(initialImageUrls ?? []);
  const [uploading, setUploading] = useState(false);
  const [scheduleTimezone, setScheduleTimezone] = useState(initialScheduleTimezone ?? "UTC");
  const [scheduledInput, setScheduledInput] = useState(initialScheduledAtLocal ?? "");
  const [scheduledAt, setScheduledAt] = useState<Date | null>(initialPublishAt ? new Date(initialPublishAt * 1000) : null);

  const parseDateTimeInTz = (localStr: string, tz: string): Date => {
    const [datePart, timePart] = localStr.split("T");
    const [y, m, d] = (datePart || "").split("-").map(Number);
    const [hh, mm] = (timePart || "").split(":").map(Number);
    const utcGuess = new Date(Date.UTC(y, (m || 1) - 1, d || 1, hh || 0, mm || 0, 0));
    const parts = new Intl.DateTimeFormat("en-US", {
      timeZone: tz,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }).formatToParts(utcGuess);
    const get = (type: string) => Number(parts.find((p) => p.type === type)?.value ?? "0");
    const tzAsUtc = Date.UTC(get("year"), get("month") - 1, get("day"), get("hour"), get("minute"), 0);
    const targetAsUtc = Date.UTC(y, (m || 1) - 1, d || 1, hh || 0, mm || 0, 0);
    return new Date(utcGuess.getTime() + (targetAsUtc - tzAsUtc));
  };

  // Sync with props when dialog opens
  useEffect(() => {
    if (open) {
      setBody(initialBodyRich ? richDocToPlain(initialBodyRich) || initialBody : initialBody);
      setImageUrls(initialImageUrls ?? []);
      setEditorMode(initialBodyRich ? "rich" : "plain");
      setRichDoc(initialBodyRich ?? null);
      setScheduleTimezone(initialScheduleTimezone ?? (Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC"));
      setScheduledInput(initialScheduledAtLocal ?? "");
      setScheduledAt(initialPublishAt ? new Date(initialPublishAt * 1000) : null);
    }
  }, [open, initialBody, initialImageUrls, initialBodyRich, initialPublishAt, initialScheduleTimezone, initialScheduledAtLocal]);

  const mutation = useMutation({
    mutationFn: () =>
      (postStatus === "scheduled" && schedulingUiEnabled ? editScheduledPost : editPost)(postId, {
        ...buildContentPayload(body, editorMode, richDoc),
        image_urls: imageUrls,
        ...(postStatus === "scheduled" && schedulingUiEnabled && scheduledAt
          ? {
              publish_at: Math.floor(scheduledAt.getTime() / 1000),
              schedule_timezone: scheduleTimezone,
              scheduled_at_local: scheduledInput || undefined,
            }
          : {}),
      }),
    onSuccess: () => {
      toast.success("Post updated");
      void queryClient.invalidateQueries({ queryKey: ["feed"] });
      if (schedulingUiEnabled) {
        void queryClient.invalidateQueries({ queryKey: ["scheduled-posts"] });
      }
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

        {postStatus === "scheduled" && schedulingUiEnabled && (
          <div className="rounded-md border border-border/60 bg-muted/20 p-2.5">
            <p className="mb-2 flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
              <Clock className="h-3.5 w-3.5" />
              Scheduled publish
            </p>
            <div className="space-y-2">
              <input
                type="datetime-local"
                value={scheduledInput}
                className="w-full rounded border border-input bg-background px-2 py-1.5 text-xs"
                onChange={(e) => {
                  const val = e.target.value;
                  setScheduledInput(val);
                  if (val) {
                    setScheduledAt(parseDateTimeInTz(val, scheduleTimezone));
                  } else {
                    setScheduledAt(null);
                  }
                }}
              />
              <div className="flex items-center gap-1.5">
                <Globe className="h-3.5 w-3.5 text-muted-foreground" />
                <input
                  type="text"
                  value={scheduleTimezone}
                  onChange={(e) => {
                    const tz = e.target.value;
                    setScheduleTimezone(tz);
                    if (scheduledInput) setScheduledAt(parseDateTimeInTz(scheduledInput, tz));
                  }}
                  className="w-full rounded border border-input bg-background px-2 py-1.5 text-xs"
                  placeholder="Timezone (e.g. America/New_York)"
                />
              </div>
              {scheduledAt && (
                <p className="text-[11px] text-muted-foreground">
                  Publishes: {scheduledAt.toLocaleString(undefined, { timeZoneName: "short" })}
                </p>
              )}
            </div>
          </div>
        )}

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
