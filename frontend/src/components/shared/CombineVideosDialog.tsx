import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Layers,
  Loader2,
  ArrowUp,
  ArrowDown,
  X,
  Film,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { listMyVideos, type VideoListItem } from "@/api/endpoints/videos";
import { combineVideos } from "@/api/endpoints/combine";

interface CombineVideosDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

function formatDuration(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (h > 0) return `${h}:${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`;
  return `${m}:${s.toString().padStart(2, "0")}`;
}

export default function CombineVideosDialog({ open, onOpenChange }: CombineVideosDialogProps) {
  const queryClient = useQueryClient();
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");

  const { data: videoList } = useQuery({
    queryKey: ["vod", "videos", "for-combine"],
    queryFn: () => listMyVideos({ limit: 200 }),
    enabled: open,
  });

  const concatMutation = useMutation({
    mutationFn: combineVideos,
    onSuccess: () => {
      toast.success("Combine job started");
      queryClient.invalidateQueries({ queryKey: ["vod", "videos"] });
      onOpenChange(false);
      setSelectedIds([]);
      setTitle("");
      setDescription("");
    },
    onError: (err: any) => {
      const msg = err?.response?.data?.detail || err?.message || "Failed to combine videos";
      toast.error(msg);
    },
  });

  // Only show published/approved videos
  const publishedVideos = (videoList?.items ?? []).filter(
    (v) => v.status === "published" || v.status === "approved",
  );

  const selectedVideos = selectedIds
    .map((id) => publishedVideos.find((v) => v.video_id === id))
    .filter(Boolean) as VideoListItem[];

  const estimatedDuration = selectedVideos.reduce(
    (sum, v) => sum + (v.duration_seconds || 0),
    0,
  );

  const isValid =
    selectedIds.length >= 2 &&
    selectedIds.length <= 10 &&
    title.trim().length > 0 &&
    estimatedDuration <= 14400;

  const toggleVideo = (videoId: string) => {
    setSelectedIds((prev) =>
      prev.includes(videoId) ? prev.filter((id) => id !== videoId) : [...prev, videoId],
    );
  };

  const moveUp = (index: number) => {
    if (index <= 0) return;
    setSelectedIds((prev) => {
      const next = [...prev];
      const temp = next[index]!;
      next[index] = next[index - 1]!;
      next[index - 1] = temp;
      return next;
    });
  };

  const moveDown = (index: number) => {
    setSelectedIds((prev) => {
      if (index >= prev.length - 1) return prev;
      const next = [...prev];
      const temp = next[index]!;
      next[index] = next[index + 1]!;
      next[index + 1] = temp;
      return next;
    });
  };

  const removeFromOrder = (videoId: string) => {
    setSelectedIds((prev) => prev.filter((id) => id !== videoId));
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Combine Videos</DialogTitle>
          <DialogDescription>
            Select 2-10 published videos to combine into a single video. Use arrows to reorder.
          </DialogDescription>
        </DialogHeader>

        {/* Video selection */}
        <div className="space-y-2 max-h-48 overflow-y-auto border rounded-md p-2">
          {publishedVideos.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-4">
              No published videos available.
            </p>
          ) : (
            publishedVideos.map((video) => (
              <div
                key={video.video_id}
                className="flex items-center gap-3 p-2 rounded hover:bg-muted cursor-pointer"
                onClick={() => toggleVideo(video.video_id)}
              >
                <Checkbox
                  checked={selectedIds.includes(video.video_id)}
                  onCheckedChange={() => toggleVideo(video.video_id)}
                />
                <div className="flex h-8 w-12 items-center justify-center rounded bg-muted shrink-0">
                  {video.thumbnail_url ? (
                    <img
                      src={video.thumbnail_url}
                      className="h-full w-full object-cover rounded"
                      alt=""
                    />
                  ) : (
                    <Film className="h-4 w-4 text-muted-foreground" />
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{video.title}</p>
                  <p className="text-xs text-muted-foreground">
                    {formatDuration(video.duration_seconds || 0)}
                  </p>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Selected order */}
        {selectedIds.length >= 2 && (
          <div className="space-y-2">
            <Label>Combine Order</Label>
            <div className="space-y-1 border rounded-md p-2">
              {selectedIds.map((id, index) => {
                const v = publishedVideos.find((v) => v.video_id === id);
                if (!v) return null;
                return (
                  <div
                    key={id}
                    className="flex items-center gap-2 p-2 bg-muted rounded text-sm"
                  >
                    <span className="text-xs text-muted-foreground w-5 text-center shrink-0">
                      {index + 1}
                    </span>
                    <span className="flex-1 truncate">{v.title}</span>
                    <span className="text-xs text-muted-foreground shrink-0">
                      {formatDuration(v.duration_seconds || 0)}
                    </span>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-6 w-6"
                      disabled={index === 0}
                      onClick={() => moveUp(index)}
                    >
                      <ArrowUp className="h-3 w-3" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-6 w-6"
                      disabled={index === selectedIds.length - 1}
                      onClick={() => moveDown(index)}
                    >
                      <ArrowDown className="h-3 w-3" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-6 w-6"
                      onClick={() => removeFromOrder(id)}
                    >
                      <X className="h-3 w-3" />
                    </Button>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Title */}
        <div className="space-y-2">
          <Label htmlFor="combine-title">Title</Label>
          <Input
            id="combine-title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Combined video title"
            maxLength={256}
          />
        </div>

        {/* Description */}
        <div className="space-y-2">
          <Label htmlFor="combine-desc">Description (optional)</Label>
          <Textarea
            id="combine-desc"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Description"
            maxLength={2000}
            rows={2}
          />
        </div>

        {/* Estimated duration */}
        {selectedIds.length >= 2 && (
          <div className="text-sm text-muted-foreground">
            Estimated duration: {formatDuration(estimatedDuration)}
            {estimatedDuration > 14400 && (
              <span className="text-destructive ml-2">Exceeds 4-hour limit</span>
            )}
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={() =>
              concatMutation.mutate({
                source_video_ids: selectedIds,
                title,
                description: description || undefined,
              })
            }
            disabled={!isValid || concatMutation.isPending}
            className="gap-2"
          >
            {concatMutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Layers className="h-4 w-4" />
            )}
            Combine ({selectedIds.length} videos)
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
