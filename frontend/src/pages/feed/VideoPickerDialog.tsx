import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Search, Video, Loader2 } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { listMyVideos, type VideoListItem } from "@/api/endpoints/videos";

function formatDuration(secs: number): string {
  const m = Math.floor(secs / 60);
  const s = Math.floor(secs % 60);
  return m >= 60
    ? `${Math.floor(m / 60)}:${String(m % 60).padStart(2, "0")}:${String(s).padStart(2, "0")}`
    : `${m}:${String(s).padStart(2, "0")}`;
}

interface FeedVideoPickerDialogProps {
  open: boolean;
  onClose: () => void;
  onSelect: (video: VideoListItem) => void;
}

export function FeedVideoPickerDialog({ open, onClose, onSelect }: FeedVideoPickerDialogProps) {
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<VideoListItem | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["my-videos", "feed-picker"],
    queryFn: () => listMyVideos({ status: "published" }),
    enabled: open,
  });

  const filtered = useMemo(() => {
    const items = data?.items ?? [];
    if (!search.trim()) return items;
    const q = search.toLowerCase();
    return items.filter((v) => v.title.toLowerCase().includes(q));
  }, [data, search]);

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-lg max-h-[80vh] flex flex-col">
        <DialogHeader>
          <DialogTitle>Attach a Video</DialogTitle>
        </DialogHeader>
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search videos..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <ScrollArea className="flex-1 min-h-0 max-h-[50vh]">
          {isLoading && (
            <div className="flex justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
          )}
          {!isLoading &&
            filtered.map((video) => (
              <button
                key={video.video_id}
                type="button"
                className={`w-full flex items-center gap-3 p-2 rounded-md text-left hover:bg-accent transition-colors ${
                  selected?.video_id === video.video_id
                    ? "bg-accent ring-2 ring-primary"
                    : ""
                }`}
                onClick={() => setSelected(video)}
              >
                {video.thumbnail_url ? (
                  <img
                    src={video.thumbnail_url}
                    alt=""
                    className="h-10 w-16 object-cover rounded flex-shrink-0"
                  />
                ) : (
                  <div className="h-10 w-16 bg-muted rounded flex items-center justify-center flex-shrink-0">
                    <Video className="h-5 w-5 text-muted-foreground" />
                  </div>
                )}
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{video.title}</p>
                  {video.duration_seconds != null && (
                    <span className="text-xs text-muted-foreground">
                      {formatDuration(video.duration_seconds)}
                    </span>
                  )}
                </div>
              </button>
            ))}
          {!isLoading && filtered.length === 0 && (
            <p className="text-center text-muted-foreground py-8">
              No published videos. Upload and publish a video first.
            </p>
          )}
        </ScrollArea>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            disabled={!selected}
            onClick={() => {
              if (selected) {
                onSelect(selected);
                onClose();
              }
            }}
          >
            Attach Video
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
