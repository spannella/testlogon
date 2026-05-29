import { Card, CardContent } from "@/components/ui/card";
import { Eye, Share2, Clock } from "lucide-react";
import type { BroadcastClip } from "@/api/types";

interface ClipCardProps {
  clip: BroadcastClip;
  onClick?: () => void;
}

export function ClipCard({ clip, onClick }: ClipCardProps) {
  return (
    <Card
      className="cursor-pointer hover:shadow-md transition-shadow overflow-hidden"
      onClick={onClick}
    >
      <div className="relative aspect-video bg-muted">
        {clip.thumbnail_url ? (
          <img src={clip.thumbnail_url} alt={clip.title} className="w-full h-full object-cover" />
        ) : (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            {clip.status === "processing" ? "Processing..." : "No thumbnail"}
          </div>
        )}
        <span className="absolute bottom-1 right-1 bg-black/70 text-white text-xs px-1 rounded">
          {clip.duration_seconds.toFixed(0)}s
        </span>
      </div>
      <CardContent className="p-3">
        <p className="text-sm font-medium line-clamp-1">{clip.title}</p>
        <p className="text-xs text-muted-foreground mt-0.5">
          by {clip.creator_display_name}
        </p>
        <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
          <span className="flex items-center gap-1">
            <Eye className="h-3 w-3" /> {clip.view_count}
          </span>
          <span className="flex items-center gap-1">
            <Share2 className="h-3 w-3" /> {clip.share_count}
          </span>
          <span className="flex items-center gap-1">
            <Clock className="h-3 w-3" /> {formatRelativeTime(clip.created_at)}
          </span>
        </div>
      </CardContent>
    </Card>
  );
}

function formatRelativeTime(ts: number): string {
  const diff = Math.floor(Date.now() / 1000) - ts;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}
