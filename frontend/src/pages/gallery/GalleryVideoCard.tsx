import { Link } from "react-router-dom";
import { Eye, Heart, MessageCircle, DollarSign } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { GalleryVideoItem } from "@/api/endpoints/gallery";

function formatDuration(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (h > 0) return `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  return `${m}:${String(s).padStart(2, "0")}`;
}

function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

interface Props {
  video: GalleryVideoItem;
}

export default function GalleryVideoCard({ video }: Props) {
  return (
    <Link to={`/gallery/${video.video_id}`} className="block group">
      <Card className="overflow-hidden transition-shadow hover:shadow-lg">
        {/* Thumbnail */}
        <div className="relative aspect-video bg-muted">
          {video.thumbnail_url ? (
            <img
              src={video.thumbnail_url}
              alt={video.title}
              className="h-full w-full object-cover"
            />
          ) : (
            <div className="flex h-full w-full items-center justify-center text-muted-foreground text-sm">
              No thumbnail
            </div>
          )}
          {/* Duration badge */}
          {video.duration_seconds != null && video.duration_seconds > 0 && (
            <span className="absolute bottom-1 right-1 rounded bg-black/75 px-1.5 py-0.5 text-xs font-medium text-white">
              {formatDuration(video.duration_seconds)}
            </span>
          )}
          {/* PPV badge */}
          {video.price_cents != null && video.price_cents > 0 && (
            <Badge variant="secondary" className="absolute top-1 right-1 gap-0.5">
              <DollarSign className="h-3 w-3" />
              {(video.price_cents / 100).toFixed(2)}
            </Badge>
          )}
        </div>

        <CardContent className="p-3">
          {/* Title */}
          <h3 className="text-sm font-semibold line-clamp-2 group-hover:text-primary transition-colors">
            {video.title}
          </h3>

          {/* Category */}
          {video.category && (
            <p className="mt-1 text-xs text-muted-foreground capitalize">{video.category}</p>
          )}

          {/* Stats */}
          <div className="mt-2 flex items-center gap-3 text-xs text-muted-foreground">
            <span className="inline-flex items-center gap-1">
              <Eye className="h-3 w-3" />
              {formatCount(video.view_count)}
            </span>
            <span className="inline-flex items-center gap-1">
              <Heart className="h-3 w-3" />
              {formatCount(video.like_count)}
            </span>
            <span className="inline-flex items-center gap-1">
              <MessageCircle className="h-3 w-3" />
              {formatCount(video.comment_count)}
            </span>
          </div>

          {/* Tags (up to 3) */}
          {video.tags.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1">
              {video.tags.slice(0, 3).map((tag) => (
                <Badge key={tag} variant="outline" className="text-[10px] px-1.5 py-0">
                  {tag}
                </Badge>
              ))}
              {video.tags.length > 3 && (
                <span className="text-[10px] text-muted-foreground">+{video.tags.length - 3}</span>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </Link>
  );
}
