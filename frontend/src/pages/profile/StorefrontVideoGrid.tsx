import { useQuery } from "@tanstack/react-query";
import { Play, Sparkles } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { Skeleton } from "@/components/ui/skeleton";
import { listCreatorVideos } from "@/api/endpoints/videos";

interface StorefrontVideoGridProps {
  creatorId: string;
}

function formatDuration(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}:${s.toString().padStart(2, "0")}`;
}

export function StorefrontVideoGrid({ creatorId }: StorefrontVideoGridProps) {
  const navigate = useNavigate();

  const { data, isLoading } = useQuery({
    queryKey: ["creator-videos", creatorId],
    queryFn: () => listCreatorVideos(creatorId, { limit: 12 }),
    enabled: !!creatorId,
    staleTime: 120_000,
  });

  if (isLoading) {
    return (
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="aspect-video w-full rounded-lg" />
        ))}
      </div>
    );
  }

  const videos = data?.items ?? [];

  if (videos.length === 0) {
    return (
      <div className="flex flex-col items-center gap-2 py-12 text-center text-muted-foreground" data-testid="videos-empty">
        <Sparkles className="h-8 w-8" />
        <p className="text-sm">No videos yet</p>
      </div>
    );
  }

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {videos.map((video) => (
        <button
          key={video.video_id}
          onClick={() => navigate(`/videos/${video.video_id}`)}
          className="group relative overflow-hidden rounded-lg border bg-card text-left transition hover:shadow-md"
          data-testid="video-card"
        >
          <div className="relative aspect-video bg-muted">
            {video.thumbnail_url ? (
              <img
                src={video.thumbnail_url}
                alt={video.title}
                className="h-full w-full object-cover"
                loading="lazy"
              />
            ) : (
              <div className="flex h-full items-center justify-center">
                <Play className="h-8 w-8 text-muted-foreground" />
              </div>
            )}
            {video.duration_seconds != null && (
              <span className="absolute bottom-1 right-1 rounded bg-black/70 px-1.5 py-0.5 text-xs text-white">
                {formatDuration(video.duration_seconds)}
              </span>
            )}
          </div>
          <div className="p-2">
            <p className="line-clamp-2 text-sm font-medium">{video.title}</p>
          </div>
        </button>
      ))}
    </div>
  );
}
