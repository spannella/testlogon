import { useQuery } from "@tanstack/react-query";
import { Loader2, Video } from "lucide-react";
import { cn } from "@/lib/utils";
import { MediaPlayer } from "@/components/shared/MediaPlayer";
import { issueVideoPostEntitlement } from "@/api/endpoints/newsfeed";

function formatDuration(secs: number): string {
  const m = Math.floor(secs / 60);
  const s = Math.floor(secs % 60);
  return m >= 60
    ? `${Math.floor(m / 60)}:${String(m % 60).padStart(2, "0")}:${String(s).padStart(2, "0")}`
    : `${m}:${String(s).padStart(2, "0")}`;
}

interface PostVideoEmbed {
  video_id: string;
  title: string;
  thumbnail_url?: string | null;
  duration_seconds?: number | null;
  hls_manifest_url?: string | null;
}

interface VideoPostPlayerProps {
  postId: string;
  video: PostVideoEmbed;
  className?: string;
}

export function VideoPostPlayer({ postId, video, className }: VideoPostPlayerProps) {
  const { data: entitlement, isLoading } = useQuery({
    queryKey: ["video-post-entitlement", postId],
    queryFn: () => issueVideoPostEntitlement(postId),
    staleTime: 4 * 60 * 1000,
    enabled: !!video.hls_manifest_url,
  });

  if (!video.hls_manifest_url) {
    return (
      <div
        className={cn(
          "aspect-video bg-muted rounded-lg flex flex-col items-center justify-center gap-2",
          className,
        )}
      >
        <Video className="h-8 w-8 text-muted-foreground" />
        <p className="text-sm text-muted-foreground">Video unavailable</p>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div
        className={cn(
          "aspect-video bg-muted rounded-lg flex items-center justify-center",
          className,
        )}
      >
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    );
  }

  const manifestUrl = entitlement?.hls_manifest_url ?? video.hls_manifest_url;

  return (
    <div className={className}>
      <MediaPlayer
        src={manifestUrl}
        mode="vod"
        poster={video.thumbnail_url ?? undefined}
        title={video.title}
      />
      {video.title && (
        <p className="mt-1 text-sm font-medium text-muted-foreground truncate">{video.title}</p>
      )}
      {video.duration_seconds != null && (
        <p className="text-xs text-muted-foreground">{formatDuration(video.duration_seconds)}</p>
      )}
    </div>
  );
}
