import * as React from "react";
import { Video, Play } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { MediaPlayer } from "@/components/shared/MediaPlayer";

function formatDuration(secs: number): string {
  const m = Math.floor(secs / 60);
  const s = Math.floor(secs % 60);
  return m >= 60
    ? `${Math.floor(m / 60)}:${String(m % 60).padStart(2, "0")}:${String(s).padStart(2, "0")}`
    : `${m}:${String(s).padStart(2, "0")}`;
}

interface VideoShareCardProps {
  videoShare: {
    video_id: string;
    title: string;
    thumbnail_url?: string;
    duration_seconds?: number;
    width?: number;
    height?: number;
    hls_manifest_url?: string;
    playback_token?: string;
    playback_expires_at?: number;
    drm_enabled?: boolean;
  };
}

export function VideoShareCard({ videoShare }: VideoShareCardProps) {
  const [playing, setPlaying] = React.useState(false);

  const aspectRatio =
    videoShare.width && videoShare.height ? videoShare.width / videoShare.height : 16 / 9;
  const manifestUrl = videoShare.hls_manifest_url
    ? `${videoShare.hls_manifest_url}${videoShare.hls_manifest_url.includes("?") ? "&" : "?"}token=${videoShare.playback_token || ""}`
    : null;

  if (playing && manifestUrl) {
    return (
      <div className="rounded-lg overflow-hidden max-w-md" style={{ aspectRatio }}>
        <MediaPlayer
          src={manifestUrl}
          mode="vod"
          poster={videoShare.thumbnail_url}
          title={videoShare.title}
        />
      </div>
    );
  }

  return (
    <div
      className="relative rounded-lg overflow-hidden max-w-md cursor-pointer group"
      style={{ aspectRatio }}
      onClick={() => manifestUrl && setPlaying(true)}
      data-testid="video-share-card"
    >
      {videoShare.thumbnail_url ? (
        <img
          src={videoShare.thumbnail_url}
          alt={videoShare.title}
          className="w-full h-full object-cover"
        />
      ) : (
        <div className="w-full h-full bg-muted flex items-center justify-center">
          <Video className="h-12 w-12 text-muted-foreground" />
        </div>
      )}
      <div className="absolute inset-0 flex items-center justify-center bg-black/30 group-hover:bg-black/40 transition-colors">
        <div className="rounded-full bg-white/90 p-3">
          <Play className="h-6 w-6 text-black fill-black" />
        </div>
      </div>
      {videoShare.duration_seconds != null && (
        <Badge className="absolute bottom-2 right-2 bg-black/70 text-white text-xs">
          {formatDuration(videoShare.duration_seconds)}
        </Badge>
      )}
      <div className="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/60 to-transparent p-2 pt-6">
        <p className="text-white text-sm font-medium truncate">{videoShare.title}</p>
      </div>
      {!manifestUrl && (
        <div className="absolute top-2 left-2">
          <Badge variant="destructive" className="text-[10px]">
            Unavailable
          </Badge>
        </div>
      )}
    </div>
  );
}
