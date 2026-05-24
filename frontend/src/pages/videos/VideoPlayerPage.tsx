/**
 * Video Player Page (VOD-008)
 *
 * Renders an HLS adaptive bitrate video player with quality selection,
 * metadata display, share functionality, and comprehensive error states.
 */

import { useEffect, useRef, useState, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import Hls from "hls.js";
import {
  ArrowLeft,
  AlertCircle,
  Loader2,
  Share2,
  RefreshCw,
  Settings,
  Clock,
  Calendar,
  Video,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Badge } from "@/components/ui/badge";
import { getVideoDetail, type VideoDetail } from "@/api/endpoints/videos";

// ─── Types ──────────────────────────────────────────────────────────────────

type PlayerErrorType =
  | "not_found"
  | "forbidden"
  | "processing"
  | "expired"
  | "hls_error"
  | "unsupported";

interface PlayerError {
  type: PlayerErrorType;
  message: string;
}

interface QualityLevel {
  index: number;
  height: number;
  bitrate: number;
  label: string;
}

// ─── Quality Selector ───────────────────────────────────────────────────────

function QualitySelector({
  levels,
  currentLevel,
  onChange,
}: {
  levels: QualityLevel[];
  currentLevel: number;
  onChange: (level: number) => void;
}) {
  if (levels.length === 0) return null;

  const activeLabel =
    currentLevel === -1
      ? "Auto"
      : levels.find((l) => l.index === currentLevel)?.label ?? "Auto";

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className="absolute bottom-14 right-3 z-10 gap-1.5 bg-black/60 text-white hover:bg-black/80 hover:text-white text-xs px-2 py-1 h-7"
          data-testid="quality-selector"
        >
          <Settings className="h-3.5 w-3.5" />
          {activeLabel}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-[140px]">
        <DropdownMenuItem
          onClick={() => onChange(-1)}
          className={currentLevel === -1 ? "font-bold" : ""}
          data-testid="quality-auto"
        >
          <span className="flex items-center gap-2">
            {currentLevel === -1 && (
              <span className="h-2 w-2 rounded-full bg-green-500" />
            )}
            Auto
          </span>
        </DropdownMenuItem>
        {levels.map((level) => (
          <DropdownMenuItem
            key={level.index}
            onClick={() => onChange(level.index)}
            className={currentLevel === level.index ? "font-bold" : ""}
            data-testid={`quality-${level.label}`}
          >
            <span className="flex items-center gap-2">
              {currentLevel === level.index && (
                <span className="h-2 w-2 rounded-full bg-green-500" />
              )}
              {level.label}
            </span>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

// ─── HLS Player ─────────────────────────────────────────────────────────────

function HlsPlayer({
  src,
  autoplay = true,
  onError,
}: {
  src: string;
  autoplay?: boolean;
  onError: (error: PlayerError) => void;
}) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const hlsRef = useRef<Hls | null>(null);
  const [levels, setLevels] = useState<QualityLevel[]>([]);
  const [currentLevel, setCurrentLevel] = useState(-1);

  useEffect(() => {
    if (!videoRef.current || !src) return;

    if (Hls.isSupported()) {
      const hls = new Hls({ startLevel: -1 });
      hlsRef.current = hls;
      hls.loadSource(src);
      hls.attachMedia(videoRef.current);

      hls.on(Hls.Events.MANIFEST_PARSED, (_, data) => {
        const parsed: QualityLevel[] = data.levels.map((level, index) => ({
          index,
          height: level.height,
          bitrate: level.bitrate,
          label: level.height ? `${level.height}p` : `${Math.round(level.bitrate / 1000)}kbps`,
        }));
        setLevels(parsed);
        if (autoplay) {
          videoRef.current?.play().catch(() => {});
        }
      });

      hls.on(Hls.Events.LEVEL_SWITCHED, (_, data) => {
        setCurrentLevel(data.level);
      });

      hls.on(Hls.Events.ERROR, (_, data) => {
        if (!data.fatal) return;
        if (data.response && (data.response as { code?: number }).code === 403) {
          onError({
            type: "expired",
            message: "Playback session expired. Please refresh to continue watching.",
          });
        } else {
          onError({
            type: "hls_error",
            message: "A playback error occurred. Please try again.",
          });
        }
        hls.destroy();
      });

      return () => {
        hls.destroy();
        hlsRef.current = null;
      };
    } else if (
      videoRef.current.canPlayType("application/vnd.apple.mpegurl")
    ) {
      // Native HLS (Safari)
      videoRef.current.src = src;
      if (autoplay) {
        videoRef.current.play().catch(() => {});
      }
    } else {
      onError({
        type: "unsupported",
        message: "Your browser does not support video playback.",
      });
    }
  }, [src, autoplay, onError]);

  const setQuality = useCallback((level: number) => {
    if (hlsRef.current) {
      hlsRef.current.currentLevel = level;
      setCurrentLevel(level);
    }
  }, []);

  return (
    <div className="relative aspect-video bg-black rounded-lg overflow-hidden" data-testid="video-player-container">
      <video
        ref={videoRef}
        className="w-full h-full"
        controls
        playsInline
        data-testid="video-element"
      />
      <QualitySelector
        levels={levels}
        currentLevel={currentLevel}
        onChange={setQuality}
      />
    </div>
  );
}

// ─── Error Display ──────────────────────────────────────────────────────────

function ErrorDisplay({
  error,
  onRetry,
}: {
  error: PlayerError;
  onRetry?: () => void;
}) {
  return (
    <div
      className="aspect-video bg-muted/30 rounded-lg flex items-center justify-center"
      data-testid="video-error"
    >
      <div className="text-center space-y-4 max-w-sm px-4">
        <AlertCircle className="h-12 w-12 text-destructive mx-auto" />
        <p className="text-lg font-medium" data-testid="error-message">
          {error.message}
        </p>
        {onRetry && (
          <Button variant="outline" onClick={onRetry} className="gap-2">
            <RefreshCw className="h-4 w-4" />
            Retry
          </Button>
        )}
      </div>
    </div>
  );
}

// ─── Processing State ───────────────────────────────────────────────────────

function ProcessingState() {
  return (
    <div
      className="aspect-video bg-muted/30 rounded-lg flex items-center justify-center"
      data-testid="video-processing"
    >
      <div className="text-center space-y-4">
        <Loader2 className="h-10 w-10 animate-spin text-muted-foreground mx-auto" />
        <p className="text-muted-foreground font-medium">
          Video is being processed...
        </p>
        <p className="text-sm text-muted-foreground/70">
          This may take a few minutes depending on the video length.
        </p>
      </div>
    </div>
  );
}

// ─── Format Helpers ─────────────────────────────────────────────────────────

function formatDuration(seconds: number | null | undefined): string {
  if (!seconds) return "";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (h > 0) {
    return `${h}:${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`;
  }
  return `${m}:${s.toString().padStart(2, "0")}`;
}

function formatDate(timestamp: number): string {
  if (!timestamp) return "";
  return new Date(timestamp * 1000).toLocaleDateString(undefined, {
    year: "numeric",
    month: "long",
    day: "numeric",
  });
}

// ─── Main Page Component ────────────────────────────────────────────────────

export default function VideoPlayerPage() {
  const { videoId } = useParams<{ videoId: string }>();
  const navigate = useNavigate();
  const [playerError, setPlayerError] = useState<PlayerError | null>(null);
  const [copied, setCopied] = useState(false);

  const {
    data: video,
    isLoading,
    error: fetchError,
    refetch,
  } = useQuery<VideoDetail>({
    queryKey: ["video", videoId],
    queryFn: () => getVideoDetail(videoId!),
    enabled: !!videoId,
    retry: false,
  });

  // Derive fetch-level error (404, 403) — these hide everything
  const fetchLevelError: PlayerError | null = (() => {
    if (!fetchError) return null;

    const err = fetchError as { status?: number };
    const status = err.status;
    if (status === 404) {
      return { type: "not_found" as const, message: "Video not found" };
    }
    if (status === 403) {
      return {
        type: "forbidden" as const,
        message: "You don't have access to this video",
      };
    }
    return { type: "hls_error" as const, message: "Failed to load video" };
  })();

  // Determine if video is still processing
  const isProcessing =
    video &&
    ["created", "probing", "pending_encoding", "encoding"].includes(
      video.status
    );

  // Build playback URL
  const playbackUrl =
    video?.hls_manifest_url && video?.playback_token
      ? `${video.hls_manifest_url}?token=${video.playback_token}`
      : null;

  const handleHlsError = useCallback((error: PlayerError) => {
    setPlayerError(error);
  }, []);

  const handleRetry = useCallback(() => {
    setPlayerError(null);
    refetch();
  }, [refetch]);

  const handleShare = useCallback(async () => {
    const url = `${window.location.origin}/videos/${videoId}`;
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback for non-HTTPS or no clipboard API
      const input = document.createElement("input");
      input.value = url;
      document.body.appendChild(input);
      input.select();
      document.execCommand("copy");
      document.body.removeChild(input);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, [videoId]);

  // ─── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="container max-w-5xl mx-auto py-6 px-4 space-y-6">
      {/* Back navigation */}
      <div>
        <Button
          variant="ghost"
          size="sm"
          className="gap-2 -ml-2"
          onClick={() => navigate("/videos")}
          data-testid="back-to-videos"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Videos
        </Button>
      </div>

      {/* Loading state */}
      {isLoading && (
        <div className="aspect-video bg-muted/30 rounded-lg flex items-center justify-center">
          <Loader2 className="h-10 w-10 animate-spin text-muted-foreground" />
        </div>
      )}

      {/* Fetch-level error (404, 403) — hides everything */}
      {fetchLevelError && !isLoading && (
        <ErrorDisplay error={fetchLevelError} onRetry={handleRetry} />
      )}

      {/* Processing state */}
      {isProcessing && !fetchLevelError && <ProcessingState />}

      {/* Player area — only shown when video loaded and not processing */}
      {video && !isProcessing && !fetchLevelError && (
        <>
          {/* HLS player error (stream failed, expired token, etc.) */}
          {playerError && (
            <ErrorDisplay error={playerError} onRetry={handleRetry} />
          )}

          {/* Active player */}
          {!playerError && playbackUrl && (
            <HlsPlayer
              src={playbackUrl}
              autoplay={true}
              onError={handleHlsError}
            />
          )}

          {/* Video with manifest but no playback token (approved but token failure) */}
          {!playerError && !playbackUrl && video.hls_manifest_url && (
            <ErrorDisplay
              error={{
                type: "expired",
                message:
                  "Playback session expired. Please refresh to continue watching.",
              }}
              onRetry={handleRetry}
            />
          )}
        </>
      )}

      {/* Metadata — always shown when video data is loaded, regardless of player errors */}
      {video && !fetchLevelError && (
        <Card>
          <CardContent className="pt-6 space-y-4">
            {/* Title row */}
            <div className="flex items-start justify-between gap-4">
              <div className="space-y-1 min-w-0">
                <h1
                  className="text-2xl font-bold truncate"
                  data-testid="video-title"
                >
                  {video.title}
                </h1>
                {video.description && (
                  <p
                    className="text-muted-foreground"
                    data-testid="video-description"
                  >
                    {video.description}
                  </p>
                )}
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <Button
                  variant="outline"
                  size="sm"
                  className="gap-2"
                  onClick={handleShare}
                  data-testid="share-button"
                >
                  <Share2 className="h-4 w-4" />
                  {copied ? "Copied!" : "Share"}
                </Button>
              </div>
            </div>

            {/* Metadata badges */}
            <div className="flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
              {video.created_at > 0 && (
                <span className="flex items-center gap-1.5" data-testid="video-upload-date">
                  <Calendar className="h-3.5 w-3.5" />
                  Uploaded on {formatDate(video.created_at)}
                </span>
              )}
              {video.duration_seconds != null && video.duration_seconds > 0 && (
                <span className="flex items-center gap-1.5" data-testid="video-duration">
                  <Clock className="h-3.5 w-3.5" />
                  {formatDuration(video.duration_seconds)}
                </span>
              )}
              {video.width && video.height && (
                <span className="flex items-center gap-1.5" data-testid="video-resolution">
                  <Video className="h-3.5 w-3.5" />
                  {video.width}x{video.height}
                </span>
              )}
              {video.status && (
                <Badge
                  variant={video.status === "published" ? "default" : "secondary"}
                  data-testid="video-status-badge"
                >
                  {video.status}
                </Badge>
              )}
              {video.visibility && (
                <Badge variant="outline" data-testid="video-visibility-badge">
                  {video.visibility}
                </Badge>
              )}
            </div>

            {/* Renditions info */}
            {video.renditions && video.renditions.length > 0 && (
              <div className="pt-2 border-t" data-testid="video-renditions">
                <p className="text-xs text-muted-foreground mb-1.5">
                  Available quality:
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {(video.renditions as Array<{ label?: string; height?: number; bitrate_kbps?: number }>).map(
                    (r, i) => (
                      <Badge key={i} variant="secondary" className="text-xs">
                        {r.label || (r.height ? `${r.height}p` : "Unknown")}
                      </Badge>
                    )
                  )}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
