/**
 * Video Player Page (VOD-008)
 *
 * Renders an HLS adaptive bitrate video player with quality selection,
 * metadata display, share functionality, and comprehensive error states.
 */

import { useState, useCallback, useRef, useEffect } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import {
  ArrowLeft,
  AlertCircle,
  Loader2,
  Share2,
  RefreshCw,
  Clock,
  Calendar,
  Download,
  Scissors,
  Video,
  Trash2,
  Upload,
  Lock,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Separator } from "@/components/ui/separator";
import { MediaPlayer, type MediaError, type SubtitleTrackInfo } from "@/components/shared/MediaPlayer";
import { getVideoDetail, getVideoDownload, type VideoDetail } from "@/api/endpoints/videos";
import { listSubtitles, uploadSubtitle, deleteSubtitle } from "@/api/endpoints/subtitles";
import { recordEngagement } from "@/api/endpoints/recommendations";
import ClipDialog from "@/components/shared/ClipDialog";
import VodWatermarkDownloadButton from "./VodWatermarkDownloadButton";
import { useAuthStore } from "@/stores/authStore";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import type { SubtitleTrack } from "@/api/types";

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

// ─── MON-005: Subscription-Gated Access Components ─────────────────────

function SubscribeCTA({
  creatorId,
  message,
  variant = "default",
}: {
  creatorId: string;
  message: string;
  variant?: "default" | "outline";
}) {
  return (
    <Card data-testid="subscribe-cta">
      <CardContent className="text-center py-8">
        <Lock className="h-8 w-8 mx-auto mb-3 text-muted-foreground" />
        <p className="text-lg mb-4" data-testid="subscribe-message">
          {message}
        </p>
        <Button variant={variant} asChild data-testid="view-plans-link">
          <Link to={`/subscriptions?creator=${creatorId}`}>View Plans</Link>
        </Button>
      </CardContent>
    </Card>
  );
}

function VideoPriceBadge({
  priceCents,
  accessMode,
  entitled,
  accessReason,
}: {
  priceCents?: number | null;
  accessMode?: string | null;
  entitled?: boolean;
  accessReason?: string;
}) {
  if (entitled) {
    if (accessReason === "owner") return null;
    if (accessReason === "subscription")
      return (
        <Badge variant="default" data-testid="badge-included">
          Included
        </Badge>
      );
    if (accessReason === "purchased")
      return (
        <Badge variant="secondary" data-testid="badge-purchased">
          Purchased
        </Badge>
      );
    return (
      <Badge variant="secondary" data-testid="badge-free">
        Free
      </Badge>
    );
  }

  if (accessMode === "subscriber_only") {
    return (
      <Badge variant="secondary" data-testid="badge-subscribers-only">
        Subscribers Only
      </Badge>
    );
  }

  const priceStr = priceCents ? `$${(priceCents / 100).toFixed(2)}` : "Free";

  if (accessMode === "subscriber_free") {
    return (
      <div className="flex items-center gap-1.5">
        <Badge variant="outline" data-testid="badge-price">
          {priceStr}
        </Badge>
        <span className="text-xs text-muted-foreground">or subscribe</span>
      </div>
    );
  }

  return (
    <Badge variant="outline" data-testid="badge-price">
      {priceStr}
    </Badge>
  );
}

function VideoAccessGate({
  video,
}: {
  video: VideoDetail;
}) {
  // If entitled, show nothing (player is shown separately)
  if (video.is_entitled) return null;

  // Subscriber-only: only show subscribe CTA
  if (video.access_mode === "subscriber_only") {
    return (
      <SubscribeCTA
        creatorId={video.owner_user_id}
        message="Subscribe to watch this video"
      />
    );
  }

  // Subscriber-free with upsell: show purchase + subscribe option
  if (video.subscription_upsell) {
    return (
      <div className="space-y-4" data-testid="access-gate-upsell">
        <Card>
          <CardContent className="text-center py-8">
            <Lock className="h-8 w-8 mx-auto mb-3 text-muted-foreground" />
            <p className="text-lg mb-2">Purchase this video</p>
            {video.price_cents != null && video.price_cents > 0 && (
              <p className="text-2xl font-bold mb-4" data-testid="purchase-price">
                ${(video.price_cents / 100).toFixed(2)}
              </p>
            )}
            <Button data-testid="purchase-button">Purchase</Button>
          </CardContent>
        </Card>
        <Separator />
        <SubscribeCTA
          creatorId={video.owner_user_id}
          message="Or subscribe for free access to all videos"
          variant="outline"
        />
      </div>
    );
  }

  // PPV: only show purchase option
  if (video.access_mode === "ppv" || video.purchase_available) {
    return (
      <Card data-testid="access-gate-ppv">
        <CardContent className="text-center py-8">
          <Lock className="h-8 w-8 mx-auto mb-3 text-muted-foreground" />
          <p className="text-lg mb-2">Purchase this video</p>
          {video.price_cents != null && video.price_cents > 0 && (
            <p className="text-2xl font-bold mb-4" data-testid="purchase-price">
              ${(video.price_cents / 100).toFixed(2)}
            </p>
          )}
          <Button data-testid="purchase-button">Purchase</Button>
        </CardContent>
      </Card>
    );
  }

  return null;
}

// ─── Main Page Component ────────────────────────────────────────────────────

export default function VideoPlayerPage() {
  const { videoId } = useParams<{ videoId: string }>();
  const navigate = useNavigate();
  const [playerError, setPlayerError] = useState<PlayerError | null>(null);
  const [copied, setCopied] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);
  const [clipDialogOpen, setClipDialogOpen] = useState(false);
  const currentUserId = useAuthStore((s) => s.userId);

  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [subtitleLang, setSubtitleLang] = useState("en");
  const [subtitleLabel, setSubtitleLabel] = useState("English");
  const [subtitleDefault, setSubtitleDefault] = useState(false);

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

  const { data: subtitleData } = useQuery({
    queryKey: ["subtitles", videoId],
    queryFn: () => listSubtitles(videoId!),
    enabled: !!videoId,
  });

  const subtitleTracksForPlayer: SubtitleTrackInfo[] = (subtitleData?.tracks || []).map((t: SubtitleTrack) => ({
    track_id: t.track_id,
    language: t.language,
    label: t.label,
    vtt_url: t.vtt_url,
    is_default: t.is_default,
  }));

  const uploadMut = useMutation({
    mutationFn: (fd: FormData) => uploadSubtitle(videoId!, fd),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["subtitles", videoId] });
      if (fileInputRef.current) fileInputRef.current.value = "";
    },
  });

  const deleteMut = useMutation({
    mutationFn: (trackId: string) => deleteSubtitle(videoId!, trackId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["subtitles", videoId] });
    },
  });

  const handleSubtitleUpload = useCallback(() => {
    const file = fileInputRef.current?.files?.[0];
    if (!file) return;
    const fd = new FormData();
    fd.append("file", file);
    fd.append("language", subtitleLang);
    fd.append("label", subtitleLabel);
    fd.append("is_default", String(subtitleDefault));
    uploadMut.mutate(fd);
  }, [subtitleLang, subtitleLabel, subtitleDefault, uploadMut]);

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

  const handleMediaError = useCallback((error: MediaError) => {
    setPlayerError({
      type: "hls_error",
      message: error.message || "A playback error occurred. Please try again.",
    });
  }, []);

  // ─── Recommendation engagement signals (GAP-0160) ───────────────────────
  // Records watch signals so compute_affinity_scores has data to work with.
  // Fire-and-forget: failures must never affect playback UX.
  const engagementMutation = useMutation({
    mutationFn: recordEngagement,
  });
  // Guard so the 30% milestone signal fires at most once per video.
  const milestoneFiredRef = useRef(false);
  useEffect(() => {
    milestoneFiredRef.current = false;
  }, [videoId]);

  const handleVideoEnded = useCallback(() => {
    if (!videoId) return;
    engagementMutation.mutate({ video_id: videoId, watch_pct: 100 });
  }, [videoId, engagementMutation]);

  const handleVideoProgress = useCallback(
    (watchPct: number) => {
      if (!videoId) return;
      // Fire once when the viewer crosses the ~30% watch milestone.
      if (watchPct >= 30 && !milestoneFiredRef.current) {
        milestoneFiredRef.current = true;
        engagementMutation.mutate({ video_id: videoId, watch_pct: watchPct });
      }
    },
    [videoId, engagementMutation],
  );

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

  const handleDownload = useCallback(async () => {
    if (!videoId) return;
    setIsDownloading(true);
    try {
      const resp = await getVideoDownload(videoId);
      window.open(resp.download_url, "_blank");
    } catch {
      // Error handled silently — user can retry
    } finally {
      setTimeout(() => setIsDownloading(false), 2000);
    }
  }, [videoId]);

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return "";
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  };

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

      {/* MON-005: Access gate — shown when video loaded but viewer is NOT entitled */}
      {video && !isProcessing && !fetchLevelError && !video.is_entitled && (
        <VideoAccessGate video={video} />
      )}

      {/* Player area — only shown when video loaded, not processing, and ENTITLED */}
      {video && !isProcessing && !fetchLevelError && video.is_entitled !== false && (
        <>
          {/* HLS player error (stream failed, expired token, etc.) */}
          {playerError && (
            <ErrorDisplay error={playerError} onRetry={handleRetry} />
          )}

          {/* Active player */}
          {!playerError && playbackUrl && (
            <div data-testid="video-player">
              <MediaPlayer
                src={playbackUrl}
                mode="vod"
                autoplay
                poster={video.thumbnail_url ?? undefined}
                title={video.title}
                onError={handleMediaError}
                onEnded={handleVideoEnded}
                onProgress={handleVideoProgress}
                subtitleTracks={subtitleTracksForPlayer.length > 0 ? subtitleTracksForPlayer : undefined}
              />
            </div>
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

      {/* Download button (VOD-012 / VOD-020) */}
      {video && !fetchLevelError && video.download_available && (
        <div className="flex items-center gap-3" data-testid="download-section">
          {video.watermark_downloads ? (
            <VodWatermarkDownloadButton videoId={video.video_id} />
          ) : (
            <Button
              onClick={handleDownload}
              disabled={isDownloading}
              className="gap-2"
              data-testid="download-mp4-button"
            >
              {isDownloading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Download className="h-4 w-4" />
              )}
              Download MP4
            </Button>
          )}
          {video.download_mp4_size_bytes != null && video.download_mp4_size_bytes > 0 && (
            <span className="text-sm text-muted-foreground" data-testid="download-size">
              {formatFileSize(video.download_mp4_size_bytes)}
            </span>
          )}
        </div>
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
                {video.owner_user_id === currentUserId &&
                  video.status === "published" &&
                  video.duration_seconds != null &&
                  video.duration_seconds > 0 && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="gap-2"
                      onClick={() => setClipDialogOpen(true)}
                      data-testid="clip-button"
                    >
                      <Scissors className="h-4 w-4" />
                      Clip
                    </Button>
                  )}
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
              {/* MON-005: Price / access badge */}
              <VideoPriceBadge
                priceCents={video.price_cents}
                accessMode={video.access_mode}
                entitled={video.is_entitled}
                accessReason={video.access_reason}
              />
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

      {/* Subtitle Manager (VOD-021) — owner only */}
      {video && !fetchLevelError && video.owner_user_id === currentUserId && (
        <Card data-testid="subtitle-manager">
          <CardHeader>
            <CardTitle className="text-lg">Subtitles &amp; Captions</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Upload form */}
            <div className="flex flex-wrap items-end gap-3">
              <div className="space-y-1">
                <Label htmlFor="subtitle-file">File (.vtt, .srt)</Label>
                <Input
                  id="subtitle-file"
                  type="file"
                  accept=".vtt,.srt"
                  ref={fileInputRef}
                  data-testid="subtitle-file-input"
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="subtitle-lang">Language</Label>
                <Input
                  id="subtitle-lang"
                  value={subtitleLang}
                  onChange={(e) => setSubtitleLang(e.target.value)}
                  placeholder="en"
                  className="w-20"
                  data-testid="subtitle-lang-input"
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="subtitle-label">Label</Label>
                <Input
                  id="subtitle-label"
                  value={subtitleLabel}
                  onChange={(e) => setSubtitleLabel(e.target.value)}
                  placeholder="English"
                  className="w-32"
                  data-testid="subtitle-label-input"
                />
              </div>
              <div className="flex items-center gap-2">
                <Checkbox
                  id="subtitle-default"
                  checked={subtitleDefault}
                  onCheckedChange={(v) => setSubtitleDefault(!!v)}
                  data-testid="subtitle-default-checkbox"
                />
                <Label htmlFor="subtitle-default" className="text-sm">Default</Label>
              </div>
              <Button
                size="sm"
                className="gap-1"
                onClick={handleSubtitleUpload}
                disabled={uploadMut.isPending}
                data-testid="subtitle-upload-button"
              >
                <Upload className="h-3 w-3" />
                Upload
              </Button>
            </div>

            {/* Track list */}
            {(subtitleData?.tracks?.length ?? 0) > 0 && (
              <div className="space-y-2" data-testid="subtitle-track-list">
                {subtitleData!.tracks.map((t: SubtitleTrack) => (
                  <div key={t.track_id} className="flex items-center gap-3 text-sm border rounded px-3 py-2">
                    <Badge variant="secondary">{t.language}</Badge>
                    <span className="flex-1">{t.label}</span>
                    {t.is_default && <Badge>Default</Badge>}
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 text-destructive"
                      onClick={() => deleteMut.mutate(t.track_id)}
                      data-testid={`subtitle-delete-${t.track_id}`}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Clip Dialog (VOD-015) */}
      {video && video.duration_seconds != null && video.duration_seconds > 0 && (
        <ClipDialog
          videoId={video.video_id}
          durationSeconds={video.duration_seconds}
          title={video.title}
          open={clipDialogOpen}
          onOpenChange={setClipDialogOpen}
        />
      )}
    </div>
  );
}
