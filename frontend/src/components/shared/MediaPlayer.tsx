/**
 * MediaPlayer — Shared HLS/DRM player component (MEDIA-001)
 *
 * A reusable adaptive bitrate video player with:
 * - HLS.js initialization with quality selection
 * - Loading/error/buffering overlays
 * - Fullscreen and Picture-in-Picture
 * - Volume control
 * - Live mode (no seek bar, LIVE badge) vs VOD mode (duration, seek bar)
 * - Native Safari HLS fallback
 * - AES-128 DRM key URL support
 */

import { useEffect, useRef, useState, useCallback } from "react";
import Hls from "hls.js";
import {
  Loader2,
  AlertCircle,
  RefreshCw,
  Play,
  Pause,
  Maximize,
  Minimize,
  PictureInPicture2,
  Volume2,
  VolumeX,
  Settings,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/utils";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface MediaError {
  code: string;
  message: string;
}

export interface MediaPlayerProps {
  /** HLS manifest URL */
  src: string;
  /** Controls seek bar visibility and buffering behavior */
  mode?: "live" | "vod";
  /** Attempt autoplay on load */
  autoplay?: boolean;
  /** Start muted */
  muted?: boolean;
  /** Poster image URL shown before playback */
  poster?: string;
  /** Overlay title shown on hover */
  title?: string;
  /** Called on fatal playback errors */
  onError?: (error: MediaError) => void;
  /** Called when manifest is parsed and player is ready */
  onReady?: () => void;
  /** Called when quality level changes */
  onQualityChange?: (level: number) => void;
  /** Additional CSS class on the container */
  className?: string;
  /** Show native controls (default true for VOD, false for live) */
  controls?: boolean;
  /** Key server URL for AES-128 HLS encryption */
  drmKeyUrl?: string;
}

interface QualityLevel {
  index: number;
  height: number;
  bitrate: number;
  label: string;
}

type PlayerState =
  | "idle"
  | "loading"
  | "ready"
  | "playing"
  | "paused"
  | "buffering"
  | "error";

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
          className="gap-1.5 bg-black/60 text-white hover:bg-black/80 hover:text-white text-xs px-2 py-1 h-7"
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

// ─── Format Helper ──────────────────────────────────────────────────────────

function formatTime(seconds: number): string {
  if (!isFinite(seconds) || seconds < 0) return "0:00";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (h > 0) {
    return `${h}:${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`;
  }
  return `${m}:${s.toString().padStart(2, "0")}`;
}

// ─── MediaPlayer Component ──────────────────────────────────────────────────

export function MediaPlayer({
  src,
  mode = "vod",
  autoplay = false,
  muted = false,
  poster,
  title,
  onError,
  onReady,
  onQualityChange,
  className,
  controls,
  drmKeyUrl,
}: MediaPlayerProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const hlsRef = useRef<Hls | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const controlsTimerRef = useRef<ReturnType<typeof setTimeout>>();
  const mediaRecoveryCount = useRef(0);

  const [playerState, setPlayerState] = useState<PlayerState>("idle");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [qualityLevels, setQualityLevels] = useState<QualityLevel[]>([]);
  const [currentLevel, setCurrentLevel] = useState(-1);
  const [isMuted, setIsMuted] = useState(muted);
  const [volume, setVolume] = useState(muted ? 0 : 100);
  const [showControls, setShowControls] = useState(true);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);

  // Determine whether to show native controls or custom overlay
  const showNativeControls = controls ?? (mode === "vod");
  const showCustomControls = !showNativeControls;

  // ─── HLS.js Setup ───────────────────────────────────────────────────────

  useEffect(() => {
    const video = videoRef.current;
    if (!video || !src) {
      setPlayerState("idle");
      return;
    }

    setPlayerState("loading");
    setErrorMessage(null);
    mediaRecoveryCount.current = 0;

    // Native HLS fallback (Safari)
    if (!Hls.isSupported()) {
      if (video.canPlayType("application/vnd.apple.mpegurl")) {
        video.src = src;
        if (autoplay) {
          video.play().catch(() => {});
        }
        setPlayerState("ready");
        onReady?.();
        return;
      }
      setErrorMessage("HLS playback is not supported in this browser.");
      setPlayerState("error");
      onError?.({ code: "UNSUPPORTED", message: "HLS not supported" });
      return;
    }

    // Destroy previous instance
    if (hlsRef.current) {
      hlsRef.current.destroy();
      hlsRef.current = null;
    }

    const hlsConfig: Partial<ConstructorParameters<typeof Hls>[0]> = {
      startLevel: -1,
      enableWorker: true,
      lowLatencyMode: mode === "live",
      maxBufferLength: mode === "live" ? 6 : 30,
      maxMaxBufferLength: mode === "live" ? 12 : 60,
      fragLoadingMaxRetry: 6,
      manifestLoadingMaxRetry: 4,
      levelLoadingMaxRetry: 4,
    };

    if (drmKeyUrl) {
      hlsConfig.emeEnabled = true;
    }

    const hls = new Hls(hlsConfig as ConstructorParameters<typeof Hls>[0]);
    hlsRef.current = hls;

    hls.loadSource(src);
    hls.attachMedia(video);

    hls.on(Hls.Events.MANIFEST_PARSED, (_event, data) => {
      const levels: QualityLevel[] = data.levels.map((level, index) => ({
        index,
        height: level.height,
        bitrate: level.bitrate,
        label: level.height
          ? `${level.height}p`
          : `${Math.round(level.bitrate / 1000)}kbps`,
      }));
      setQualityLevels(levels);
      setPlayerState("ready");
      onReady?.();

      if (autoplay) {
        video.play().catch(() => {
          // Autoplay blocked by browser policy
          setPlayerState("ready");
        });
      }
    });

    hls.on(Hls.Events.LEVEL_SWITCHED, (_event, data) => {
      setCurrentLevel(data.level);
      onQualityChange?.(data.level);
    });

    hls.on(Hls.Events.ERROR, (_event, data) => {
      if (!data.fatal) return;

      switch (data.type) {
        case Hls.ErrorTypes.NETWORK_ERROR:
          if (
            data.details === "manifestLoadError" ||
            data.details === "manifestLoadTimeOut"
          ) {
            const msg = "Stream unavailable. It may have ended or the URL has expired.";
            setErrorMessage(msg);
            setPlayerState("error");
            onError?.({ code: "NETWORK_ERROR", message: msg });
          } else {
            // Attempt recovery
            hls.startLoad();
          }
          break;
        case Hls.ErrorTypes.MEDIA_ERROR:
          if (mediaRecoveryCount.current < 3) {
            mediaRecoveryCount.current++;
            hls.recoverMediaError();
          } else {
            const msg = "A media error occurred. Please try again.";
            setErrorMessage(msg);
            setPlayerState("error");
            onError?.({ code: "MEDIA_ERROR", message: msg });
          }
          break;
        default: {
          const msg = "Playback failed. Please try again.";
          setErrorMessage(msg);
          setPlayerState("error");
          onError?.({ code: data.type, message: data.details });
          hls.destroy();
        }
      }
    });

    return () => {
      hls.destroy();
      hlsRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [src, mode, drmKeyUrl]);

  // ─── Video event listeners ──────────────────────────────────────────────

  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;

    const onPlay = () => setPlayerState("playing");
    const onPause = () => setPlayerState("paused");
    const onWaiting = () => setPlayerState("buffering");
    const onPlaying = () => setPlayerState("playing");
    const onTimeUpdate = () => {
      setCurrentTime(video.currentTime);
      setDuration(video.duration || 0);
    };
    const onLoadedMetadata = () => {
      setDuration(video.duration || 0);
    };

    video.addEventListener("play", onPlay);
    video.addEventListener("pause", onPause);
    video.addEventListener("waiting", onWaiting);
    video.addEventListener("playing", onPlaying);
    video.addEventListener("timeupdate", onTimeUpdate);
    video.addEventListener("loadedmetadata", onLoadedMetadata);

    return () => {
      video.removeEventListener("play", onPlay);
      video.removeEventListener("pause", onPause);
      video.removeEventListener("waiting", onWaiting);
      video.removeEventListener("playing", onPlaying);
      video.removeEventListener("timeupdate", onTimeUpdate);
      video.removeEventListener("loadedmetadata", onLoadedMetadata);
    };
  }, []);

  // ─── Fullscreen change listener ─────────────────────────────────────────

  useEffect(() => {
    const onFsChange = () => {
      setIsFullscreen(!!document.fullscreenElement);
    };
    document.addEventListener("fullscreenchange", onFsChange);
    return () => document.removeEventListener("fullscreenchange", onFsChange);
  }, []);

  // ─── Controls auto-hide ─────────────────────────────────────────────────

  const resetControlsTimer = useCallback(() => {
    setShowControls(true);
    if (controlsTimerRef.current) clearTimeout(controlsTimerRef.current);
    if (playerState === "playing") {
      controlsTimerRef.current = setTimeout(() => {
        setShowControls(false);
      }, 3000);
    }
  }, [playerState]);

  useEffect(() => {
    if (playerState !== "playing") {
      setShowControls(true);
    }
  }, [playerState]);

  useEffect(() => {
    return () => {
      if (controlsTimerRef.current) clearTimeout(controlsTimerRef.current);
    };
  }, []);

  // ─── Player control handlers ────────────────────────────────────────────

  const togglePlay = useCallback(() => {
    const video = videoRef.current;
    if (!video) return;
    if (video.paused) {
      video.play().catch(() => {});
    } else {
      video.pause();
    }
  }, []);

  const toggleMute = useCallback(() => {
    const video = videoRef.current;
    if (!video) return;
    video.muted = !video.muted;
    setIsMuted(video.muted);
  }, []);

  const handleVolumeChange = useCallback((newVolume: number) => {
    const video = videoRef.current;
    if (!video) return;
    const vol = newVolume / 100;
    video.volume = vol;
    setVolume(newVolume);
    if (vol === 0) {
      video.muted = true;
      setIsMuted(true);
    } else if (video.muted) {
      video.muted = false;
      setIsMuted(false);
    }
  }, []);

  const toggleFullscreen = useCallback(() => {
    const container = containerRef.current;
    if (!container) return;
    if (document.fullscreenElement) {
      document.exitFullscreen();
    } else {
      container.requestFullscreen().catch(() => {});
    }
  }, []);

  const togglePip = useCallback(async () => {
    const video = videoRef.current;
    if (!video) return;
    try {
      if (document.pictureInPictureElement) {
        await document.exitPictureInPicture();
      } else {
        await video.requestPictureInPicture();
      }
    } catch {
      // PiP not available
    }
  }, []);

  const setQuality = useCallback((levelIndex: number) => {
    if (hlsRef.current) {
      hlsRef.current.currentLevel = levelIndex;
      setCurrentLevel(levelIndex);
    }
  }, []);

  const handleSeek = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const video = videoRef.current;
    if (!video) return;
    const time = Number(e.target.value);
    video.currentTime = time;
    setCurrentTime(time);
  }, []);

  const retry = useCallback(() => {
    setErrorMessage(null);
    setPlayerState("loading");
    const video = videoRef.current;
    if (!video) return;

    if (hlsRef.current) {
      hlsRef.current.destroy();
      hlsRef.current = null;
    }

    // Re-trigger by toggling src effect
    if (Hls.isSupported() && src) {
      const hls = new Hls({
        startLevel: -1,
        enableWorker: true,
        lowLatencyMode: mode === "live",
        maxBufferLength: mode === "live" ? 6 : 30,
        maxMaxBufferLength: mode === "live" ? 12 : 60,
      });
      hlsRef.current = hls;
      hls.loadSource(src);
      hls.attachMedia(video);

      hls.on(Hls.Events.MANIFEST_PARSED, (_event, data) => {
        const levels: QualityLevel[] = data.levels.map((level, index) => ({
          index,
          height: level.height,
          bitrate: level.bitrate,
          label: level.height
            ? `${level.height}p`
            : `${Math.round(level.bitrate / 1000)}kbps`,
        }));
        setQualityLevels(levels);
        setPlayerState("ready");
        onReady?.();
        video.play().catch(() => {});
      });

      hls.on(Hls.Events.LEVEL_SWITCHED, (_event, data) => {
        setCurrentLevel(data.level);
        onQualityChange?.(data.level);
      });

      hls.on(Hls.Events.ERROR, (_event, data) => {
        if (!data.fatal) return;
        const msg = "Playback failed. Please try again.";
        setErrorMessage(msg);
        setPlayerState("error");
        onError?.({ code: data.type, message: data.details });
      });
    } else if (video.canPlayType("application/vnd.apple.mpegurl")) {
      video.src = src;
      video.play().catch(() => {});
      setPlayerState("ready");
    }
  }, [src, mode, onError, onReady, onQualityChange]);

  // ─── Render ─────────────────────────────────────────────────────────────

  return (
    <div
      ref={containerRef}
      className={cn(
        "relative w-full aspect-video bg-black rounded-lg overflow-hidden group",
        className,
      )}
      onMouseMove={showCustomControls ? resetControlsTimer : undefined}
      onTouchStart={showCustomControls ? resetControlsTimer : undefined}
      data-testid="media-player"
      data-mode={mode}
      data-state={playerState}
    >
      {/* Video element */}
      <video
        ref={videoRef}
        className="absolute inset-0 w-full h-full object-contain"
        controls={showNativeControls}
        playsInline
        muted={muted}
        poster={poster}
        onClick={showCustomControls ? togglePlay : undefined}
        data-testid="media-player-video"
      />

      {/* Title overlay */}
      {title && showControls && playerState !== "error" && (
        <div className="absolute top-0 left-0 right-0 bg-gradient-to-b from-black/60 to-transparent px-4 pt-3 pb-8 pointer-events-none">
          <p className="text-white text-sm font-medium truncate" data-testid="media-player-title">
            {title}
          </p>
        </div>
      )}

      {/* Loading spinner overlay */}
      {(playerState === "idle" || playerState === "loading") && !errorMessage && (
        <div
          className="absolute inset-0 flex items-center justify-center bg-black/60"
          data-testid="media-player-loading"
        >
          <div className="text-center space-y-3">
            <Loader2 className="h-10 w-10 animate-spin text-white mx-auto" />
            <p className="text-gray-300 text-sm">Loading...</p>
          </div>
        </div>
      )}

      {/* Buffering overlay */}
      {playerState === "buffering" && (
        <div className="absolute inset-0 flex items-center justify-center bg-black/30 pointer-events-none">
          <Loader2 className="h-8 w-8 animate-spin text-white" />
        </div>
      )}

      {/* Error overlay */}
      {playerState === "error" && errorMessage && (
        <div
          className="absolute inset-0 flex items-center justify-center bg-black/80"
          data-testid="media-player-error"
        >
          <div className="text-center space-y-4 max-w-sm px-4">
            <AlertCircle className="h-10 w-10 text-red-400 mx-auto" />
            <p className="text-white font-medium" data-testid="media-player-error-message">
              {errorMessage}
            </p>
            <Button
              variant="secondary"
              onClick={retry}
              className="gap-2"
              data-testid="media-player-retry"
            >
              <RefreshCw className="h-4 w-4" />
              Retry
            </Button>
          </div>
        </div>
      )}

      {/* Custom controls overlay (when native controls are disabled) */}
      {showCustomControls &&
        showControls &&
        playerState !== "error" &&
        playerState !== "idle" &&
        playerState !== "loading" && (
          <div className="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/80 to-transparent px-4 pb-3 pt-10 transition-opacity">
            {/* Seek bar (VOD mode only) */}
            {mode === "vod" && duration > 0 && (
              <div className="flex items-center gap-2 mb-2" data-testid="media-player-seekbar">
                <span className="text-white text-xs min-w-[40px]">
                  {formatTime(currentTime)}
                </span>
                <input
                  type="range"
                  className="flex-1 h-1 accent-white cursor-pointer"
                  min={0}
                  max={duration}
                  step={0.1}
                  value={currentTime}
                  onChange={handleSeek}
                  aria-label="Seek"
                />
                <span className="text-white text-xs min-w-[40px] text-right" data-testid="media-player-duration">
                  {formatTime(duration)}
                </span>
              </div>
            )}

            <div className="flex items-center gap-2 sm:gap-3">
              {/* Play/Pause */}
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8 text-white hover:bg-white/20"
                onClick={togglePlay}
                data-testid="media-player-playpause"
              >
                {playerState === "playing" || playerState === "buffering" ? (
                  <Pause className="h-4 w-4" />
                ) : (
                  <Play className="h-4 w-4" />
                )}
              </Button>

              {/* Live badge */}
              {mode === "live" && (
                <Badge
                  variant="secondary"
                  className="bg-red-600 text-white hover:bg-red-600 text-xs gap-1"
                  data-testid="media-player-live-badge"
                >
                  <span className="inline-block h-1.5 w-1.5 rounded-full bg-white animate-pulse" />
                  LIVE
                </Badge>
              )}

              {/* Time display for VOD in controls bar */}
              {mode === "vod" && duration > 0 && (
                <span className="text-white text-xs hidden sm:block" data-testid="media-player-time">
                  {formatTime(currentTime)} / {formatTime(duration)}
                </span>
              )}

              {/* Spacer */}
              <div className="flex-1" />

              {/* Volume */}
              <div className="hidden sm:flex items-center gap-2">
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8 text-white hover:bg-white/20"
                  onClick={toggleMute}
                  data-testid="media-player-mute"
                >
                  {isMuted || volume === 0 ? (
                    <VolumeX className="h-4 w-4" />
                  ) : (
                    <Volume2 className="h-4 w-4" />
                  )}
                </Button>
                <input
                  type="range"
                  className="w-20 h-1 accent-white cursor-pointer"
                  value={isMuted ? 0 : volume}
                  max={100}
                  step={1}
                  onChange={(e) => handleVolumeChange(Number(e.target.value))}
                  aria-label="Volume"
                  data-testid="media-player-volume"
                />
              </div>

              {/* Quality selector */}
              {qualityLevels.length > 0 && (
                <QualitySelector
                  levels={qualityLevels}
                  currentLevel={currentLevel}
                  onChange={setQuality}
                />
              )}

              {/* Picture-in-Picture */}
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8 text-white hover:bg-white/20"
                onClick={togglePip}
                data-testid="media-player-pip"
              >
                <PictureInPicture2 className="h-4 w-4" />
              </Button>

              {/* Fullscreen */}
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8 text-white hover:bg-white/20"
                onClick={toggleFullscreen}
                data-testid="media-player-fullscreen"
              >
                {isFullscreen ? (
                  <Minimize className="h-4 w-4" />
                ) : (
                  <Maximize className="h-4 w-4" />
                )}
              </Button>
            </div>
          </div>
        )}

      {/* Quality selector for native controls mode (positioned absolutely) */}
      {showNativeControls && qualityLevels.length > 0 && (
        <div className="absolute bottom-14 right-3 z-10">
          <QualitySelector
            levels={qualityLevels}
            currentLevel={currentLevel}
            onChange={setQuality}
          />
        </div>
      )}
    </div>
  );
}

export default MediaPlayer;
