import { useEffect, useRef, useState, useCallback } from "react";
import { useParams, Link } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import Hls, { Events, ErrorTypes } from "hls.js";
import {
  Loader2,
  ArrowLeft,
  AlertCircle,
  Play,
  Pause,
  Maximize,
  Volume2,
  VolumeX,
  RefreshCw,
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
import { mintPlaybackUrl, getSession, type BroadcastSession } from "@/api/endpoints/broadcast";
import { useAuthStore } from "@/stores/authStore";

// ─── Types ──────────────────────────────────────────────────────

interface QualityLevel {
  index: number;
  height: number;
  width: number;
  bitrate: number;
  label: string;
}

type PlayerState = "idle" | "loading" | "ready" | "playing" | "paused" | "buffering" | "error" | "ended";

interface PlayerError {
  type: "network" | "media" | "fatal" | "auth";
  message: string;
}

// ─── Component ──────────────────────────────────────────────────

export default function LivePlayer() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);

  const videoRef = useRef<HTMLVideoElement>(null);
  const hlsRef = useRef<Hls | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout>>();
  const mediaRecoveryCount = useRef(0);

  const [playerState, setPlayerState] = useState<PlayerState>("idle");
  const [playerError, setPlayerError] = useState<PlayerError | null>(null);
  const [qualityLevels, setQualityLevels] = useState<QualityLevel[]>([]);
  const [currentLevel, setCurrentLevel] = useState(-1);
  const [isMuted, setIsMuted] = useState(false);
  const [volume, setVolume] = useState(100);
  const [showControls, setShowControls] = useState(true);
  const [session, setSession] = useState<BroadcastSession | null>(null);
  const [playbackUrl, setPlaybackUrl] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState<number>(0);

  const controlsTimerRef = useRef<ReturnType<typeof setTimeout>>();

  // ─── Fetch session info ───────────────────────────────────────

  const sessionMutation = useMutation({
    mutationFn: () => getSession(sessionId!),
    onSuccess: (data) => {
      setSession(data);
    },
    onError: () => {
      setPlayerError({ type: "fatal", message: "Session not found or unavailable." });
      setPlayerState("error");
    },
  });

  // ─── Fetch playback URL ───────────────────────────────────────

  const playbackMutation = useMutation({
    mutationFn: () => mintPlaybackUrl(sessionId!),
    onSuccess: (data) => {
      setPlaybackUrl(data.playback_url);
      setExpiresAt(data.expires_at);

      // Schedule refresh at 75% of remaining time
      const nowSec = Math.floor(Date.now() / 1000);
      const remainingSec = data.expires_at - nowSec;
      if (remainingSec > 10) {
        const refreshMs = remainingSec * 750; // 75% in ms
        if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
        refreshTimerRef.current = setTimeout(() => {
          playbackMutation.mutate();
        }, refreshMs);
      }
    },
    onError: () => {
      setPlayerError({ type: "auth", message: "Failed to acquire playback URL. Please try again." });
      setPlayerState("error");
    },
  });

  // ─── Initialize ───────────────────────────────────────────────

  useEffect(() => {
    if (!sessionId || !isAuthenticated) return;
    sessionMutation.mutate();
  }, [sessionId, isAuthenticated]);

  useEffect(() => {
    if (!session || !isAuthenticated) return;
    // Only fetch playback URL for live or stopped sessions (archives)
    playbackMutation.mutate();
  }, [session]);

  // ─── HLS.js Setup ────────────────────────────────────────────

  useEffect(() => {
    const video = videoRef.current;
    if (!video || !playbackUrl) return;

    setPlayerState("loading");
    setPlayerError(null);
    mediaRecoveryCount.current = 0;

    // Safari native HLS support
    const nativeHls = video.canPlayType("application/vnd.apple.mpegURL") !== "";
    if (nativeHls && !Hls.isSupported()) {
      video.src = playbackUrl;
      video.play().catch(() => {
        // Autoplay blocked - user must interact
        setPlayerState("ready");
      });
      return;
    }

    if (!Hls.isSupported()) {
      setPlayerError({ type: "fatal", message: "HLS playback is not supported in this browser." });
      setPlayerState("error");
      return;
    }

    // Destroy previous instance
    if (hlsRef.current) {
      hlsRef.current.destroy();
    }

    const hls = new Hls({
      enableWorker: true,
      lowLatencyMode: true,
      backBufferLength: 30,
      maxBufferLength: 30,
      maxMaxBufferLength: 60,
      fragLoadingMaxRetry: 6,
      manifestLoadingMaxRetry: 4,
      levelLoadingMaxRetry: 4,
    });

    hls.loadSource(playbackUrl);
    hls.attachMedia(video);

    hls.on(Events.MANIFEST_PARSED, (_event, data) => {
      const levels: QualityLevel[] = data.levels.map((level, index) => ({
        index,
        height: level.height,
        width: level.width,
        bitrate: level.bitrate,
        label: level.height ? `${level.height}p` : `${Math.round(level.bitrate / 1000)}kbps`,
      }));
      setQualityLevels([{ index: -1, height: 0, width: 0, bitrate: 0, label: "Auto" }, ...levels]);
      setPlayerState("ready");

      // Attempt autoplay
      video.play().catch(() => {
        // Autoplay blocked
        setPlayerState("ready");
      });
    });

    hls.on(Events.LEVEL_SWITCHED, (_event, data) => {
      setCurrentLevel(data.level);
    });

    hls.on(Events.ERROR, (_event, data) => {
      if (!data.fatal) return;

      switch (data.type) {
        case ErrorTypes.MEDIA_ERROR:
          if (mediaRecoveryCount.current < 2) {
            mediaRecoveryCount.current++;
            hls.recoverMediaError();
          } else {
            hls.swapAudioCodec();
            hls.recoverMediaError();
            mediaRecoveryCount.current = 0;
          }
          break;
        case ErrorTypes.NETWORK_ERROR:
          if (data.details === "manifestLoadError" || data.details === "manifestLoadTimeOut") {
            setPlayerError({
              type: "network",
              message: "Stream unavailable. It may have ended or the URL has expired.",
            });
            setPlayerState("error");
          } else {
            // Try to recover from network error
            hls.startLoad();
          }
          break;
        default:
          setPlayerError({ type: "fatal", message: "Playback failed. Please try again." });
          setPlayerState("error");
          hls.destroy();
      }
    });

    hlsRef.current = hls;

    return () => {
      hls.destroy();
      hlsRef.current = null;
    };
  }, [playbackUrl]);

  // ─── Video event listeners ────────────────────────────────────

  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;

    const onPlay = () => setPlayerState("playing");
    const onPause = () => setPlayerState("paused");
    const onWaiting = () => setPlayerState("buffering");
    const onPlaying = () => setPlayerState("playing");
    const onEnded = () => setPlayerState("ended");

    video.addEventListener("play", onPlay);
    video.addEventListener("pause", onPause);
    video.addEventListener("waiting", onWaiting);
    video.addEventListener("playing", onPlaying);
    video.addEventListener("ended", onEnded);

    return () => {
      video.removeEventListener("play", onPlay);
      video.removeEventListener("pause", onPause);
      video.removeEventListener("waiting", onWaiting);
      video.removeEventListener("playing", onPlaying);
      video.removeEventListener("ended", onEnded);
    };
  }, []);

  // ─── Controls auto-hide ───────────────────────────────────────

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

  // ─── Cleanup timers ───────────────────────────────────────────

  useEffect(() => {
    return () => {
      if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
      if (controlsTimerRef.current) clearTimeout(controlsTimerRef.current);
    };
  }, []);

  // ─── Player controls ─────────────────────────────────────────

  const togglePlay = () => {
    const video = videoRef.current;
    if (!video) return;
    if (video.paused) {
      video.play().catch(() => {});
    } else {
      video.pause();
    }
  };

  const toggleMute = () => {
    const video = videoRef.current;
    if (!video) return;
    video.muted = !video.muted;
    setIsMuted(video.muted);
  };

  const handleVolumeChange = (newVolume: number) => {
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
  };

  const toggleFullscreen = () => {
    const container = containerRef.current;
    if (!container) return;
    if (document.fullscreenElement) {
      document.exitFullscreen();
    } else {
      container.requestFullscreen().catch(() => {});
    }
  };

  const setQuality = (levelIndex: number) => {
    if (hlsRef.current) {
      hlsRef.current.currentLevel = levelIndex;
      hlsRef.current.loadLevel = levelIndex;
      setCurrentLevel(levelIndex);
    }
  };

  const retry = () => {
    setPlayerError(null);
    setPlayerState("idle");
    playbackMutation.mutate();
  };

  // ─── Render: Not authenticated ────────────────────────────────

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-black flex flex-col items-center justify-center p-4">
        <div className="text-center space-y-4 max-w-md">
          <AlertCircle className="h-12 w-12 text-yellow-500 mx-auto" />
          <h1 className="text-xl font-semibold text-white">Sign in required</h1>
          <p className="text-gray-400">
            You need to sign in to watch this broadcast.
          </p>
          <Link to="/login">
            <Button className="mt-4">Sign in</Button>
          </Link>
        </div>
      </div>
    );
  }

  // ─── Render: Main player page ─────────────────────────────────

  const isLive = session?.status === "live";

  return (
    <div className="min-h-screen bg-black flex flex-col">
      {/* Header */}
      <header className="flex items-center gap-3 px-4 py-3 bg-gray-900/80 border-b border-gray-800">
        <Link to="/" className="text-gray-400 hover:text-white transition-colors">
          <ArrowLeft className="h-5 w-5" />
        </Link>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h1 className="text-white font-medium truncate text-sm sm:text-base">
              {session ? `Session ${session.id.slice(0, 12)}...` : "Loading..."}
            </h1>
            {isLive && (
              <Badge
                variant="secondary"
                className="bg-red-600 text-white hover:bg-red-600 gap-1 shrink-0"
              >
                <span className="inline-block h-2 w-2 rounded-full bg-white animate-pulse" />
                LIVE
              </Badge>
            )}
            {session && !isLive && (
              <Badge variant="secondary" className="text-xs shrink-0">
                {session.status}
              </Badge>
            )}
          </div>
        </div>
      </header>

      {/* Player area */}
      <div className="flex-1 flex items-center justify-center p-2 sm:p-4">
        <div
          ref={containerRef}
          className="relative w-full max-w-5xl aspect-video bg-black rounded-lg overflow-hidden"
          onMouseMove={resetControlsTimer}
          onTouchStart={resetControlsTimer}
        >
          {/* Video element */}
          <video
            ref={videoRef}
            className="absolute inset-0 w-full h-full object-contain"
            playsInline
            onClick={togglePlay}
          />

          {/* Loading overlay */}
          {(playerState === "idle" || playerState === "loading") && !playerError && (
            <div className="absolute inset-0 flex items-center justify-center bg-black/60">
              <div className="text-center space-y-3">
                <Loader2 className="h-10 w-10 animate-spin text-white mx-auto" />
                <p className="text-gray-300 text-sm">
                  {playerState === "idle" ? "Preparing stream..." : "Loading stream..."}
                </p>
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
          {playerState === "error" && playerError && (
            <div className="absolute inset-0 flex items-center justify-center bg-black/80">
              <div className="text-center space-y-4 max-w-sm px-4">
                <AlertCircle className="h-10 w-10 text-red-400 mx-auto" />
                <p className="text-white font-medium">{playerError.message}</p>
                <Button
                  variant="secondary"
                  onClick={retry}
                  className="gap-2"
                >
                  <RefreshCw className="h-4 w-4" />
                  Retry
                </Button>
              </div>
            </div>
          )}

          {/* Ended overlay */}
          {playerState === "ended" && (
            <div className="absolute inset-0 flex items-center justify-center bg-black/60">
              <div className="text-center space-y-3">
                <Play className="h-12 w-12 text-white mx-auto" />
                <p className="text-gray-300">Stream ended</p>
                <Button variant="secondary" onClick={() => videoRef.current?.play()}>
                  Replay
                </Button>
              </div>
            </div>
          )}

          {/* Controls overlay */}
          {showControls && playerState !== "error" && playerState !== "idle" && playerState !== "loading" && (
            <div className="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/80 to-transparent px-4 pb-3 pt-10 transition-opacity">
              <div className="flex items-center gap-2 sm:gap-3">
                {/* Play/Pause */}
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8 text-white hover:bg-white/20"
                  onClick={togglePlay}
                >
                  {playerState === "playing" || playerState === "buffering" ? (
                    <Pause className="h-4 w-4" />
                  ) : (
                    <Play className="h-4 w-4" />
                  )}
                </Button>

                {/* Live badge in controls */}
                {isLive && (
                  <Badge
                    variant="secondary"
                    className="bg-red-600 text-white hover:bg-red-600 text-xs gap-1"
                  >
                    <span className="inline-block h-1.5 w-1.5 rounded-full bg-white animate-pulse" />
                    LIVE
                  </Badge>
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
                  />
                </div>

                {/* Quality selector */}
                {qualityLevels.length > 1 && (
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8 text-white hover:bg-white/20"
                      >
                        <Settings className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="min-w-[120px]">
                      {qualityLevels.map((level) => (
                        <DropdownMenuItem
                          key={level.index}
                          onClick={() => setQuality(level.index)}
                          className={currentLevel === level.index ? "font-bold" : ""}
                        >
                          {level.label}
                          {currentLevel === level.index && " *"}
                        </DropdownMenuItem>
                      ))}
                    </DropdownMenuContent>
                  </DropdownMenu>
                )}

                {/* Fullscreen */}
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8 text-white hover:bg-white/20"
                  onClick={toggleFullscreen}
                >
                  <Maximize className="h-4 w-4" />
                </Button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Session info below video */}
      {session && (
        <div className="px-4 pb-6 max-w-5xl mx-auto w-full">
          <div className="text-gray-400 text-sm space-y-1 mt-2">
            <p>
              <span className="text-gray-500">Session:</span>{" "}
              <span className="text-gray-300 font-mono text-xs">{session.id}</span>
            </p>
            {session.started_at && (
              <p>
                <span className="text-gray-500">Started:</span>{" "}
                {new Date(session.started_at).toLocaleString()}
              </p>
            )}
            {expiresAt > 0 && (
              <p>
                <span className="text-gray-500">Playback URL expires:</span>{" "}
                {new Date(expiresAt * 1000).toLocaleTimeString()}
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
