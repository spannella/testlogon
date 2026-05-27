import { useEffect, useRef, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import {
  ArrowLeft,
  AlertCircle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { MediaPlayer, type MediaError } from "@/components/shared/MediaPlayer";
import { mintPlaybackUrl, getSession, type BroadcastSession } from "@/api/endpoints/broadcast";
import { useAuthStore } from "@/stores/authStore";
import { BroadcastChat } from "./BroadcastChat";
import { ChatOverlay } from "./ChatOverlay";
import { ProductShelf } from "./ProductShelf";
import { type ChatMessage } from "@/api/endpoints/broadcast-chat";

// ─── Types ──────────────────────────────────────────────────────

interface PlayerError {
  type: "network" | "media" | "fatal" | "auth";
  message: string;
}

// ─── Component ──────────────────────────────────────────────────

export default function LivePlayer() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);

  const refreshTimerRef = useRef<ReturnType<typeof setTimeout>>();

  const [playerError, setPlayerError] = useState<PlayerError | null>(null);
  const [session, setSession] = useState<BroadcastSession | null>(null);
  const [playbackUrl, setPlaybackUrl] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState<number>(0);
  const [showChat, setShowChat] = useState(true);
  const [showShelf, setShowShelf] = useState(true);
  const [overlayEnabled, setOverlayEnabled] = useState(false);
  const [chatMessages] = useState<ChatMessage[]>([]);

  // ─── Fetch session info ───────────────────────────────────────

  const sessionMutation = useMutation({
    mutationFn: () => getSession(sessionId!),
    onSuccess: (data) => {
      setSession(data);
    },
    onError: () => {
      setPlayerError({ type: "fatal", message: "Session not found or unavailable." });
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
    },
  });

  // ─── Initialize ───────────────────────────────────────────────

  useEffect(() => {
    if (!sessionId || !isAuthenticated) return;
    sessionMutation.mutate();
  }, [sessionId, isAuthenticated]);

  useEffect(() => {
    if (!session || !isAuthenticated) return;
    playbackMutation.mutate();
  }, [session]);

  // ─── Cleanup timers ───────────────────────────────────────────

  useEffect(() => {
    return () => {
      if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    };
  }, []);

  // ─── MediaPlayer error handler ────────────────────────────────

  const handleMediaError = (error: MediaError) => {
    setPlayerError({ type: "network", message: error.message });
  };

  const retry = () => {
    setPlayerError(null);
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

      {/* Player + Chat area */}
      <div className="flex-1 flex flex-col lg:flex-row p-2 sm:p-4 gap-2">
        {/* Player container */}
        <div className="flex-1 flex items-center justify-center">
          <div className="relative w-full max-w-5xl">
            {/* Chat overlay on video */}
            {isLive && (
              <ChatOverlay messages={chatMessages} enabled={overlayEnabled} />
            )}
            {playbackUrl ? (
              <MediaPlayer
                src={playbackUrl}
                mode="live"
                autoplay
                muted={false}
                controls={false}
                onError={handleMediaError}
              />
            ) : !playerError ? (
              <div className="aspect-video bg-black rounded-lg flex items-center justify-center">
                <div className="text-center space-y-3">
                  <div className="h-10 w-10 animate-spin rounded-full border-2 border-white border-t-transparent mx-auto" />
                  <p className="text-gray-300 text-sm">Preparing stream...</p>
                </div>
              </div>
            ) : (
              <div className="aspect-video bg-black rounded-lg flex items-center justify-center">
                <div className="text-center space-y-4 max-w-sm px-4">
                  <AlertCircle className="h-10 w-10 text-red-400 mx-auto" />
                  <p className="text-white font-medium">{playerError.message}</p>
                  <Button variant="secondary" onClick={retry} className="gap-2">
                    Retry
                  </Button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Side panels (right side on desktop, below on mobile) */}
        {isLive && sessionId && (
          <div className="flex flex-col gap-2 w-full lg:w-80 shrink-0">
            {showChat && (
              <div className="h-64 lg:h-auto lg:max-h-[calc(100vh-16rem)] lg:flex-1" data-testid="chat-panel">
                <BroadcastChat
                  sessionId={sessionId}
                  isBroadcaster={session?.created_by === useAuthStore.getState().userId}
                />
              </div>
            )}
            <ProductShelf
              sessionId={sessionId}
              isVisible={showShelf}
              onToggle={() => setShowShelf((v) => !v)}
            />
          </div>
        )}
      </div>

      {/* Chat toggle + overlay toggle */}
      {isLive && (
        <div className="flex items-center gap-2 px-4 py-1">
          <Button
            variant="ghost"
            size="sm"
            className="text-gray-400 hover:text-white text-xs"
            onClick={() => setShowChat((v) => !v)}
            data-testid="chat-toggle"
          >
            {showChat ? "Hide Chat" : "Show Chat"}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="text-gray-400 hover:text-white text-xs"
            onClick={() => setOverlayEnabled((v) => !v)}
            data-testid="overlay-toggle"
          >
            {overlayEnabled ? "Overlay On" : "Overlay Off"}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="text-gray-400 hover:text-white text-xs"
            onClick={() => setShowShelf((v) => !v)}
            data-testid="shelf-visibility-toggle"
          >
            {showShelf ? "Hide Products" : "Show Products"}
          </Button>
        </div>
      )}

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
