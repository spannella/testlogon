import * as React from "react";
import { Phone, PhoneCall, PhoneIncoming, PhoneOff, Video, Mic, MicOff, VideoOff, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { cn } from "@/lib/utils";
import type { DirectCallMode } from "@/api/endpoints/messaging";

export type CallUiState =
  | "idle"
  | "incoming_ringing"
  | "outgoing_inviting"
  | "outgoing_ringing"
  | "outgoing_connecting"
  | "reconnecting"
  | "connected"
  | "declined"
  | "busy"
  | "timeout"
  | "ended"
  | "failure";

export interface CallSessionUi {
  state: CallUiState;
  direction: "incoming" | "outgoing";
  mode: DirectCallMode;
  peerName: string;
  callId?: string;
  reasonMessage?: string;
}

interface Props {
  session: CallSessionUi;
  isBusy?: boolean;
  localStream?: MediaStream | null;
  remoteStream?: MediaStream | null;
  isMuted?: boolean;
  isCameraOff?: boolean;
  onAccept: () => void;
  onDecline: () => void;
  onEnd: () => void;
  onDismiss: () => void;
  onToggleMute?: () => void;
  onToggleCamera?: () => void;
}

const outcomeCopy: Record<Extract<CallUiState, "declined" | "busy" | "timeout" | "ended" | "failure">, string> = {
  declined: "Call declined.",
  busy: "User is busy on another call.",
  timeout: "Call timed out with no answer.",
  ended: "Call ended.",
  failure: "Call failed to connect.",
};

// ─── Sub-components ────────────────────────────────────────────────────────

interface VideoRendererProps {
  stream: MediaStream | null | undefined;
  muted?: boolean;
  mirror?: boolean;
  className?: string;
  "aria-label"?: string;
}

function VideoRenderer({ stream, muted = false, mirror = false, className, ...props }: VideoRendererProps) {
  const videoRef = React.useRef<HTMLVideoElement>(null);

  React.useEffect(() => {
    if (!videoRef.current) return;
    videoRef.current.srcObject = stream ?? null;
    return () => {
      if (videoRef.current) videoRef.current.srcObject = null;
    };
  }, [stream]);

  return (
    <video
      ref={videoRef}
      autoPlay
      playsInline
      muted={muted}
      className={cn(
        "h-full w-full object-cover",
        mirror && "[transform:scaleX(-1)]",
        className,
      )}
      aria-label={props["aria-label"]}
    />
  );
}

function AudioRenderer({ stream }: { stream: MediaStream | null | undefined }) {
  const audioRef = React.useRef<HTMLAudioElement>(null);

  React.useEffect(() => {
    if (!audioRef.current) return;
    audioRef.current.srcObject = stream ?? null;
    return () => {
      if (audioRef.current) audioRef.current.srcObject = null;
    };
  }, [stream]);

  return <audio ref={audioRef} autoPlay className="hidden" />;
}

function CallTimer({ running }: { running: boolean }) {
  const [elapsed, setElapsed] = React.useState(0);

  React.useEffect(() => {
    if (!running) { setElapsed(0); return; }
    const interval = window.setInterval(() => setElapsed((e) => e + 1), 1000);
    return () => window.clearInterval(interval);
  }, [running]);

  const minutes = Math.floor(elapsed / 60).toString().padStart(2, "0");
  const seconds = (elapsed % 60).toString().padStart(2, "0");

  return (
    <span className="font-mono text-sm tabular-nums text-muted-foreground" aria-label="Call duration">
      {minutes}:{seconds}
    </span>
  );
}

interface CallControlsProps {
  mode: DirectCallMode;
  isMuted: boolean;
  isCameraOff: boolean;
  onToggleMute: () => void;
  onToggleCamera: () => void;
  onEnd: () => void;
  isBusy: boolean;
}

function CallControls({ mode, isMuted, isCameraOff, onToggleMute, onToggleCamera, onEnd, isBusy }: CallControlsProps) {
  return (
    <div className="flex items-center justify-center gap-3">
      <Button
        variant={isMuted ? "destructive" : "secondary"}
        size="icon"
        className="h-10 w-10 rounded-full"
        onClick={onToggleMute}
        aria-label={isMuted ? "Unmute microphone" : "Mute microphone"}
      >
        {isMuted ? <MicOff className="h-4 w-4" /> : <Mic className="h-4 w-4" />}
      </Button>

      {mode === "video" && (
        <Button
          variant={isCameraOff ? "destructive" : "secondary"}
          size="icon"
          className="h-10 w-10 rounded-full"
          onClick={onToggleCamera}
          aria-label={isCameraOff ? "Turn camera on" : "Turn camera off"}
        >
          {isCameraOff ? <VideoOff className="h-4 w-4" /> : <Video className="h-4 w-4" />}
        </Button>
      )}

      <Button
        variant="destructive"
        size="icon"
        className="h-12 w-12 rounded-full"
        onClick={onEnd}
        disabled={isBusy}
        aria-label="End call"
      >
        <PhoneOff className="h-5 w-5" />
      </Button>
    </div>
  );
}

// ─── Main component ────────────────────────────────────────────────────────

/** Detect if a failure is permission-related based on the reason message. */
function isPermissionDeniedFailure(session: CallSessionUi): boolean {
  if (session.state !== "failure") return false;
  const msg = (session.reasonMessage ?? "").toLowerCase();
  return msg.includes("denied") || msg.includes("access") || msg.includes("permission") || msg.includes("not found");
}

export function CallSessionOverlay({
  session,
  isBusy = false,
  localStream,
  remoteStream,
  isMuted,
  isCameraOff,
  onAccept,
  onDecline,
  onEnd,
  onDismiss,
  onToggleMute,
  onToggleCamera,
}: Props) {
  const isIncoming = session.state === "incoming_ringing";
  const isOutgoing = ["outgoing_inviting", "outgoing_ringing", "outgoing_connecting", "reconnecting"].includes(session.state);
  const isConnected = session.state === "connected";
  const isOutcome = ["declined", "busy", "timeout", "ended", "failure"].includes(session.state);
  const isPermissionDenied = isPermissionDeniedFailure(session);

  // Track whether remote stream has active video tracks
  const [hasRemoteVideo, setHasRemoteVideo] = React.useState(false);

  React.useEffect(() => {
    if (!remoteStream) { setHasRemoteVideo(false); return; }
    const videoTracks = remoteStream.getVideoTracks();
    setHasRemoteVideo(videoTracks.length > 0 && videoTracks.some((t) => t.enabled && !t.muted));

    const handler = () => {
      const tracks = remoteStream.getVideoTracks();
      setHasRemoteVideo(tracks.some((t) => t.enabled && !t.muted));
    };
    videoTracks.forEach((t) => {
      t.addEventListener("mute", handler);
      t.addEventListener("unmute", handler);
      t.addEventListener("ended", handler);
    });
    return () => {
      videoTracks.forEach((t) => {
        t.removeEventListener("mute", handler);
        t.removeEventListener("unmute", handler);
        t.removeEventListener("ended", handler);
      });
    };
  }, [remoteStream]);

  if (session.state === "idle") {
    return null;
  }

  const modeLabel = session.mode === "video" ? "video" : "audio";

  // ─── Video call connected layout ─────────────────────────────────────────
  if (isConnected && session.mode === "video") {
    return (
      <Dialog open onOpenChange={(open) => !open && onDismiss()}>
        <DialogContent
          className="sm:max-w-[95vw] md:max-w-4xl max-h-[90vh] p-0 overflow-hidden"
          aria-label="Video call"
        >
          {/* Hidden audio element for remote audio playback */}
          <AudioRenderer stream={remoteStream} />

          {/* Remote video (full area) */}
          <div className="relative w-full aspect-video bg-black">
            {hasRemoteVideo ? (
              <VideoRenderer
                stream={remoteStream}
                aria-label="Remote video"
              />
            ) : (
              <div className="flex h-full w-full items-center justify-center bg-gradient-to-b from-zinc-800 to-zinc-900">
                <Avatar className="h-24 w-24">
                  <AvatarFallback className="text-2xl bg-zinc-700 text-white">
                    {session.peerName.slice(0, 2).toUpperCase()}
                  </AvatarFallback>
                </Avatar>
              </div>
            )}

            {/* Local PiP */}
            <div className="absolute bottom-4 right-4 w-28 h-20 sm:w-40 sm:h-28 rounded-xl overflow-hidden ring-2 ring-white/60 shadow-lg">
              {isCameraOff ? (
                <div className="flex h-full w-full items-center justify-center bg-zinc-800">
                  <VideoOff className="h-5 w-5 text-zinc-400" />
                </div>
              ) : (
                <VideoRenderer
                  stream={localStream}
                  muted
                  mirror
                  aria-label="Local video preview"
                />
              )}
            </div>

            {/* Peer name + timer overlay */}
            <div className="absolute top-4 left-4 flex items-center gap-2 rounded-lg bg-black/50 px-3 py-1.5 text-white backdrop-blur-sm">
              <span className="text-sm font-medium">{session.peerName}</span>
              <CallTimer running />
            </div>
          </div>

          {/* Controls bar */}
          <div className="flex items-center justify-center px-4 py-4 bg-background">
            <CallControls
              mode="video"
              isMuted={isMuted ?? false}
              isCameraOff={isCameraOff ?? false}
              onToggleMute={onToggleMute ?? (() => {})}
              onToggleCamera={onToggleCamera ?? (() => {})}
              onEnd={onEnd}
              isBusy={isBusy}
            />
          </div>

          {/* Visually hidden DialogTitle for accessibility */}
          <DialogHeader className="sr-only">
            <DialogTitle>Video call with {session.peerName}</DialogTitle>
            <DialogDescription>Video call in progress</DialogDescription>
          </DialogHeader>
        </DialogContent>
      </Dialog>
    );
  }

  // ─── Audio call connected layout ─────────────────────────────────────────
  if (isConnected && session.mode === "audio") {
    return (
      <Dialog open onOpenChange={(open) => !open && onDismiss()}>
        <DialogContent className="sm:max-w-md" aria-label="Audio call">
          {/* Remote audio playback */}
          <AudioRenderer stream={remoteStream} />

          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <PhoneCall className="h-4 w-4" />
              Audio call
            </DialogTitle>
            <DialogDescription className="sr-only">
              Audio call in progress with {session.peerName}
            </DialogDescription>
          </DialogHeader>

          {/* Avatar + name + timer */}
          <div className="flex items-center gap-4 py-4">
            <Avatar className="h-16 w-16">
              <AvatarFallback className="text-xl">
                {session.peerName.slice(0, 2).toUpperCase()}
              </AvatarFallback>
            </Avatar>
            <div className="flex flex-col gap-1">
              <span className="text-sm font-semibold">{session.peerName}</span>
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">Connected</span>
                <CallTimer running />
              </div>
            </div>
          </div>

          {/* Controls */}
          <DialogFooter className="justify-center sm:justify-center">
            <CallControls
              mode="audio"
              isMuted={isMuted ?? false}
              isCameraOff={isCameraOff ?? false}
              onToggleMute={onToggleMute ?? (() => {})}
              onToggleCamera={onToggleCamera ?? (() => {})}
              onEnd={onEnd}
              isBusy={isBusy}
            />
          </DialogFooter>
        </DialogContent>
      </Dialog>
    );
  }

  // ─── Non-connected states (incoming, outgoing, outcome) ──────────────────
  return (
    <Dialog open onOpenChange={(open) => !open && onDismiss()}>
      <DialogContent className="sm:max-w-md" aria-label="Direct call">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {isPermissionDenied ? (
              <ShieldAlert className="h-4 w-4 text-destructive" />
            ) : isIncoming ? (
              <PhoneIncoming className="h-4 w-4" />
            ) : isConnected ? (
              <PhoneCall className="h-4 w-4" />
            ) : (
              <Phone className="h-4 w-4" />
            )}
            {isPermissionDenied
              ? "Permission Required"
              : isIncoming
                ? `Incoming ${modeLabel} call`
                : isOutgoing
                  ? `${session.mode === "video" ? "Video" : "Audio"} call`
                  : "Call status"}
          </DialogTitle>
          <DialogDescription>
            {isPermissionDenied && (
              <span data-testid="permission-denied-message">
                {session.mode === "video"
                  ? "Camera and microphone access denied. Please allow camera and microphone access in your browser settings."
                  : "Microphone access denied. Please allow microphone access in your browser settings."}
              </span>
            )}
            {!isPermissionDenied && isIncoming && `${session.peerName} is calling you.`}
            {!isPermissionDenied && session.state === "outgoing_ringing" && `Ringing ${session.peerName}…`}
            {!isPermissionDenied && session.state === "outgoing_inviting" && `Starting call with ${session.peerName}…`}
            {!isPermissionDenied && session.state === "outgoing_connecting" && `Connecting to ${session.peerName}…`}
            {!isPermissionDenied && session.state === "reconnecting" && `Reconnecting to ${session.peerName}…`}
            {!isPermissionDenied && isOutcome && (session.reasonMessage ?? outcomeCopy[session.state as keyof typeof outcomeCopy])}
          </DialogDescription>
        </DialogHeader>

        <DialogFooter className="gap-2 sm:justify-start">
          {isIncoming && (
            <>
              <Button variant="outline" onClick={onDecline} disabled={isBusy} aria-label="Decline call">
                <PhoneOff className="mr-2 h-4 w-4" />
                Decline
              </Button>
              <Button onClick={onAccept} disabled={isBusy} aria-label="Accept call">
                {session.mode === "video" ? <Video className="mr-2 h-4 w-4" /> : <PhoneCall className="mr-2 h-4 w-4" />}
                Accept
              </Button>
            </>
          )}
          {isOutgoing && (
            <Button variant="outline" onClick={onEnd} disabled={isBusy} aria-label="Cancel call">
              <PhoneOff className="mr-2 h-4 w-4" />
              Cancel
            </Button>
          )}
          {isOutcome && (
            <Button onClick={onDismiss} aria-label="Dismiss call status">
              Dismiss
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
