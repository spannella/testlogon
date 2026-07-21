/**
 * Group Call Overlay (CALL-012, GAP-0017)
 *
 * Full-screen overlay for group video/audio calls.
 * Renders participant grid, call controls (mute/camera/leave/end),
 * and an active call banner for non-participants.
 *
 * WebRTC media flow is owned by the `useGroupCall` hook, which reads the
 * topology `mode` ("mesh" | "sfu") and ICE servers from the join response and
 * drives the peer connection setup accordingly. This component is the
 * presentation layer for that hook.
 */
import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Phone,
  PhoneOff,
  Mic,
  MicOff,
  Video,
  VideoOff,
  Users,
  MonitorUp,
  Monitor,
  MonitorOff,
  Grid3X3,
  LayoutDashboard,
  X,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { cn } from "@/lib/utils";
import {
  createGroupCall,
  getActiveGroupCall,
} from "@/api/endpoints/groupCalls";
import { useGroupCall } from "@/hooks/useGroupCall";
import type {
  GroupCallParticipant,
  GroupCallMediaStatus,
} from "@/api/types";

// ─── Props ────────────────────────────────────────────────────────

interface GroupCallButtonProps {
  conversationId: string;
  userId: string;
  isGroup: boolean;
}

interface GroupCallOverlayProps {
  callId: string;
  userId: string;
  conversationId: string;
  /** "audio" | "video" — controls whether a camera track is acquired. */
  mode?: "audio" | "video";
  onClose: () => void;
}

// ─── Start Call Button ────────────────────────────────────────────

export function GroupCallButton({ conversationId, userId, isGroup }: GroupCallButtonProps) {
  const queryClient = useQueryClient();
  const [activeCallId, setActiveCallId] = React.useState<string | null>(null);
  const [inCall, setInCall] = React.useState(false);

  // Poll for active call
  const { data: activeData } = useQuery({
    queryKey: ["group-call-active", conversationId],
    queryFn: () => getActiveGroupCall(conversationId),
    refetchInterval: 5000,
    enabled: isGroup,
  });

  React.useEffect(() => {
    if (activeData?.active && activeData.call_id) {
      setActiveCallId(activeData.call_id);
    } else {
      setActiveCallId(null);
      setInCall(false);
    }
  }, [activeData]);

  const createMut = useMutation({
    mutationFn: () => createGroupCall({ conversation_id: conversationId, mode: "video" }),
    onSuccess: (data) => {
      setActiveCallId(data.call_id);
      // Mount the overlay; useGroupCall performs the actual join (reading the
      // topology mode + ICE servers from the join response).
      setInCall(true);
      queryClient.invalidateQueries({ queryKey: ["group-call-active", conversationId] });
      toast.success("Group call started");
    },
    onError: (err: Error & { response?: { data?: { detail?: string } } }) => {
      toast.error(err.response?.data?.detail || "Failed to start call");
    },
  });

  // Joining simply mounts the overlay; the useGroupCall hook drives the join +
  // WebRTC setup so the join response's `mode`/`ice_servers` are not discarded.
  const handleJoin = () => {
    setInCall(true);
    toast.success("Joined group call");
  };

  if (!isGroup) return null;

  return (
    <>
      {/* Start or Join button in header */}
      {!activeCallId ? (
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8 shrink-0"
          onClick={() => createMut.mutate()}
          disabled={createMut.isPending}
          aria-label="Start group call"
          data-testid="start-group-call"
        >
          <Video className="h-4 w-4" />
        </Button>
      ) : !inCall ? (
        <Button
          variant="default"
          size="sm"
          className="shrink-0 bg-green-600 hover:bg-green-700 text-white"
          onClick={handleJoin}
          aria-label="Join group call"
          data-testid="join-group-call"
        >
          <Phone className="mr-1.5 h-4 w-4" />
          Join Call
        </Button>
      ) : null}

      {/* Active call banner */}
      {activeCallId && !inCall && (
        <div className="absolute left-0 right-0 top-[57px] z-10 flex items-center justify-between bg-green-600 px-4 py-2 text-sm text-white">
          <span className="flex items-center gap-2">
            <Phone className="h-4 w-4 animate-pulse" />
            Active group call
            {activeData?.current_participant_count != null && (
              <span className="text-green-100">
                ({activeData.current_participant_count} participant{activeData.current_participant_count !== 1 ? "s" : ""})
              </span>
            )}
          </span>
          <Button
            variant="ghost"
            size="sm"
            className="text-white hover:bg-green-700"
            onClick={handleJoin}
          >
            Join
          </Button>
        </div>
      )}

      {/* Call overlay */}
      {inCall && activeCallId && (
        <GroupCallOverlay
          callId={activeCallId}
          userId={userId}
          conversationId={conversationId}
          mode="video"
          onClose={() => {
            setInCall(false);
            queryClient.invalidateQueries({ queryKey: ["group-call-active", conversationId] });
          }}
        />
      )}
    </>
  );
}


// ─── Call Overlay ─────────────────────────────────────────────────

function GroupCallOverlay({ callId, userId, conversationId, mode: callKind, onClose }: GroupCallOverlayProps) {
  const queryClient = useQueryClient();
  const [layout, setLayout] = React.useState<"grid" | "speaker">("grid");
  const [localMedia, setLocalMedia] = React.useState<GroupCallMediaStatus>({
    audio: true,
    video: true,
    screen: false,
  });

  const handleEnded = React.useCallback(() => {
    queryClient.invalidateQueries({ queryKey: ["group-call-active", conversationId] });
    onClose();
  }, [queryClient, conversationId, onClose]);

  // Lifecycle + WebRTC media driven by the hook. It reads the topology `mode`
  // and ICE servers from the join response and sets up the peer connection(s).
  const {
    callData,
    mode,
    isCreator,
    activeParticipants,
    localStream,
    remoteStreams,
    join,
    leave,
    end,
    updateMedia,
    isLeaving,
    isEnding,
  } = useGroupCall({
    callId,
    userId,
    callMode: callKind,
    onEnded: handleEnded,
  });

  // Join when the overlay mounts (the button only flips `inCall` to render us).
  const joinedRef = React.useRef(false);
  React.useEffect(() => {
    if (joinedRef.current) return;
    joinedRef.current = true;
    join();
  }, [join]);

  // Toast on natural end (creator ended for all).
  React.useEffect(() => {
    if (callData?.state === "ended") {
      toast.info("Group call ended");
    }
  }, [callData?.state]);

  const leaveMut = {
    mutate: () => {
      toast.info("Left group call");
      leave();
    },
    isPending: isLeaving,
  };

  const endMut = {
    mutate: () => end(),
    isPending: isEnding,
  };

  const toggleAudio = () => {
    const next = !localMedia.audio;
    setLocalMedia((m) => ({ ...m, audio: next }));
    updateMedia({ audio: next });
  };
  const toggleVideo = () => {
    const next = !localMedia.video;
    setLocalMedia((m) => ({ ...m, video: next }));
    updateMedia({ video: next });
  };
  const toggleScreenShare = () => {
    if (localMedia.screen) {
      setLocalMedia((m) => ({ ...m, screen: false }));
      updateMedia({ screen: false });
    } else {
      // Check if someone else is already sharing
      const sharer = activeParticipants.find((p) => p.media_status.screen && p.user_id !== userId);
      if (sharer) {
        toast.error(`${sharer.display_name || sharer.user_id} is already sharing their screen`);
        return;
      }
      setLocalMedia((m) => ({ ...m, screen: true }));
      updateMedia({ screen: true });
    }
  };

  // Determine if anyone is screen sharing for layout purposes
  const screenSharer = activeParticipants.find((p) => p.media_status.screen);
  const effectiveLayout = screenSharer ? "presentation" as const : layout;

  // Resolve the MediaStream for a tile: the local publish for self, the
  // per-participant remote stream (mesh RTCPeerConnection OR LiveKit SFU —
  // both key streams by user_id) for everyone else. null → avatar fallback.
  const streamFor = React.useCallback(
    (participantUserId: string, isLocal: boolean): MediaStream | null => {
      if (isLocal) return localStream ?? null;
      return remoteStreams[participantUserId] ?? null;
    },
    [localStream, remoteStreams],
  );

  // Grid column class based on participant count
  const gridCols =
    activeParticipants.length <= 2
      ? "grid-cols-1 sm:grid-cols-2"
      : activeParticipants.length <= 4
        ? "grid-cols-2"
        : activeParticipants.length <= 6
          ? "grid-cols-2 sm:grid-cols-3"
          : "grid-cols-2 sm:grid-cols-4";

  return (
    <div
      className="fixed inset-0 z-50 flex flex-col bg-gray-900"
      data-testid="group-call-overlay"
    >
      {/* Top bar */}
      <div className="flex items-center justify-between px-4 py-3 text-white">
        <div className="flex items-center gap-2">
          <Users className="h-5 w-5" />
          <span className="text-sm font-medium">
            Group Call - {activeParticipants.length} participant{activeParticipants.length !== 1 ? "s" : ""}
          </span>
          <span className="text-xs text-gray-400">({callData?.mode ?? "video"})</span>
          {mode && (
            <span
              className="rounded bg-gray-700 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-gray-300"
              data-testid="call-mode-indicator"
            >
              {mode}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 text-white hover:bg-gray-700"
            onClick={() => setLayout(layout === "grid" ? "speaker" : "grid")}
            disabled={!!screenSharer}
            aria-label={`Switch to ${layout === "grid" ? "speaker" : "grid"} view`}
          >
            {layout === "grid" ? <LayoutDashboard className="h-4 w-4" /> : <Grid3X3 className="h-4 w-4" />}
          </Button>
        </div>
      </div>

      {/* Participant grid */}
      <div className="flex-1 overflow-auto p-4">
        {effectiveLayout === "presentation" && screenSharer ? (
          <div className="flex h-full gap-3" data-testid="presentation-layout">
            {/* Screen share area: ~80% width */}
            <div className="flex-1 min-w-0 relative">
              <div className="h-full rounded-lg bg-gray-800 flex items-center justify-center">
                <div className="text-center text-gray-400">
                  <MonitorUp className="h-16 w-16 mx-auto mb-2" />
                  <p className="text-sm font-medium">
                    {screenSharer.user_id === userId
                      ? "You are presenting"
                      : `${screenSharer.display_name || screenSharer.user_id} is presenting`}
                  </p>
                </div>
              </div>
            </div>
            {/* Participant sidebar: ~20% width */}
            <div className="w-40 lg:w-48 flex flex-col gap-2 overflow-y-auto">
              {activeParticipants.map((p) => (
                <ParticipantTile
                  key={p.user_id}
                  participant={p}
                  isLocal={p.user_id === userId}
                  stream={streamFor(p.user_id, p.user_id === userId)}
                />
              ))}
            </div>
          </div>
        ) : effectiveLayout === "grid" || layout === "grid" ? (
          <div className={cn("grid gap-3 h-full", gridCols)}>
            {activeParticipants.map((p) => (
              <ParticipantTile
                key={p.user_id}
                participant={p}
                isLocal={p.user_id === userId}
                stream={streamFor(p.user_id, p.user_id === userId)}
              />
            ))}
          </div>
        ) : (
          <div className="flex h-full flex-col gap-3">
            {/* Speaker (first participant or self) */}
            {activeParticipants[0] && (
              <div className="flex-1">
                <ParticipantTile
                  participant={activeParticipants[0]}
                  isLocal={activeParticipants[0].user_id === userId}
                  stream={streamFor(activeParticipants[0].user_id, activeParticipants[0].user_id === userId)}
                  large
                />
              </div>
            )}
            {/* Thumbnail strip */}
            {activeParticipants.length > 1 && (
              <div className="flex gap-2 overflow-x-auto pb-2">
                {activeParticipants.slice(1).map((p) => (
                  <div key={p.user_id} className="w-36 shrink-0">
                    <ParticipantTile
                      participant={p}
                      isLocal={p.user_id === userId}
                      stream={streamFor(p.user_id, p.user_id === userId)}
                    />
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Controls bar */}
      <div className="flex items-center justify-center gap-4 px-4 py-4">
        <Button
          variant="ghost"
          size="icon"
          className={cn(
            "h-12 w-12 rounded-full",
            localMedia.audio ? "bg-gray-700 text-white hover:bg-gray-600" : "bg-red-600 text-white hover:bg-red-700",
          )}
          onClick={toggleAudio}
          aria-label={localMedia.audio ? "Mute microphone" : "Unmute microphone"}
          data-testid="toggle-audio"
        >
          {localMedia.audio ? <Mic className="h-5 w-5" /> : <MicOff className="h-5 w-5" />}
        </Button>

        <Button
          variant="ghost"
          size="icon"
          className={cn(
            "h-12 w-12 rounded-full",
            localMedia.video ? "bg-gray-700 text-white hover:bg-gray-600" : "bg-red-600 text-white hover:bg-red-700",
          )}
          onClick={toggleVideo}
          aria-label={localMedia.video ? "Turn off camera" : "Turn on camera"}
          data-testid="toggle-video"
        >
          {localMedia.video ? <Video className="h-5 w-5" /> : <VideoOff className="h-5 w-5" />}
        </Button>

        <Button
          variant="ghost"
          size="icon"
          className={cn(
            "h-12 w-12 rounded-full",
            localMedia.screen ? "bg-blue-600 text-white hover:bg-blue-700" : "bg-gray-700 text-white hover:bg-gray-600",
          )}
          onClick={toggleScreenShare}
          aria-label={localMedia.screen ? "Stop sharing" : "Share screen"}
          data-testid="toggle-screen-share"
        >
          {localMedia.screen ? <MonitorOff className="h-5 w-5" /> : <Monitor className="h-5 w-5" />}
        </Button>

        <Button
          variant="ghost"
          size="icon"
          className="h-12 w-12 rounded-full bg-red-600 text-white hover:bg-red-700"
          onClick={() => leaveMut.mutate()}
          disabled={leaveMut.isPending}
          aria-label="Leave call"
          data-testid="leave-call"
        >
          <PhoneOff className="h-5 w-5" />
        </Button>

        {isCreator && (
          <Button
            variant="ghost"
            size="icon"
            className="h-12 w-12 rounded-full bg-red-800 text-white hover:bg-red-900"
            onClick={() => endMut.mutate()}
            disabled={endMut.isPending}
            aria-label="End call for all"
            data-testid="end-call-all"
          >
            <X className="h-5 w-5" />
          </Button>
        )}
      </div>
    </div>
  );
}


// ─── Media renderers ──────────────────────────────────────────────

/** Attach a MediaStream to a <video> element (same pattern as direct calls). */
function TileVideo({
  stream,
  muted,
  mirror,
}: {
  stream: MediaStream;
  muted?: boolean;
  mirror?: boolean;
}) {
  const videoRef = React.useRef<HTMLVideoElement>(null);
  React.useEffect(() => {
    if (!videoRef.current) return;
    videoRef.current.srcObject = stream;
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
      className={cn("absolute inset-0 h-full w-full object-cover", mirror && "[transform:scaleX(-1)]")}
    />
  );
}

/** Attach a MediaStream's audio to a hidden <audio> element. */
function TileAudio({ stream }: { stream: MediaStream }) {
  const audioRef = React.useRef<HTMLAudioElement>(null);
  React.useEffect(() => {
    if (!audioRef.current) return;
    audioRef.current.srcObject = stream;
    return () => {
      if (audioRef.current) audioRef.current.srcObject = null;
    };
  }, [stream]);
  return <audio ref={audioRef} autoPlay className="hidden" />;
}

// ─── Participant Tile ─────────────────────────────────────────────

interface ParticipantTileProps {
  participant: GroupCallParticipant;
  isLocal?: boolean;
  large?: boolean;
  /** Live media for this tile (local publish or remote mesh/SFU stream). */
  stream?: MediaStream | null;
}

function ParticipantTile({ participant, isLocal, large, stream }: ParticipantTileProps) {
  const name = participant.display_name || participant.user_id;
  const initials = name.slice(0, 2).toUpperCase();

  // A live stream with a video track drives the real <video>. When video is
  // off (or no track yet) we fall back to the avatar. This is the same for
  // both media paths: mesh RTCPeerConnection streams and LiveKit SFU streams
  // are both plain MediaStreams keyed by user_id.
  const hasVideo =
    !!participant.media_status.video &&
    !!stream &&
    stream.getVideoTracks().length > 0;

  return (
    <div
      className={cn(
        "relative flex items-center justify-center overflow-hidden rounded-lg bg-gray-800",
        large ? "min-h-[300px]" : "aspect-video min-h-[120px]",
      )}
      data-testid={`participant-tile-${participant.user_id}`}
    >
      {/* Avatar (shown when there is no live video for the tile) */}
      {!hasVideo && (
        <Avatar className={cn("border-2 border-gray-600", large ? "h-24 w-24" : "h-16 w-16")}>
          <AvatarFallback className="bg-gray-700 text-white text-lg">{initials}</AvatarFallback>
        </Avatar>
      )}

      {/* Real video (mesh or LiveKit SFU). Muted for the local tile to avoid
          echo; the remote audio tracks in the stream still play. */}
      {hasVideo && (
        <TileVideo stream={stream!} muted={!!isLocal} mirror={!!isLocal} />
      )}

      {/* Remote audio: attach the stream so audio plays even when video is
          off (avatar shown). Local audio is never played back (no echo). */}
      {!isLocal && stream && stream.getAudioTracks().length > 0 && (
        <TileAudio stream={stream} />
      )}

      {/* Name overlay */}
      <div className="absolute bottom-2 left-2 flex items-center gap-1.5 rounded bg-black/60 px-2 py-1">
        <span className="text-xs text-white">{isLocal ? `${name} (You)` : name}</span>
      </div>

      {/* Mic mute indicator */}
      {!participant.media_status.audio && (
        <div className="absolute left-2 top-2 rounded bg-red-600/80 p-1">
          <MicOff className="h-3 w-3 text-white" />
        </div>
      )}

      {/* Screen share indicator */}
      {participant.media_status.screen && (
        <div className="absolute right-2 top-2 rounded bg-blue-600/80 p-1">
          <MonitorUp className="h-3 w-3 text-white" />
        </div>
      )}
    </div>
  );
}
