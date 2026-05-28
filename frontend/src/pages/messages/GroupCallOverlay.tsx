/**
 * Group Call Overlay (CALL-012)
 *
 * Full-screen overlay for group video/audio calls.
 * Renders participant grid, call controls (mute/camera/leave/end),
 * and an active call banner for non-participants.
 *
 * NOTE: No actual WebRTC peer connections — this is the call state
 * management UI only. WebRTC media is a separate concern.
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
  joinGroupCall,
  leaveGroupCall,
  endGroupCall,
  getGroupCall,
  getActiveGroupCall,
  updateGroupCallMedia,
} from "@/api/endpoints/groupCalls";
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
      setInCall(true);
      queryClient.invalidateQueries({ queryKey: ["group-call-active", conversationId] });
      toast.success("Group call started");
    },
    onError: (err: Error & { response?: { data?: { detail?: string } } }) => {
      toast.error(err.response?.data?.detail || "Failed to start call");
    },
  });

  const joinMut = useMutation({
    mutationFn: (callId: string) => joinGroupCall(callId),
    onSuccess: () => {
      setInCall(true);
      toast.success("Joined group call");
    },
    onError: (err: Error & { response?: { data?: { detail?: string } } }) => {
      toast.error(err.response?.data?.detail || "Failed to join call");
    },
  });

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
          onClick={() => joinMut.mutate(activeCallId)}
          disabled={joinMut.isPending}
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
            onClick={() => joinMut.mutate(activeCallId)}
            disabled={joinMut.isPending}
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

function GroupCallOverlay({ callId, userId, conversationId, onClose }: GroupCallOverlayProps) {
  const queryClient = useQueryClient();
  const [layout, setLayout] = React.useState<"grid" | "speaker">("grid");
  const [localMedia, setLocalMedia] = React.useState<GroupCallMediaStatus>({
    audio: true,
    video: true,
    screen: false,
  });

  // Poll call state
  const { data: callData } = useQuery({
    queryKey: ["group-call", callId],
    queryFn: () => getGroupCall(callId),
    refetchInterval: 3000,
  });

  // Auto-close if call ended
  React.useEffect(() => {
    if (callData?.state === "ended") {
      toast.info("Group call ended");
      onClose();
    }
  }, [callData?.state, onClose]);

  const leaveMut = useMutation({
    mutationFn: () => leaveGroupCall(callId),
    onSuccess: () => {
      toast.info("Left group call");
      queryClient.invalidateQueries({ queryKey: ["group-call-active", conversationId] });
      onClose();
    },
  });

  const endMut = useMutation({
    mutationFn: () => endGroupCall(callId),
    onSuccess: (data) => {
      toast.info(`Call ended (${data.duration_seconds}s, ${data.total_participants} participants)`);
      queryClient.invalidateQueries({ queryKey: ["group-call-active", conversationId] });
      onClose();
    },
    onError: (err: Error & { response?: { data?: { detail?: string } } }) => {
      toast.error(err.response?.data?.detail || "Failed to end call");
    },
  });

  const mediaMut = useMutation({
    mutationFn: (params: { audio?: boolean; video?: boolean; screen?: boolean }) =>
      updateGroupCallMedia(callId, params),
    onSuccess: (data) => {
      setLocalMedia(data.media_status);
    },
  });

  const participants = callData?.participants ?? [];
  const activeParticipants = participants.filter((p) => p.state === "active");
  const isCreator = callData?.creator_user_id === userId;

  const toggleAudio = () => mediaMut.mutate({ audio: !localMedia.audio });
  const toggleVideo = () => mediaMut.mutate({ video: !localMedia.video });
  const toggleScreenShare = () => {
    if (localMedia.screen) {
      mediaMut.mutate({ screen: false });
    } else {
      // Check if someone else is already sharing
      const sharer = activeParticipants.find((p) => p.media_status.screen && p.user_id !== userId);
      if (sharer) {
        toast.error(`${sharer.display_name || sharer.user_id} is already sharing their screen`);
        return;
      }
      mediaMut.mutate({ screen: true });
    }
  };

  // Determine if anyone is screen sharing for layout purposes
  const screenSharer = activeParticipants.find((p) => p.media_status.screen);
  const effectiveLayout = screenSharer ? "presentation" as const : layout;

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
                />
              ))}
            </div>
          </div>
        ) : effectiveLayout === "grid" || layout === "grid" ? (
          <div className={cn("grid gap-3 h-full", gridCols)}>
            {activeParticipants.map((p) => (
              <ParticipantTile key={p.user_id} participant={p} isLocal={p.user_id === userId} />
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
                  large
                />
              </div>
            )}
            {/* Thumbnail strip */}
            {activeParticipants.length > 1 && (
              <div className="flex gap-2 overflow-x-auto pb-2">
                {activeParticipants.slice(1).map((p) => (
                  <div key={p.user_id} className="w-36 shrink-0">
                    <ParticipantTile participant={p} isLocal={p.user_id === userId} />
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
          disabled={mediaMut.isPending}
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


// ─── Participant Tile ─────────────────────────────────────────────

interface ParticipantTileProps {
  participant: GroupCallParticipant;
  isLocal?: boolean;
  large?: boolean;
}

function ParticipantTile({ participant, isLocal, large }: ParticipantTileProps) {
  const name = participant.display_name || participant.user_id;
  const initials = name.slice(0, 2).toUpperCase();

  return (
    <div
      className={cn(
        "relative flex items-center justify-center rounded-lg bg-gray-800",
        large ? "min-h-[300px]" : "aspect-video min-h-[120px]",
      )}
      data-testid={`participant-tile-${participant.user_id}`}
    >
      {/* Avatar (shown when video is off) */}
      {!participant.media_status.video && (
        <Avatar className={cn("border-2 border-gray-600", large ? "h-24 w-24" : "h-16 w-16")}>
          <AvatarFallback className="bg-gray-700 text-white text-lg">{initials}</AvatarFallback>
        </Avatar>
      )}

      {/* Video placeholder (would be <video> element in real impl) */}
      {participant.media_status.video && (
        <div className="flex items-center justify-center text-gray-500">
          <Video className={cn(large ? "h-12 w-12" : "h-8 w-8")} />
        </div>
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
