/**
 * useGroupCall — group-call lifecycle + WebRTC media hook (CALL-012, GAP-0017).
 *
 * Previously the group-call lifecycle lived inline inside GroupCallOverlay.tsx
 * and the join response (`mode` + `signaling.ice_servers`) was discarded — no
 * RTCPeerConnection was ever created, so group calls showed participant tiles
 * but transmitted no audio or video.
 *
 * This hook:
 *  - Owns join / leave / end / media-toggle mutations and call-state polling.
 *  - Reads the topology `mode` ("mesh" | "sfu") and the ICE servers from the
 *    join response and uses them to drive the WebRTC peer setup.
 *  - MESH: one RTCPeerConnection per remote participant. The numerically/lex
 *    lower user_id is the offerer (deterministic glare avoidance); SDP + ICE
 *    are exchanged via `sendGroupCallSignal` and the SSE relay.
 *  - SFU: a single upstream RTCPeerConnection to the SFU. The offer is sent to
 *    the SFU and downstream tracks arrive on the same connection. Full
 *    simulcast/track-routing is a larger effort — see TODO(GAP-0017-sfu).
 *  - Exposes `mode`, the local stream, and remote streams keyed by user_id so
 *    GroupCallOverlay can render real media.
 *
 * Inbound signaling is delivered via the existing SSE bridge as a window
 * "messaging:webrtc-signal" CustomEvent (same channel used by
 * useRtcPeerConnection for direct calls).
 */
import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  getGroupCall,
  joinGroupCall,
  leaveGroupCall,
  endGroupCall,
  updateGroupCallMedia,
  sendGroupCallSignal,
} from "@/api/endpoints/groupCalls";
import { acquireLocalMedia } from "@/lib/webrtc";
import type { GroupCallOut, GroupCallParticipant } from "@/api/types";

export type GroupCallMode = "mesh" | "sfu";

/** Sentinel target id for the single SFU upstream peer connection. */
const SFU_PEER_ID = "__sfu__";

interface UseGroupCallOptions {
  callId: string;
  userId: string;
  /** "audio" | "video" — controls whether a camera track is acquired. */
  callMode?: "audio" | "video";
  /** Called when the call ends, the user leaves, or the creator ends it. */
  onEnded?: () => void;
}

export interface UseGroupCallReturn {
  callData: GroupCallOut | undefined;
  inCall: boolean;
  /** Resolved topology from the join response; null until joined. */
  mode: GroupCallMode | null;
  isCreator: boolean;
  participants: GroupCallParticipant[];
  activeParticipants: GroupCallParticipant[];
  localStream: MediaStream | null;
  /** Remote media streams keyed by participant user_id. */
  remoteStreams: Record<string, MediaStream>;
  join: () => void;
  leave: () => void;
  end: () => void;
  updateMedia: (update: { audio?: boolean; video?: boolean; screen?: boolean }) => void;
  isJoining: boolean;
  isLeaving: boolean;
  isEnding: boolean;
}

function toGroupCallMode(raw: string | undefined): GroupCallMode {
  return raw === "sfu" ? "sfu" : "mesh";
}

function toIceServers(raw: Array<Record<string, string>> | undefined): RTCIceServer[] {
  if (!raw) return [];
  const servers: RTCIceServer[] = [];
  for (const s of raw) {
    const urls = s.urls;
    if (typeof urls !== "string" || urls.length === 0) continue;
    const server: RTCIceServer = { urls };
    if (s.username) server.username = s.username;
    if (s.credential) server.credential = s.credential;
    servers.push(server);
  }
  return servers;
}

export function useGroupCall(options: UseGroupCallOptions): UseGroupCallReturn {
  const { callId, userId, callMode = "video", onEnded } = options;
  const queryClient = useQueryClient();

  const [inCall, setInCall] = React.useState(false);
  const [mode, setMode] = React.useState<GroupCallMode | null>(null);
  const [iceServers, setIceServers] = React.useState<RTCIceServer[]>([]);
  const [localStream, setLocalStream] = React.useState<MediaStream | null>(null);
  const [remoteStreams, setRemoteStreams] = React.useState<Record<string, MediaStream>>({});

  // Stable callback ref so effects don't re-run when the caller passes a new fn.
  const onEndedRef = React.useRef(onEnded);
  onEndedRef.current = onEnded;

  // One RTCPeerConnection per remote peer (mesh), or a single SFU peer.
  const peersRef = React.useRef<Map<string, RTCPeerConnection>>(new Map());
  const localStreamRef = React.useRef<MediaStream | null>(null);

  // ── Call-state polling ─────────────────────────────────────────────
  const { data: callData } = useQuery({
    queryKey: ["group-call", callId],
    queryFn: () => getGroupCall(callId),
    refetchInterval: 3000,
    enabled: inCall,
  });

  // Auto-close when the call ends server-side.
  React.useEffect(() => {
    if (callData?.state === "ended") {
      onEndedRef.current?.();
    }
  }, [callData?.state]);

  // ── Local media + ICE-server config (derived) ──────────────────────
  const iceConfig = React.useMemo<RTCConfiguration>(
    () => ({ iceServers: iceServers.length > 0 ? iceServers : undefined }),
    [iceServers],
  );

  const setRemoteStream = React.useCallback((peerId: string, stream: MediaStream) => {
    setRemoteStreams((prev) => ({ ...prev, [peerId]: stream }));
  }, []);

  const removeRemoteStream = React.useCallback((peerId: string) => {
    setRemoteStreams((prev) => {
      if (!(peerId in prev)) return prev;
      const next = { ...prev };
      delete next[peerId];
      return next;
    });
  }, []);

  /** Send an SDP/ICE signal to a peer (or the SFU) via the relay endpoint. */
  const signal = React.useCallback(
    (targetUserId: string, type: string, payload: Record<string, unknown>) => {
      sendGroupCallSignal(callId, {
        type,
        target_user_id: targetUserId,
        payload,
      }).catch(() => {
        // Best-effort: signaling delivery failures are non-fatal (peer may have
        // left). ICE will retry; the polling loop reconciles participant state.
      });
    },
    [callId],
  );

  /** Create + wire a fresh RTCPeerConnection for a given peer/SFU target. */
  const createPeer = React.useCallback(
    (targetUserId: string): RTCPeerConnection => {
      const pc = new RTCPeerConnection(iceConfig);

      // Attach local tracks (upstream).
      const local = localStreamRef.current;
      if (local) {
        for (const track of local.getTracks()) {
          pc.addTrack(track, local);
        }
      }

      // Downstream tracks → remote stream for this peer.
      const remote = new MediaStream();
      setRemoteStream(targetUserId, remote);
      pc.ontrack = (event) => {
        const tracks = event.streams[0]?.getTracks() ?? [event.track];
        for (const track of tracks) remote.addTrack(track);
        setRemoteStream(targetUserId, remote);
      };

      pc.onicecandidate = (event) => {
        if (event.candidate) {
          signal(targetUserId, "webrtc.ice_candidate", {
            candidate: event.candidate.candidate,
            sdpMid: event.candidate.sdpMid,
            sdpMLineIndex: event.candidate.sdpMLineIndex,
            usernameFragment: event.candidate.usernameFragment,
          });
        }
      };

      pc.onconnectionstatechange = () => {
        if (pc.connectionState === "failed" || pc.connectionState === "closed") {
          removeRemoteStream(targetUserId);
        }
      };

      peersRef.current.set(targetUserId, pc);

      // Dev-mode testability: expose the live peer map for E2E inspection.
      if (import.meta.env.DEV) {
        (window as unknown as Record<string, unknown>).__groupCallPeers = peersRef.current;
        (window as unknown as Record<string, unknown>).__groupCallMode = mode;
      }

      return pc;
    },
    [iceConfig, mode, removeRemoteStream, setRemoteStream, signal],
  );

  /** Tear down a single peer connection. */
  const closePeer = React.useCallback(
    (targetUserId: string) => {
      const pc = peersRef.current.get(targetUserId);
      if (pc) {
        pc.onicecandidate = null;
        pc.ontrack = null;
        pc.onconnectionstatechange = null;
        pc.close();
        peersRef.current.delete(targetUserId);
      }
      removeRemoteStream(targetUserId);
    },
    [removeRemoteStream],
  );

  /** Tear down all peers + local media. */
  const teardown = React.useCallback(() => {
    for (const pc of peersRef.current.values()) {
      pc.onicecandidate = null;
      pc.ontrack = null;
      pc.onconnectionstatechange = null;
      pc.close();
    }
    peersRef.current.clear();
    const local = localStreamRef.current;
    if (local) {
      local.getTracks().forEach((t) => t.stop());
      localStreamRef.current = null;
    }
    setLocalStream(null);
    setRemoteStreams({});
  }, []);

  // ── Join (reads mode + ICE servers from the response) ──────────────
  const joinMut = useMutation({
    mutationFn: () => joinGroupCall(callId),
    onSuccess: async (resp) => {
      const resolvedMode = toGroupCallMode(resp.mode ?? resp.signaling?.mode);
      const resolvedIce = toIceServers(resp.signaling?.ice_servers);
      setMode(resolvedMode);
      setIceServers(resolvedIce);
      setInCall(true);

      // Acquire local media once. Failures (no camera, denied permission) are
      // non-fatal — the call still proceeds receive-only.
      try {
        const stream = await acquireLocalMedia(callMode);
        localStreamRef.current = stream;
        setLocalStream(stream);
      } catch {
        localStreamRef.current = null;
      }

      if (import.meta.env.DEV) {
        (window as unknown as Record<string, unknown>).__groupCallMode = resolvedMode;
      }

      queryClient.invalidateQueries({ queryKey: ["group-call", callId] });
    },
  });

  const leaveMut = useMutation({
    mutationFn: () => leaveGroupCall(callId),
    onSuccess: () => {
      setInCall(false);
      teardown();
      onEndedRef.current?.();
    },
  });

  const endMut = useMutation({
    mutationFn: () => endGroupCall(callId),
    onSuccess: () => {
      setInCall(false);
      teardown();
      onEndedRef.current?.();
    },
  });

  const mediaMut = useMutation({
    mutationFn: (update: { audio?: boolean; video?: boolean; screen?: boolean }) =>
      updateGroupCallMedia(callId, update),
    onSuccess: (_data, update) => {
      // Reflect mute/unmute on the local upstream tracks so peers stop/resume
      // receiving immediately (the REST call only updates server-side status).
      const local = localStreamRef.current;
      if (local) {
        if (typeof update.audio === "boolean") {
          local.getAudioTracks().forEach((t) => (t.enabled = update.audio!));
        }
        if (typeof update.video === "boolean") {
          local.getVideoTracks().forEach((t) => (t.enabled = update.video!));
        }
      }
    },
  });

  // ── Mesh: open/close peer connections as participants come and go ───
  const participants = React.useMemo(
    () => callData?.participants ?? [],
    [callData?.participants],
  );
  const activeParticipants = React.useMemo(
    () => participants.filter((p) => p.state === "active"),
    [participants],
  );

  React.useEffect(() => {
    if (!inCall || mode === null) return;

    if (mode === "sfu") {
      // Single upstream connection to the SFU. Create once.
      // TODO(GAP-0017-sfu): full SFU media (downstream track routing per
      // participant, simulcast layers) requires server-side SFU support. For
      // now we establish the single upstream peer so the join response actually
      // drives a connection.
      if (!peersRef.current.has(SFU_PEER_ID)) {
        const pc = createPeer(SFU_PEER_ID);
        (async () => {
          try {
            const offer = await pc.createOffer();
            await pc.setLocalDescription(offer);
            signal(SFU_PEER_ID, "webrtc.offer", { sdp: offer.sdp, type: offer.type });
          } catch {
            /* offer creation failed — connection-state handler will clean up */
          }
        })();
      }
      return;
    }

    // MESH: one connection per *other* active participant.
    const otherIds = new Set(
      activeParticipants.map((p) => p.user_id).filter((id) => id !== userId),
    );

    // Open connections to new peers (deterministic offerer = lower user_id).
    for (const peerId of otherIds) {
      if (peersRef.current.has(peerId)) continue;
      const isOfferer = userId < peerId;
      const pc = createPeer(peerId);
      if (isOfferer) {
        (async () => {
          try {
            const offer = await pc.createOffer();
            await pc.setLocalDescription(offer);
            signal(peerId, "webrtc.offer", { sdp: offer.sdp, type: offer.type });
          } catch {
            /* offer creation failed — connection-state handler will clean up */
          }
        })();
      }
      // Non-offerer waits for the inbound offer via the signaling handler below.
    }

    // Close connections to peers who have left.
    for (const peerId of Array.from(peersRef.current.keys())) {
      if (peerId === SFU_PEER_ID) continue;
      if (!otherIds.has(peerId)) closePeer(peerId);
    }
  }, [inCall, mode, activeParticipants, userId, createPeer, closePeer, signal]);

  // ── Inbound signaling (SSE → window event) ─────────────────────────
  React.useEffect(() => {
    if (!inCall) return;

    const handler = async (event: Event) => {
      const detail = (event as CustomEvent<Record<string, unknown>>).detail ?? {};
      if (detail.call_id !== callId) return;
      if (detail.sender_user_id === userId) return;

      const senderId = String(detail.sender_user_id ?? "");
      if (!senderId) return;

      const eventType = String(detail.event_type ?? detail.type ?? "");
      const payload = (detail.payload ?? {}) as Record<string, unknown>;

      // For SFU mode, all inbound signals route through the single SFU peer.
      const peerKey = mode === "sfu" ? SFU_PEER_ID : senderId;
      let pc = peersRef.current.get(peerKey);

      try {
        if (eventType === "webrtc.offer") {
          // Mesh non-offerer (or SFU) receives an offer → answer.
          if (!pc) pc = createPeer(peerKey);
          await pc.setRemoteDescription(
            new RTCSessionDescription({
              type: "offer",
              sdp: typeof payload.sdp === "string" ? payload.sdp : "",
            }),
          );
          const answer = await pc.createAnswer();
          await pc.setLocalDescription(answer);
          signal(peerKey === SFU_PEER_ID ? SFU_PEER_ID : senderId, "webrtc.answer", {
            sdp: answer.sdp,
            type: answer.type,
          });
        } else if (eventType === "webrtc.answer") {
          if (!pc) return;
          await pc.setRemoteDescription(
            new RTCSessionDescription({
              type: "answer",
              sdp: typeof payload.sdp === "string" ? payload.sdp : "",
            }),
          );
        } else if (eventType === "webrtc.ice_candidate") {
          if (!pc) return;
          await pc.addIceCandidate(
            new RTCIceCandidate({
              candidate: typeof payload.candidate === "string" ? payload.candidate : "",
              sdpMid: typeof payload.sdpMid === "string" ? payload.sdpMid : null,
              sdpMLineIndex:
                typeof payload.sdpMLineIndex === "number" ? payload.sdpMLineIndex : null,
              usernameFragment:
                typeof payload.usernameFragment === "string"
                  ? payload.usernameFragment
                  : undefined,
            }),
          );
        }
      } catch (err) {
        console.warn("[useGroupCall] signaling error:", err);
      }
    };

    window.addEventListener("messaging:webrtc-signal", handler as EventListener);
    return () => {
      window.removeEventListener("messaging:webrtc-signal", handler as EventListener);
    };
  }, [inCall, callId, userId, mode, createPeer, signal]);

  // ── Teardown on unmount ────────────────────────────────────────────
  React.useEffect(() => {
    return () => teardown();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const isCreator = callData?.creator_user_id === userId;

  return {
    callData,
    inCall,
    mode,
    isCreator,
    participants,
    activeParticipants,
    localStream,
    remoteStreams,
    join: joinMut.mutate,
    leave: leaveMut.mutate,
    end: endMut.mutate,
    updateMedia: mediaMut.mutate,
    isJoining: joinMut.isPending,
    isLeaving: leaveMut.isPending,
    isEnding: endMut.isPending,
  };
}
