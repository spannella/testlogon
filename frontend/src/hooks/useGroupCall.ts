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
 *  - SFU (LiveKit): when the join response advertises sfu_provider="livekit",
 *    the platform's existing LiveKit SFU (shared with audio rooms) handles
 *    selective forwarding + simulcast. This hook fetches a LiveKit join token
 *    and exposes it (livekit) so the call surface can connect with the
 *    LiveKit client SDK. NOTE: the browser LiveKit SDK (livekit-client) is not
 *    yet a web dependency, so web media over LiveKit is SEAM-NOT-LIVE — the
 *    token + URL are real; the connect step is the remaining wiring. We do NOT
 *    fake mesh-as-SFU. See sfuStatus below and GAP-0017-sfu.
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
  getGroupCallLiveKitToken,
} from "@/api/endpoints/groupCalls";
import { acquireLocalMedia } from "@/lib/webrtc";
import {
  connectGroupCallLiveKit,
  type GroupCallLiveKitSession,
} from "@/lib/groupCallLiveKit";
import type { GroupCallOut, GroupCallParticipant } from "@/api/types";

export type GroupCallMode = "mesh" | "sfu";

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
  /** SFU provider when mode==="sfu" (e.g. "livekit"); null for mesh. */
  sfuProvider: string | null;
  /**
   * LiveKit connection material when sfu_provider==="livekit" and a token was
   * minted. url+token+room are REAL; a call surface with the livekit-client
   * SDK can connect. null when not applicable or the token fetch failed.
   */
  livekit: { url: string; token: string; room: string } | null;
  /**
   * SFU media status. "na" (mesh path), "connecting" (fetching token),
   * "seam" (token minted but not yet connecting), "connected" (LiveKit Room
   * connected — real media flowing), "unavailable" (LiveKit not configured/
   * failed → the server returned mesh or 503).
   */
  sfuStatus: "na" | "connecting" | "connected" | "seam" | "unavailable";
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
  const [sfuProvider, setSfuProvider] = React.useState<string | null>(null);
  const [livekit, setLivekit] = React.useState<{ url: string; token: string; room: string } | null>(null);
  const [sfuStatus, setSfuStatus] = React.useState<
    "na" | "connecting" | "connected" | "seam" | "unavailable"
  >("na");

  // Stable callback ref so effects don't re-run when the caller passes a new fn.
  const onEndedRef = React.useRef(onEnded);
  onEndedRef.current = onEnded;

  // One RTCPeerConnection per remote peer (mesh), or a single SFU peer.
  const peersRef = React.useRef<Map<string, RTCPeerConnection>>(new Map());
  const localStreamRef = React.useRef<MediaStream | null>(null);
  // Live LiveKit session (SFU path). null on the mesh path.
  const livekitSessionRef = React.useRef<GroupCallLiveKitSession | null>(null);
  // Current local media intent (audio/video on?). Seeded from callMode and
  // kept in sync by updateMedia so a LiveKit connect publishes the right
  // tracks and toggles route to the SFU session.
  const mediaStateRef = React.useRef<{ audio: boolean; video: boolean }>({
    audio: true,
    video: callMode === "video",
  });

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
    // Disconnect the LiveKit session (SFU path) if one is live.
    if (livekitSessionRef.current) {
      void livekitSessionRef.current.disconnect();
      livekitSessionRef.current = null;
    }
    setLocalStream(null);
    setRemoteStreams({});
    setLivekit(null);
    setSfuStatus("na");
    setSfuProvider(null);
  }, []);

  // ── Join (reads mode + ICE servers from the response) ──────────────
  const joinMut = useMutation({
    mutationFn: () => joinGroupCall(callId),
    onSuccess: async (resp) => {
      const resolvedMode = toGroupCallMode(resp.mode ?? resp.signaling?.mode);
      const resolvedIce = toIceServers(resp.signaling?.ice_servers);
      const provider = resp.signaling?.sfu_provider ?? null;
      setMode(resolvedMode);
      setIceServers(resolvedIce);
      setSfuProvider(provider);
      setInCall(true);

      // SFU via LiveKit: fetch a real join token. The token + URL are honest
      // (server mints against the shared LiveKit deployment). We do NOT open a
      // hand-rolled peer pretending to be an SFU.
      if (resolvedMode === "sfu" && provider === "livekit") {
        setSfuStatus("connecting");
        try {
          const tok = await getGroupCallLiveKitToken(callId);
          if (tok?.token && tok?.url) {
            setLivekit({ url: tok.url, token: tok.token, room: tok.room_name });
            // Real browser media leg: connect the LiveKit Room and publish
            // mic/camera honoring the current mute/camera state. Remote
            // tracks arrive keyed by participant identity (== user_id) and
            // merge into remoteStreams, reusing the mesh render contract.
            const session = await connectGroupCallLiveKit(
              tok.url,
              tok.token,
              { audio: mediaStateRef.current.audio, video: mediaStateRef.current.video },
              {
                onRemoteStream: (identity, stream) => {
                  if (identity === userId) return; // never overwrite self-tile
                  if (stream) setRemoteStream(identity, stream);
                  else removeRemoteStream(identity);
                },
                onPhase: (phase) => {
                  if (phase === "connected") setSfuStatus("connected");
                  else if (phase === "connecting" || phase === "reconnecting")
                    setSfuStatus("connecting");
                  else if (phase === "failed") setSfuStatus("unavailable");
                  // "disconnected" during an active call: leave/teardown owns
                  // the terminal state; a transient drop is followed by
                  // "reconnecting"/"connected" above.
                },
              },
            );
            livekitSessionRef.current = session;
            if (import.meta.env.DEV) {
              (window as unknown as Record<string, unknown>).__groupCallLiveKit = session;
            }
          } else {
            setSfuStatus("unavailable");
          }
        } catch {
          // 503 LIVEKIT_NOT_CONFIGURED / SDK unavailable / connect failed.
          // Do NOT fabricate media: surface the honest unavailable state.
          setLivekit(null);
          if (livekitSessionRef.current) {
            void livekitSessionRef.current.disconnect();
            livekitSessionRef.current = null;
          }
          setSfuStatus("unavailable");
        }
      } else {
        setSfuStatus("na");
      }

      // Acquire local media for the MESH path. On the LiveKit path the SFU
      // session acquires + publishes its own devices, so we skip this to
      // avoid grabbing the camera twice. Failures (no camera, denied
      // permission) are non-fatal — the call still proceeds receive-only.
      if (!(resolvedMode === "sfu" && provider === "livekit")) {
        try {
          const stream = await acquireLocalMedia(callMode);
          localStreamRef.current = stream;
          setLocalStream(stream);
        } catch {
          localStreamRef.current = null;
        }
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
      // Track the current intent for a (re)publish / late LiveKit connect.
      if (typeof update.audio === "boolean") mediaStateRef.current.audio = update.audio;
      if (typeof update.video === "boolean") mediaStateRef.current.video = update.video;

      // SFU (LiveKit) path: toggle publish on the live session.
      const session = livekitSessionRef.current;
      if (session) {
        if (typeof update.audio === "boolean") void session.setMicrophoneEnabled(update.audio);
        if (typeof update.video === "boolean") void session.setCameraEnabled(update.video);
        if (typeof update.screen === "boolean") void session.setScreenShareEnabled(update.screen);
        return;
      }

      // MESH path: reflect mute/unmute on the local upstream tracks so peers
      // stop/resume receiving immediately (the REST call only updates
      // server-side status).
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
      // SFU (LiveKit) path. Media is handled by the LiveKit SFU (real
      // selective forwarding + simulcast), NOT by hand-rolled peer
      // connections. The LiveKit join token + URL are fetched at join time
      // and exposed via `livekit` / `sfuStatus`; the call surface connects
      // with the livekit-client SDK.
      //
      // We deliberately do NOT open an RTCPeerConnection here: signaling a
      // raw offer to a non-existent per-call SFU (the previous stub) connects
      // to nothing and would be a fake SFU. When livekit-client is added as a
      // web dependency, the connect happens in the surface component using
      // `livekit.{url,token,room}`. Until then this is SEAM-NOT-LIVE for web
      // media (Android already connects to the same LiveKit deployment for
      // audio rooms via the livekit-android SDK).
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

      // Mesh-only signaling. (SFU/LiveKit media does not use this relay — it
      // is handled by the LiveKit SDK against the LiveKit server.)
      if (mode === "sfu") return;
      const peerKey = senderId;
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
          signal(senderId, "webrtc.answer", {
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
    sfuProvider,
    livekit,
    sfuStatus,
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
