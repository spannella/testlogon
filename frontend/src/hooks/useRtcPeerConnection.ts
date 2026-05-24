/**
 * useRtcPeerConnection — manages the full RTCPeerConnection lifecycle for
 * direct (1-on-1) calls. Bridges the call state machine to real WebRTC
 * offer/answer exchange, ICE candidate trickle, and media stream management.
 */
import * as React from "react";
import type { CallRole } from "@/pages/messages/callStateMachine";
import type { CallRuntimeResources } from "@/pages/messages/callStateMachine";
import { teardownCallResources } from "@/pages/messages/callStateMachine";
import type { CallUiState } from "@/pages/messages/CallSessionOverlay";
import type { DirectCallMode, SignalingPayload } from "@/api/endpoints/messaging";
import { fetchTurnCredentials, sendSignalingEvent } from "@/api/endpoints/messaging";
import { acquireLocalMedia, createIceCandidateBuffer, generateNonce, generateEventId } from "@/lib/webrtc";

export interface UseRtcPeerConnectionParams {
  callId: string | undefined;
  conversationId: string;
  role: CallRole | null;
  mode: DirectCallMode;
  phase: CallUiState;
  peerId: string;
  userId: string;
  enabled: boolean;
  onConnect: () => void;
  onConnectionLost: (msg?: string) => void;
  onFail: (msg?: string) => void;
}

export interface UseRtcPeerConnectionReturn {
  localStream: MediaStream | null;
  remoteStream: MediaStream | null;
  resources: CallRuntimeResources | null;
  connectionState: RTCPeerConnectionState | null;
}

/**
 * Determines whether the hook should activate peer connection setup.
 *
 * Activation phases:
 * - Caller: "outgoing_ringing" — creates PC and sends offer proactively so the
 *   callee receives it immediately upon accepting. The state machine's REMOTE_ACCEPT
 *   event (from SSE "call.accept") transitions the caller directly to "connected".
 *   The hook keeps the PC alive through connected state to handle answer/ICE.
 * - Callee: "outgoing_connecting" — creates PC and waits for the offer via SSE.
 *   When ICE completes (pc.connectionState === "connected"), dispatches CONNECT
 *   to transition the state machine from outgoing_connecting to connected.
 * - Reconnect: "outgoing_connecting" (after a reconnect attempt) — restarts ICE.
 */
function shouldActivate(phase: CallUiState, role: CallRole | null): boolean {
  if (role === "caller") {
    return phase === "outgoing_ringing" || phase === "outgoing_connecting" || phase === "connected";
  }
  if (role === "callee") {
    return phase === "outgoing_connecting" || phase === "connected";
  }
  return false;
}

export function useRtcPeerConnection(params: UseRtcPeerConnectionParams): UseRtcPeerConnectionReturn {
  const {
    callId,
    conversationId,
    role,
    mode,
    phase,
    peerId,
    userId,
    enabled,
    onConnect,
    onConnectionLost,
    onFail,
  } = params;

  const [localStream, setLocalStream] = React.useState<MediaStream | null>(null);
  const [remoteStream, setRemoteStream] = React.useState<MediaStream | null>(null);
  const [connectionState, setConnectionState] = React.useState<RTCPeerConnectionState | null>(null);
  const [resources, setResources] = React.useState<CallRuntimeResources | null>(null);

  // Stable refs for callbacks to avoid re-triggering the effect
  const onConnectRef = React.useRef(onConnect);
  const onConnectionLostRef = React.useRef(onConnectionLost);
  const onFailRef = React.useRef(onFail);
  onConnectRef.current = onConnect;
  onConnectionLostRef.current = onConnectionLost;
  onFailRef.current = onFail;

  // Track whether we've already set up the PC for this call to avoid double-setup
  const setupCallIdRef = React.useRef<string | null>(null);
  const pcRef = React.useRef<RTCPeerConnection | null>(null);

  const activate = enabled && !!callId && shouldActivate(phase, role);

  React.useEffect(() => {
    // Only run setup once per callId (don't re-run when phase transitions within active states)
    if (!activate || !callId || !role) return;
    if (setupCallIdRef.current === callId) return;

    setupCallIdRef.current = callId;

    let aborted = false;
    const detachListeners: Array<() => void> = [];
    const teardownTimers: Array<number> = [];

    async function setup() {
      if (aborted) return;

      // 1. Fetch TURN credentials
      let iceServers: RTCIceServer[] = [];
      try {
        const turnResp = await fetchTurnCredentials(callId!);
        iceServers = turnResp.ice_servers.map((s) => ({
          urls: s.urls,
          username: s.username,
          credential: s.credential,
        }));
      } catch {
        // TURN fetch may fail (feature disabled, etc.) — continue with empty ICE servers
        // (will use STUN/host candidates only, or fail gracefully)
      }
      if (aborted) return;

      // 2. Create RTCPeerConnection
      let pc: RTCPeerConnection;
      try {
        pc = new RTCPeerConnection({
          iceServers: iceServers.length > 0 ? iceServers : undefined,
          // Use unified-plan (default in modern browsers)
        });
      } catch (err) {
        onFailRef.current?.("Failed to create peer connection.");
        return;
      }
      if (aborted) {
        pc.close();
        return;
      }
      pcRef.current = pc;

      // Dev-mode testability: expose the RTCPeerConnection on window for E2E tests
      if (import.meta.env.DEV) {
        (window as unknown as Record<string, unknown>).__rtcPeerConnection = pc;
        (window as unknown as Record<string, unknown>).__rtcLocalStream = null; // will be set below
        (window as unknown as Record<string, unknown>).__rtcRemoteStream = null; // will be set below
      }

      // 3. Acquire local media
      let localMediaStream: MediaStream;
      try {
        localMediaStream = await acquireLocalMedia(mode);
      } catch (err) {
        pc.close();
        const errMsg =
          err instanceof Error && err.name === "NotAllowedError"
            ? "Microphone/camera permission denied."
            : "Failed to access media devices.";
        onFailRef.current?.(errMsg);
        return;
      }
      if (aborted) {
        localMediaStream.getTracks().forEach((t) => t.stop());
        pc.close();
        return;
      }
      setLocalStream(localMediaStream);
      if (import.meta.env.DEV) {
        (window as unknown as Record<string, unknown>).__rtcLocalStream = localMediaStream;
      }

      // 4. Add local tracks to peer connection
      for (const track of localMediaStream.getTracks()) {
        pc.addTrack(track, localMediaStream);
      }

      // 5. Set up remote stream
      const remote = new MediaStream();
      setRemoteStream(remote);
      if (import.meta.env.DEV) {
        (window as unknown as Record<string, unknown>).__rtcRemoteStream = remote;
      }

      pc.ontrack = (event) => {
        const tracks = event.streams[0]?.getTracks() ?? [event.track];
        for (const track of tracks) {
          remote.addTrack(track);
        }
        setRemoteStream(remote); // trigger re-render
      };

      // 6. ICE candidate buffer (for candidates received before remote desc is set)
      const iceBuffer = createIceCandidateBuffer();

      // 7. Connection state monitoring
      pc.onconnectionstatechange = () => {
        setConnectionState(pc.connectionState);
        switch (pc.connectionState) {
          case "connected":
            onConnectRef.current?.();
            break;
          case "disconnected":
            onConnectionLostRef.current?.("Peer connection interrupted.");
            break;
          case "failed":
            onConnectionLostRef.current?.("Peer connection failed.");
            break;
          case "closed":
            // No-op; teardown handles this
            break;
        }
      };

      pc.oniceconnectionstatechange = () => {
        if (pc.iceConnectionState === "failed") {
          // Attempt ICE restart
          try {
            pc.restartIce();
          } catch {
            // Ignore if connection is already closed
          }
        }
      };

      // 8. ICE candidate trickle (outbound)
      pc.onicecandidate = (event) => {
        if (event.candidate && callId) {
          const signalingData: SignalingPayload = {
            type: "webrtc.ice_candidate",
            event_id: generateEventId("ice"),
            conversation_id: conversationId,
            recipient_user_id: peerId,
            nonce: generateNonce(),
            sent_at: Math.floor(Date.now() / 1000),
            payload: {
              candidate: event.candidate.candidate,
              sdpMid: event.candidate.sdpMid,
              sdpMLineIndex: event.candidate.sdpMLineIndex,
              usernameFragment: event.candidate.usernameFragment,
            },
          };
          sendSignalingEvent(callId, signalingData).catch(() => {
            // Best-effort: ICE candidate delivery failures are non-fatal
          });
        }
      };

      // 9. Listen for incoming signaling events via SSE
      const signalingHandler = async (event: Event) => {
        const custom = event as CustomEvent<Record<string, unknown>>;
        const detail = custom.detail ?? {};
        // Only handle events for our call
        if (detail.call_id !== callId) return;
        // Only handle events from the peer (not our own)
        if (detail.sender_user_id === userId) return;

        const eventType = String(detail.event_type ?? "");
        const payload = (detail.payload ?? detail) as Record<string, unknown>;

        if (eventType === "webrtc.offer") {
          // Callee receives offer (or caller receives re-offer during ICE restart)
          try {
            const sdp = typeof payload.sdp === "string" ? payload.sdp : "";
            const type = typeof payload.type === "string" ? payload.type : "offer";
            const remoteOffer = new RTCSessionDescription({ type: type as RTCSdpType, sdp });

            // Handle glare: if we have a local offer pending and we're the polite peer (callee)
            if (pc.signalingState === "have-local-offer" && role === "callee") {
              await pc.setLocalDescription({ type: "rollback" });
            }

            await pc.setRemoteDescription(remoteOffer);
            // Flush buffered ICE candidates now that remote desc is set
            await iceBuffer.flush(pc);

            // Create and send answer
            const answer = await pc.createAnswer();
            await pc.setLocalDescription(answer);

            const answerPayload: SignalingPayload = {
              type: "webrtc.answer",
              event_id: generateEventId("answer"),
              conversation_id: conversationId,
              recipient_user_id: peerId,
              nonce: generateNonce(),
              sent_at: Math.floor(Date.now() / 1000),
              payload: {
                sdp: answer.sdp,
                type: answer.type,
              },
            };
            await sendSignalingEvent(callId!, answerPayload);
          } catch (err) {
            console.warn("[useRtcPeerConnection] Error handling offer:", err);
          }
        } else if (eventType === "webrtc.answer") {
          // Caller receives answer
          try {
            const sdp = typeof payload.sdp === "string" ? payload.sdp : "";
            const type = typeof payload.type === "string" ? payload.type : "answer";
            const remoteAnswer = new RTCSessionDescription({ type: type as RTCSdpType, sdp });
            await pc.setRemoteDescription(remoteAnswer);
            // Flush buffered ICE candidates
            await iceBuffer.flush(pc);
          } catch (err) {
            console.warn("[useRtcPeerConnection] Error handling answer:", err);
          }
        } else if (eventType === "webrtc.ice_candidate") {
          // Remote ICE candidate
          try {
            const candidate: RTCIceCandidateInit = {
              candidate: typeof payload.candidate === "string" ? payload.candidate : "",
              sdpMid: typeof payload.sdpMid === "string" ? payload.sdpMid : null,
              sdpMLineIndex:
                typeof payload.sdpMLineIndex === "number" ? payload.sdpMLineIndex : null,
              usernameFragment:
                typeof payload.usernameFragment === "string" ? payload.usernameFragment : undefined,
            };

            // If remote description not yet set, buffer the candidate
            const buffered = iceBuffer.add(candidate);
            if (buffered === null) {
              // Already flushed — apply immediately
              await pc.addIceCandidate(new RTCIceCandidate(candidate));
            }
          } catch (err) {
            console.warn("[useRtcPeerConnection] Error adding ICE candidate:", err);
          }
        }
      };

      window.addEventListener("messaging:webrtc-signal", signalingHandler as EventListener);
      detachListeners.push(() =>
        window.removeEventListener("messaging:webrtc-signal", signalingHandler as EventListener),
      );
      detachListeners.push(() => { pc.onicecandidate = null; });
      detachListeners.push(() => { pc.ontrack = null; });
      detachListeners.push(() => { pc.onconnectionstatechange = null; });
      detachListeners.push(() => { pc.oniceconnectionstatechange = null; });

      // 10. If caller, create and send offer immediately
      if (role === "caller") {
        try {
          const offer = await pc.createOffer();
          await pc.setLocalDescription(offer);

          const offerPayload: SignalingPayload = {
            type: "webrtc.offer",
            event_id: generateEventId("offer"),
            conversation_id: conversationId,
            recipient_user_id: peerId,
            nonce: generateNonce(),
            sent_at: Math.floor(Date.now() / 1000),
            payload: {
              sdp: offer.sdp,
              type: offer.type,
            },
          };
          await sendSignalingEvent(callId!, offerPayload);
        } catch (err) {
          console.warn("[useRtcPeerConnection] Error creating/sending offer:", err);
          onFailRef.current?.("Failed to create call offer.");
          return;
        }
      }

      // 11. Store resources
      const callResources: CallRuntimeResources = {
        peerConnection: pc,
        localStream: localMediaStream,
        remoteStream: remote,
        detachListeners,
        teardownTimers,
        cleanedUp: false,
      };
      setResources(callResources);
    }

    setup();

    return () => {
      aborted = true;
      // Don't teardown here — let the callMachine phase-change effect handle teardown
      // (so the connection persists across phase transitions like ringing -> connected)
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activate, callId, role]);

  // Teardown when call ends or hook is disabled
  React.useEffect(() => {
    if (!enabled || !callId) {
      // Call ended or hook disabled — teardown if we have resources
      if (resources && !resources.cleanedUp) {
        teardownCallResources(resources);
        setResources(null);
        setLocalStream(null);
        setRemoteStream(null);
        setConnectionState(null);
        setupCallIdRef.current = null;
        pcRef.current = null;
      }
    }
  }, [enabled, callId, resources]);

  // Reset setup tracking when callId changes (new call)
  React.useEffect(() => {
    if (!callId) {
      setupCallIdRef.current = null;
    }
  }, [callId]);

  return {
    localStream,
    remoteStream,
    resources,
    connectionState,
  };
}
