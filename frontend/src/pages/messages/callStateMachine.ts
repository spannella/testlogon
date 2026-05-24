import type { DirectCallMode } from "@/api/endpoints/messaging";
import type { CallUiState } from "./CallSessionOverlay";

export type CallRole = "caller" | "callee";

export interface CallMachineState {
  phase: CallUiState;
  role: CallRole | null;
  mode: DirectCallMode;
  callId?: string;
  peerName: string;
  reasonMessage?: string;
  retryCount: number;
  maxRetries: number;
  isOnline: boolean;
  isTabVisible: boolean;
}

export type CallMachineEvent =
  | { type: "START_OUTGOING"; mode: DirectCallMode; peerName: string }
  | { type: "OUTGOING_RINGING"; callId: string }
  | { type: "INCOMING_INVITE"; mode: DirectCallMode; peerName: string; callId?: string }
  | { type: "LOCAL_ACCEPT" }
  | { type: "REMOTE_ACCEPT" }
  | { type: "REMOTE_DECLINE"; reason?: "declined" | "busy" | "timeout"; message?: string }
  | { type: "CONNECT" }
  | { type: "CONNECTION_LOST"; message?: string }
  | { type: "RECONNECT_ATTEMPT" }
  | { type: "NETWORK_OFFLINE" }
  | { type: "NETWORK_ONLINE" }
  | { type: "TAB_HIDDEN" }
  | { type: "TAB_VISIBLE" }
  | { type: "END_LOCAL" }
  | { type: "END_REMOTE"; message?: string }
  | { type: "FAIL"; message?: string }
  | { type: "RESET" };

export const createInitialCallMachineState = (): CallMachineState => ({
  phase: "idle",
  role: null,
  mode: "audio",
  peerName: "",
  retryCount: 0,
  maxRetries: 2,
  isOnline: true,
  isTabVisible: true,
});

const withPhase = (state: CallMachineState, phase: CallUiState, patch?: Partial<CallMachineState>): CallMachineState => ({
  ...state,
  ...patch,
  phase,
});

export function callStateReducer(state: CallMachineState, event: CallMachineEvent): CallMachineState {
  switch (event.type) {
    case "START_OUTGOING": {
      if (state.phase !== "idle") return state;
      return withPhase(state, "outgoing_inviting", {
        role: "caller",
        mode: event.mode,
        peerName: event.peerName,
        reasonMessage: undefined,
        retryCount: 0,
      });
    }
    case "OUTGOING_RINGING": {
      if (!["outgoing_inviting", "outgoing_ringing"].includes(state.phase)) return state;
      return withPhase(state, "outgoing_ringing", { callId: event.callId, reasonMessage: undefined });
    }
    case "INCOMING_INVITE": {
      if (state.phase !== "idle") return state;
      return withPhase(state, "incoming_ringing", {
        role: "callee",
        mode: event.mode,
        peerName: event.peerName,
        callId: event.callId,
        reasonMessage: undefined,
      });
    }
    case "LOCAL_ACCEPT": {
      if (state.phase !== "incoming_ringing") return state;
      return withPhase(state, "outgoing_connecting", { reasonMessage: undefined });
    }
    case "REMOTE_ACCEPT": {
      if (!["outgoing_ringing", "outgoing_connecting", "reconnecting"].includes(state.phase)) return state;
      return withPhase(state, "connected", { reasonMessage: undefined, retryCount: 0 });
    }
    case "CONNECT": {
      if (!["outgoing_connecting", "reconnecting"].includes(state.phase)) return state;
      return withPhase(state, "connected", { reasonMessage: undefined, retryCount: 0 });
    }
    case "REMOTE_DECLINE": {
      if (!["incoming_ringing", "outgoing_inviting", "outgoing_ringing", "outgoing_connecting", "reconnecting"].includes(state.phase)) return state;
      if (event.reason === "busy") return withPhase(state, "busy", { reasonMessage: event.message ?? "User is busy on another call." });
      if (event.reason === "timeout") return withPhase(state, "timeout", { reasonMessage: event.message ?? "Call timed out with no answer." });
      return withPhase(state, "declined", { reasonMessage: event.message ?? "Call declined." });
    }
    case "CONNECTION_LOST": {
      if (!["connected", "outgoing_connecting", "outgoing_ringing"].includes(state.phase)) return state;
      return withPhase(state, "reconnecting", { reasonMessage: event.message ?? "Connection interrupted." });
    }
    case "RECONNECT_ATTEMPT": {
      if (state.phase !== "reconnecting") return state;
      if (!state.isOnline || !state.isTabVisible || state.retryCount >= state.maxRetries) {
        return withPhase(state, "failure", { reasonMessage: "Call failed to reconnect." });
      }
      return withPhase(state, "outgoing_connecting", { retryCount: state.retryCount + 1, reasonMessage: "Reconnecting…" });
    }
    case "NETWORK_OFFLINE": {
      const next = { ...state, isOnline: false };
      if (["connected", "outgoing_connecting", "outgoing_ringing"].includes(state.phase)) {
        return withPhase(next, "reconnecting", { reasonMessage: "Waiting for network…" });
      }
      return next;
    }
    case "NETWORK_ONLINE": {
      const next = { ...state, isOnline: true };
      if (state.phase === "reconnecting" && state.isTabVisible) {
        return withPhase(next, "outgoing_connecting", { reasonMessage: "Reconnecting…" });
      }
      return next;
    }
    case "TAB_HIDDEN": {
      return { ...state, isTabVisible: false };
    }
    case "TAB_VISIBLE": {
      if (state.phase === "reconnecting" && state.isOnline) {
        return withPhase({ ...state, isTabVisible: true }, "outgoing_connecting", { reasonMessage: "Reconnecting…" });
      }
      return { ...state, isTabVisible: true };
    }
    case "END_LOCAL": {
      if (state.phase === "idle") return state;
      return withPhase(state, "ended", { reasonMessage: "Call ended." });
    }
    case "END_REMOTE": {
      if (state.phase === "idle") return state;
      return withPhase(state, "ended", { reasonMessage: event.message ?? "Call ended." });
    }
    case "FAIL": {
      if (state.phase === "idle") return state;
      return withPhase(state, "failure", { reasonMessage: event.message ?? "Call failed to connect." });
    }
    case "RESET": {
      if (!["declined", "busy", "timeout", "ended", "failure"].includes(state.phase)) return state;
      return createInitialCallMachineState();
    }
    default:
      return state;
  }
}

export interface CallRuntimeResources {
  peerConnection?: RTCPeerConnection | null;
  localStream?: MediaStream | null;
  remoteStream?: MediaStream | null;
  detachListeners?: Array<() => void>;
  teardownTimers?: Array<number>;
  cleanedUp?: boolean;
}

export function teardownCallResources(resources?: CallRuntimeResources | null): void {
  if (!resources || resources.cleanedUp) return;

  for (const timerId of resources.teardownTimers ?? []) {
    window.clearTimeout(timerId);
  }

  for (const detach of resources.detachListeners ?? []) {
    try {
      detach();
    } catch {
      // no-op cleanup best effort
    }
  }

  for (const stream of [resources.localStream, resources.remoteStream]) {
    for (const track of stream?.getTracks() ?? []) {
      track.stop();
    }
  }

  resources.peerConnection?.close();
  resources.cleanedUp = true;
}
