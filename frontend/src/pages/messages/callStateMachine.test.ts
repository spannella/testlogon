import { describe, expect, it, vi } from "vitest";
import { callStateReducer, createInitialCallMachineState, teardownCallResources } from "./callStateMachine";

describe("callStateReducer", () => {
  it("enforces deterministic caller transitions", () => {
    let state = createInitialCallMachineState();
    state = callStateReducer(state, { type: "START_OUTGOING", mode: "audio", peerName: "Peer" });
    state = callStateReducer(state, { type: "OUTGOING_RINGING", callId: "c1" });
    state = callStateReducer(state, { type: "REMOTE_ACCEPT" });
    state = callStateReducer(state, { type: "END_REMOTE" });

    expect(state.phase).toBe("ended");

    const invalid = callStateReducer(state, { type: "REMOTE_ACCEPT" });
    expect(invalid.phase).toBe("ended");
  });

  it("handles reconnect across tab hidden/visible and network offline/online", () => {
    let state = createInitialCallMachineState();
    state = callStateReducer(state, { type: "START_OUTGOING", mode: "video", peerName: "Peer" });
    state = callStateReducer(state, { type: "OUTGOING_RINGING", callId: "c1" });
    state = callStateReducer(state, { type: "REMOTE_ACCEPT" });

    state = callStateReducer(state, { type: "TAB_HIDDEN" });
    state = callStateReducer(state, { type: "NETWORK_OFFLINE" });
    expect(state.phase).toBe("reconnecting");

    state = callStateReducer(state, { type: "NETWORK_ONLINE" });
    // still reconnecting while hidden
    expect(state.phase).toBe("reconnecting");

    state = callStateReducer(state, { type: "TAB_VISIBLE" });
    expect(state.phase).toBe("outgoing_connecting");

    state = callStateReducer(state, { type: "CONNECT" });
    expect(state.phase).toBe("connected");
  });

  it("fails deterministically after reconnect retries are exhausted", () => {
    let state = createInitialCallMachineState();
    state = callStateReducer(state, { type: "START_OUTGOING", mode: "audio", peerName: "Peer" });
    state = callStateReducer(state, { type: "OUTGOING_RINGING", callId: "c1" });
    state = callStateReducer(state, { type: "REMOTE_ACCEPT" });
    state = callStateReducer(state, { type: "CONNECTION_LOST" });

    state = callStateReducer(state, { type: "RECONNECT_ATTEMPT" });
    state = callStateReducer(state, { type: "CONNECTION_LOST" });
    state = callStateReducer(state, { type: "RECONNECT_ATTEMPT" });
    state = callStateReducer(state, { type: "CONNECTION_LOST" });
    state = callStateReducer(state, { type: "RECONNECT_ATTEMPT" });

    expect(state.phase).toBe("failure");
  });

  // ── ICE Restart transitions (CALL-008) ──────────────────────────────

  it("CONNECTION_LOST from connected → reconnecting", () => {
    let state = createInitialCallMachineState();
    state = callStateReducer(state, { type: "START_OUTGOING", mode: "audio", peerName: "Peer" });
    state = callStateReducer(state, { type: "OUTGOING_RINGING", callId: "c1" });
    state = callStateReducer(state, { type: "REMOTE_ACCEPT" });
    expect(state.phase).toBe("connected");

    state = callStateReducer(state, { type: "CONNECTION_LOST", message: "ICE connection interrupted." });
    expect(state.phase).toBe("reconnecting");
    expect(state.reasonMessage).toBe("ICE connection interrupted.");
  });

  it("RECONNECT_ATTEMPT from reconnecting → outgoing_connecting with retryCount incremented", () => {
    let state = createInitialCallMachineState();
    state = callStateReducer(state, { type: "START_OUTGOING", mode: "audio", peerName: "Peer" });
    state = callStateReducer(state, { type: "OUTGOING_RINGING", callId: "c1" });
    state = callStateReducer(state, { type: "REMOTE_ACCEPT" });
    state = callStateReducer(state, { type: "CONNECTION_LOST" });
    expect(state.phase).toBe("reconnecting");
    expect(state.retryCount).toBe(0);

    state = callStateReducer(state, { type: "RECONNECT_ATTEMPT" });
    expect(state.phase).toBe("outgoing_connecting");
    expect(state.retryCount).toBe(1);
  });

  it("RECONNECT_ATTEMPT when retryCount >= maxRetries → failure", () => {
    let state = createInitialCallMachineState();
    state = callStateReducer(state, { type: "START_OUTGOING", mode: "audio", peerName: "Peer" });
    state = callStateReducer(state, { type: "OUTGOING_RINGING", callId: "c1" });
    state = callStateReducer(state, { type: "REMOTE_ACCEPT" });

    // First reconnect cycle
    state = callStateReducer(state, { type: "CONNECTION_LOST" });
    state = callStateReducer(state, { type: "RECONNECT_ATTEMPT" }); // retryCount = 1
    // Second reconnect cycle
    state = callStateReducer(state, { type: "CONNECTION_LOST" });
    state = callStateReducer(state, { type: "RECONNECT_ATTEMPT" }); // retryCount = 2
    // Third attempt should fail (maxRetries defaults to 2)
    state = callStateReducer(state, { type: "CONNECTION_LOST" });
    state = callStateReducer(state, { type: "RECONNECT_ATTEMPT" });
    expect(state.phase).toBe("failure");
    expect(state.reasonMessage).toBe("Call failed to reconnect.");
  });

  it("CONNECT from outgoing_connecting → connected resets retryCount to 0", () => {
    let state = createInitialCallMachineState();
    state = callStateReducer(state, { type: "START_OUTGOING", mode: "audio", peerName: "Peer" });
    state = callStateReducer(state, { type: "OUTGOING_RINGING", callId: "c1" });
    state = callStateReducer(state, { type: "REMOTE_ACCEPT" });
    state = callStateReducer(state, { type: "CONNECTION_LOST" });
    state = callStateReducer(state, { type: "RECONNECT_ATTEMPT" }); // retryCount = 1
    expect(state.retryCount).toBe(1);

    state = callStateReducer(state, { type: "CONNECT" });
    expect(state.phase).toBe("connected");
    expect(state.retryCount).toBe(0);
  });

  it("NETWORK_OFFLINE from connected → reconnecting", () => {
    let state = createInitialCallMachineState();
    state = callStateReducer(state, { type: "START_OUTGOING", mode: "audio", peerName: "Peer" });
    state = callStateReducer(state, { type: "OUTGOING_RINGING", callId: "c1" });
    state = callStateReducer(state, { type: "REMOTE_ACCEPT" });
    expect(state.phase).toBe("connected");

    state = callStateReducer(state, { type: "NETWORK_OFFLINE" });
    expect(state.phase).toBe("reconnecting");
    expect(state.isOnline).toBe(false);
  });

  it("NETWORK_ONLINE from reconnecting → outgoing_connecting without incrementing retryCount", () => {
    let state = createInitialCallMachineState();
    state = callStateReducer(state, { type: "START_OUTGOING", mode: "audio", peerName: "Peer" });
    state = callStateReducer(state, { type: "OUTGOING_RINGING", callId: "c1" });
    state = callStateReducer(state, { type: "REMOTE_ACCEPT" });
    state = callStateReducer(state, { type: "NETWORK_OFFLINE" });
    expect(state.phase).toBe("reconnecting");
    const retryBefore = state.retryCount;

    state = callStateReducer(state, { type: "NETWORK_ONLINE" });
    expect(state.phase).toBe("outgoing_connecting");
    expect(state.retryCount).toBe(retryBefore); // no increment
    expect(state.isOnline).toBe(true);
  });

  it("TAB_HIDDEN while reconnecting blocks RECONNECT_ATTEMPT", () => {
    let state = createInitialCallMachineState();
    state = callStateReducer(state, { type: "START_OUTGOING", mode: "audio", peerName: "Peer" });
    state = callStateReducer(state, { type: "OUTGOING_RINGING", callId: "c1" });
    state = callStateReducer(state, { type: "REMOTE_ACCEPT" });
    state = callStateReducer(state, { type: "CONNECTION_LOST" });
    state = callStateReducer(state, { type: "TAB_HIDDEN" });
    expect(state.isTabVisible).toBe(false);

    state = callStateReducer(state, { type: "RECONNECT_ATTEMPT" });
    // Should transition to failure because tab is not visible
    expect(state.phase).toBe("failure");
  });

  it("TAB_VISIBLE while reconnecting auto-transitions to outgoing_connecting", () => {
    let state = createInitialCallMachineState();
    state = callStateReducer(state, { type: "START_OUTGOING", mode: "audio", peerName: "Peer" });
    state = callStateReducer(state, { type: "OUTGOING_RINGING", callId: "c1" });
    state = callStateReducer(state, { type: "REMOTE_ACCEPT" });
    state = callStateReducer(state, { type: "TAB_HIDDEN" });
    state = callStateReducer(state, { type: "NETWORK_OFFLINE" });
    expect(state.phase).toBe("reconnecting");

    state = callStateReducer(state, { type: "NETWORK_ONLINE" });
    // Still reconnecting because tab is hidden
    expect(state.phase).toBe("reconnecting");

    state = callStateReducer(state, { type: "TAB_VISIBLE" });
    expect(state.phase).toBe("outgoing_connecting");
  });
});

describe("teardownCallResources", () => {
  it("stops tracks, closes peer connection, removes listeners, and is idempotent", () => {
    const stopLocal1 = vi.fn();
    const stopLocal2 = vi.fn();
    const stopRemote = vi.fn();
    const close = vi.fn();
    const detach = vi.fn();

    const resources = {
      localStream: { getTracks: () => [{ stop: stopLocal1 }, { stop: stopLocal2 }] } as unknown as MediaStream,
      remoteStream: { getTracks: () => [{ stop: stopRemote }] } as unknown as MediaStream,
      peerConnection: { close } as unknown as RTCPeerConnection,
      detachListeners: [detach],
      teardownTimers: [window.setTimeout(() => undefined, 1000)],
      cleanedUp: false,
    };

    teardownCallResources(resources);
    teardownCallResources(resources);

    expect(stopLocal1).toHaveBeenCalledTimes(1);
    expect(stopLocal2).toHaveBeenCalledTimes(1);
    expect(stopRemote).toHaveBeenCalledTimes(1);
    expect(close).toHaveBeenCalledTimes(1);
    expect(detach).toHaveBeenCalledTimes(1);
    expect(resources.cleanedUp).toBe(true);
  });
});
