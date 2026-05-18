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
      peerConnection: { close },
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
