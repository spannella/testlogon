import { render } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, expect, it, vi, afterEach } from "vitest";
import { useMessagingStream } from "./useMessagingStream";

class MockEventSource {
  onopen: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;

  private _listeners: Map<string, ((event: MessageEvent) => void)[]> = new Map();

  static instances: MockEventSource[] = [];

  constructor(_url: string, _init?: EventSourceInit) {
    MockEventSource.instances.push(this);
  }

  addEventListener(type: string, listener: (event: MessageEvent) => void) {
    if (!this._listeners.has(type)) {
      this._listeners.set(type, []);
    }
    this._listeners.get(type)!.push(listener);
  }

  removeEventListener(type: string, listener: (event: MessageEvent) => void) {
    const listeners = this._listeners.get(type);
    if (listeners) {
      this._listeners.set(type, listeners.filter((l) => l !== listener));
    }
  }

  dispatchNamedEvent(type: string, data: unknown) {
    const event = { type, data: JSON.stringify(data) } as MessageEvent;
    const listeners = this._listeners.get(type) ?? [];
    for (const listener of listeners) {
      listener(event);
    }
  }

  close() {}
}

function TestHarness() {
  useMessagingStream(true);
  return null;
}

describe("useMessagingStream", () => {
  afterEach(() => {
    MockEventSource.instances = [];
    vi.restoreAllMocks();
  });

  it("invalidates conversation messages on once-media consumed events", () => {
    vi.stubGlobal("EventSource", MockEventSource as unknown as typeof EventSource);

    const client = new QueryClient();
    const invalidateSpy = vi.spyOn(client, "invalidateQueries");

    render(
      <QueryClientProvider client={client}>
        <TestHarness />
      </QueryClientProvider>,
    );

    const es = MockEventSource.instances[0]!;
    expect(es).toBeTruthy();
    if (!es) throw new Error("Expected EventSource instance");

    es.onmessage?.({
      data: JSON.stringify({ type: "once_media_consumed", conversation_id: "c-1" }),
    } as MessageEvent);

    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ["messages", "c-1"] });
  });

  it("invalidates conversations and messages on message:new", () => {
    vi.stubGlobal("EventSource", MockEventSource as unknown as typeof EventSource);

    const client = new QueryClient();
    const invalidateSpy = vi.spyOn(client, "invalidateQueries");

    render(
      <QueryClientProvider client={client}>
        <TestHarness />
      </QueryClientProvider>,
    );

    const es = MockEventSource.instances[0]!;
    expect(es).toBeTruthy();
    if (!es) throw new Error("Expected EventSource instance");

    // Dispatch a named SSE event (as the backend sends: "event: message:new")
    es.dispatchNamedEvent("message:new", { conversation_id: "c-2" });

    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ["conversations"] });
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ["messages", "c-2"] });
  });
});
