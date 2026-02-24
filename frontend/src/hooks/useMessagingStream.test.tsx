import { render } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, expect, it, vi, afterEach } from "vitest";
import { useMessagingStream } from "./useMessagingStream";

class MockEventSource {
  onopen: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;

  static instances: MockEventSource[] = [];

  constructor(_url: string, _init?: EventSourceInit) {
    MockEventSource.instances.push(this);
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

    const es = MockEventSource.instances[0];
    expect(es).toBeTruthy();
    if (!es) throw new Error("Expected EventSource instance");

    es.onmessage?.({
      data: JSON.stringify({ type: "once_media_consumed", conversation_id: "c-1" }),
    } as MessageEvent);

    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ["messages", "c-1"] });
  });

  it("invalidates conversations and messages on new_message", () => {
    vi.stubGlobal("EventSource", MockEventSource as unknown as typeof EventSource);

    const client = new QueryClient();
    const invalidateSpy = vi.spyOn(client, "invalidateQueries");

    render(
      <QueryClientProvider client={client}>
        <TestHarness />
      </QueryClientProvider>,
    );

    const es = MockEventSource.instances[0];
    expect(es).toBeTruthy();
    if (!es) throw new Error("Expected EventSource instance");
    es.onmessage?.({
      data: JSON.stringify({ type: "new_message", conversation_id: "c-2" }),
    } as MessageEvent);

    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ["conversations"] });
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ["messages", "c-2"] });
  });
});
