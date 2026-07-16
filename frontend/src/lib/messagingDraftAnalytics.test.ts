import { describe, expect, it, vi } from "vitest";

import { emitMessagingDraftEvent, sanitizeMessagingDraftEvent } from "./messagingDraftAnalytics";

describe("messagingDraftAnalytics", () => {
  it("sanitizes payload to allowed metadata-only keys", () => {
    const sanitized = sanitizeMessagingDraftEvent({
      event: "draft_save",
      outcome: "success",
      source: "local",
      reason: "none",
      conversation_id_present: true,
      at_ms: 123,
    });

    expect(Object.keys(sanitized).sort()).toEqual([
      "at_ms",
      "conversation_id_present",
      "event",
      "outcome",
      "reason",
      "source",
    ]);
  });

  it("emits analytics event on window with safe detail payload", () => {
    const handler = vi.fn();
    window.addEventListener("messaging:draft-analytics", handler as EventListener);

    emitMessagingDraftEvent({
      event: "draft_fallback",
      outcome: "success",
      source: "local",
      reason: "create_failed",
      conversation_id_present: true,
      at_ms: 456,
    });

    expect(handler).toHaveBeenCalledTimes(1);
    const evt = handler.mock.calls[0]![0] as CustomEvent;
    expect(evt.detail).toEqual({
      event: "draft_fallback",
      outcome: "success",
      source: "local",
      reason: "create_failed",
      conversation_id_present: true,
      at_ms: 456,
    });

    window.removeEventListener("messaging:draft-analytics", handler as EventListener);
  });
});
