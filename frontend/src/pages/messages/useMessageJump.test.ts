import { describe, expect, it, vi } from "vitest";
import { jumpToMessageInTimeline } from "./useMessageJump";

describe("jumpToMessageInTimeline", () => {
  it("scrolls and highlights when message is found", async () => {
    const el = document.createElement("div");
    el.id = "msg-m1";
    el.scrollIntoView = vi.fn();
    document.body.appendChild(el);

    const setHighlight = vi.fn();
    const clearJump = vi.fn();

    const found = await jumpToMessageInTimeline({
      messageId: "m1",
      hasNextPage: () => false,
      fetchNextPage: vi.fn(),
      setHighlightMessageId: setHighlight,
      clearJumpTarget: clearJump,
    });

    expect(found).toBe(true);
    expect(el.scrollIntoView).toHaveBeenCalled();
    expect(setHighlight).toHaveBeenCalledWith("m1");
    expect(clearJump).toHaveBeenCalled();

    document.body.removeChild(el);
  });

  it("returns false and calls fallback when message is missing", async () => {
    const onMissing = vi.fn();
    const fetchNextPage = vi.fn();

    const found = await jumpToMessageInTimeline({
      messageId: "missing",
      hasNextPage: () => false,
      fetchNextPage,
      setHighlightMessageId: vi.fn(),
      clearJumpTarget: vi.fn(),
      onMissingMessage: onMissing,
    });

    expect(found).toBe(false);
    expect(fetchNextPage).not.toHaveBeenCalled();
    expect(onMissing).toHaveBeenCalledWith("missing");
  });

  it("loads more pages while looking for message", async () => {
    const setHighlight = vi.fn();
    const clearJump = vi.fn();
    const fetchNextPage = vi.fn(async () => {
      const el = document.createElement("div");
      el.id = "msg-m2";
      el.scrollIntoView = vi.fn();
      document.body.appendChild(el);
    });

    const found = await jumpToMessageInTimeline({
      messageId: "m2",
      hasNextPage: () => true,
      fetchNextPage,
      setHighlightMessageId: setHighlight,
      clearJumpTarget: clearJump,
      maxAttempts: 1,
    });

    expect(found).toBe(true);
    expect(fetchNextPage).toHaveBeenCalledTimes(1);
    expect(setHighlight).toHaveBeenCalledWith("m2");

    const el = document.getElementById("msg-m2");
    if (el) document.body.removeChild(el);
  });
});
