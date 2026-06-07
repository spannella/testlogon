/**
 * Regression test for GAP-0314: the `message:viewed` SSE handler in
 * `frontend/src/hooks/useMessagingStream.ts` must surgically patch the
 * messages cache via `setQueriesData` instead of triggering a full
 * message-list refetch via `invalidateQueries(["messages", ...])`.
 *
 * A full SSE/network behavioural test requires two live browser sessions,
 * a running backend and a real EventSource connection. The robust, hermetic
 * regression here is a SOURCE-LEVEL assertion (mirrors the readFileSync-based
 * specs already in this folder, e.g. alerts.spec.ts / media-player-drm.spec.ts):
 * read useMessagingStream.ts and assert the read-receipt handler now does a
 * surgical cache mutation referencing read_by_count / read_by_user_ids, and
 * no longer invalidates the ["messages", ...] query on a view event.
 *
 * Fails-before: the original handler called
 *   queryClient.invalidateQueries({ queryKey: ["messages", conversationId] })
 * inside the `message:viewed` branch (and the broad block did so unconditionally),
 * so the setQueriesData / read_by_count assertions below would fail.
 * Passes-after: the fixed handler uses setQueriesData and increments read_by_count.
 */
import { test, expect } from "@playwright/test";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, resolve } from "path";

const here = dirname(fileURLToPath(import.meta.url));
const SOURCE = readFileSync(
  resolve(here, "../src/hooks/useMessagingStream.ts"),
  "utf-8",
);

// Extract the `message:viewed` handler block so assertions are scoped to it.
function viewedHandlerBlock(src: string): string {
  const start = src.indexOf('eventType === "message:viewed"');
  expect(start).toBeGreaterThan(-1);
  // Take a generous slice from the start of the handler; large enough to
  // contain the whole setQueriesData mutation, small enough to exclude
  // unrelated handlers further down the file.
  return src.slice(start, start + 1800);
}

test.describe("GAP-0314 — message:viewed surgical cache patch", () => {
  test("the message:viewed handler uses setQueriesData for the messages cache", () => {
    const block = viewedHandlerBlock(SOURCE);
    expect(block).toContain("setQueriesData");
    expect(block).toContain('["messages", conversationId]');
  });

  test("the message:viewed handler does NOT invalidate the messages query", () => {
    const block = viewedHandlerBlock(SOURCE);
    // The narrow per-message-views invalidation is still allowed; the
    // ["messages", ...] full-refetch invalidation must be gone from this branch.
    expect(block).not.toMatch(
      /invalidateQueries\(\s*\{\s*queryKey:\s*\["messages", conversationId\]/,
    );
  });

  test("the surgical patch increments read_by_count and appends read_by_user_ids", () => {
    const block = viewedHandlerBlock(SOURCE);
    expect(block).toContain("read_by_count");
    expect(block).toContain("read_by_user_ids");
    // Dedup: viewer is only appended when not already present.
    expect(block).toMatch(/includes\(viewerId\)/);
  });

  test("the per-message-views detail query is still invalidated", () => {
    const block = viewedHandlerBlock(SOURCE);
    expect(block).toMatch(
      /invalidateQueries\(\s*\{\s*queryKey:\s*\["message-views", conversationId, messageId\]/,
    );
  });

  test("the broad per-conversation invalidate excludes message:viewed", () => {
    // The unconditional `if (conversationId) invalidateQueries(["messages", ...])`
    // block must skip message:viewed, otherwise the surgical patch is clobbered.
    expect(SOURCE).toMatch(/eventType !== "message:viewed"/);
  });
});
