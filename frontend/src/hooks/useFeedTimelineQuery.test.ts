import { describe, expect, it } from "vitest";
import { ApiError } from "@/api/client";
import { buildFeedRequestParams, isInvalidCursorError } from "./useFeedTimelineQuery";

describe("useFeedTimelineQuery helpers", () => {
  it("builds feed request params from scope + page cursor", () => {
    expect(
      buildFeedRequestParams(
        {
          authorId: "u_1",
          q: "release",
          from: "2026-01-01T00:00:00Z",
          to: "2026-03-01T00:00:00Z",
          hasMedia: true,
        },
        "cursor_abc",
      ),
    ).toEqual({
      cursor: "cursor_abc",
      author_id: "u_1",
      q: "release",
      from: "2026-01-01T00:00:00Z",
      to: "2026-03-01T00:00:00Z",
      has_media: true,
    });
  });

  it("normalizes date-only bounds and preserves full ISO timestamps", () => {
    expect(
      buildFeedRequestParams({
        from: "2026-04-01",
        to: "2026-04-30",
      }),
    ).toMatchObject({
      from: "2026-04-01T00:00:00Z",
      to: "2026-04-30T23:59:59Z",
    });

    expect(
      buildFeedRequestParams({
        from: "2026-04-01T05:00:00Z",
        to: "2026-04-30T10:30:00+00:00",
      }),
    ).toMatchObject({
      from: "2026-04-01T05:00:00Z",
      to: "2026-04-30T10:30:00+00:00",
    });
  });

  it("detects invalid_cursor semantic API errors", () => {
    const semantic = new ApiError(400, "Invalid cursor", {
      detail: { code: "invalid_cursor", message: "Invalid cursor" },
    });
    expect(isInvalidCursorError(semantic)).toBe(true);
    expect(isInvalidCursorError(new ApiError(400, "Bad request", { detail: { code: "invalid_query" } }))).toBe(false);
    expect(isInvalidCursorError(new Error("boom"))).toBe(false);
  });
});
