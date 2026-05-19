import { describe, expect, it } from "vitest";
import { parseProfileFeedUrlState, writeProfileFeedUrlState } from "./profileFeedUrlState";

describe("profileFeedUrlState", () => {
  it("parses prefixed params and ignores malformed dates", () => {
    const params = new URLSearchParams("pf_q=hello&pf_from=2026-03-01&pf_to=bad&pf_has_media=1&pf_cursor=abc");
    expect(parseProfileFeedUrlState(params)).toEqual({
      q: "hello",
      from: "2026-03-01",
      hasMedia: true,
      cursor: "abc",
    });
  });

  it("parses has_media=false variants", () => {
    expect(parseProfileFeedUrlState(new URLSearchParams("pf_has_media=0"))).toEqual({
      hasMedia: false,
    });
    expect(parseProfileFeedUrlState(new URLSearchParams("has_media=false"))).toEqual({
      hasMedia: false,
    });
  });

  it("writes/removes params idempotently", () => {
    const params = new URLSearchParams("x=1");
    const next = writeProfileFeedUrlState(params, { q: "hi", hasMedia: true });
    expect(next.get("pf_q")).toBe("hi");
    expect(next.get("pf_has_media")).toBe("1");

    const cleaned = writeProfileFeedUrlState(next, { q: undefined, hasMedia: undefined });
    expect(cleaned.get("pf_q")).toBeNull();
    expect(cleaned.get("pf_has_media")).toBeNull();
    expect(cleaned.get("x")).toBe("1");
  });

  it("writes has_media=false explicitly", () => {
    const params = new URLSearchParams();
    const next = writeProfileFeedUrlState(params, { hasMedia: false });
    expect(next.get("pf_has_media")).toBe("0");
  });
});
