import { describe, expect, it } from "vitest";

import {
  MAX_UPLOAD_RETRIES,
  encodeMediaKey,
  resolveMediaUrl,
  isRetryableUploadStatus,
  uploadBackoffMs,
  uploadProgressPct,
} from "./mediaCdn";

describe("encodeMediaKey", () => {
  it("encodes each segment but preserves separators", () => {
    expect(encodeMediaKey("a/b c/d.png")).toBe("a/b%20c/d.png");
  });
  it("encodes special chars within a segment", () => {
    expect(encodeMediaKey("conv/msg#1?x.png")).toBe("conv/msg%231%3Fx.png");
  });
  it("handles a single segment", () => {
    expect(encodeMediaKey("file.png")).toBe("file.png");
  });
});

describe("resolveMediaUrl", () => {
  it("returns null/undefined for empty input", () => {
    expect(resolveMediaUrl(undefined)).toBeUndefined();
    expect(resolveMediaUrl(null)).toBeUndefined();
    expect(resolveMediaUrl("")).toBeUndefined();
  });

  it("returns already-absolute http(s) URLs as-is", () => {
    expect(resolveMediaUrl("https://cdn.x/y.png", { cdnBase: "https://other" })).toBe(
      "https://cdn.x/y.png",
    );
    expect(resolveMediaUrl("http://cdn.x/y.png")).toBe("http://cdn.x/y.png");
  });

  it("joins a relative path to the CDN base", () => {
    expect(resolveMediaUrl("/media/a.png", { cdnBase: "https://cdn.x" })).toBe(
      "https://cdn.x/media/a.png",
    );
    expect(resolveMediaUrl("media/a.png", { cdnBase: "https://cdn.x/" })).toBe(
      "https://cdn.x/media/a.png",
    );
  });

  it("falls back to apiBase for relative paths when no CDN", () => {
    expect(resolveMediaUrl("/media/a.png", { apiBase: "https://api.x" })).toBe(
      "https://api.x/media/a.png",
    );
  });

  it("returns the relative path unchanged when no base configured", () => {
    expect(resolveMediaUrl("/media/a.png")).toBe("/media/a.png");
  });

  it("builds a CDN object URL from bucket/key", () => {
    expect(
      resolveMediaUrl({ bucket: "media", key: "conv/1/pic name.png" }, { cdnBase: "https://cdn.x" }),
    ).toBe("https://cdn.x/media/conv/1/pic%20name.png");
  });

  it("falls back to /mock/s3 for bucket/key when no CDN (dev unchanged)", () => {
    expect(resolveMediaUrl({ bucket: "media", key: "conv/1/pic.png" })).toBe(
      "/mock/s3/media/conv/1/pic.png",
    );
  });

  it("prefers an explicit absolute url field over bucket/key", () => {
    expect(
      resolveMediaUrl(
        { bucket: "media", key: "k.png", url: "https://abs/x.png" },
        { cdnBase: "https://cdn.x" },
      ),
    ).toBe("https://abs/x.png");
  });

  it("resolves a relative url field against the CDN base", () => {
    expect(
      resolveMediaUrl({ bucket: "media", key: "k.png", url: "/rel/x.png" }, { cdnBase: "https://cdn.x" }),
    ).toBe("https://cdn.x/rel/x.png");
  });

  it("returns undefined for an object missing bucket or key and no url", () => {
    expect(resolveMediaUrl({ bucket: "media" })).toBeUndefined();
    expect(resolveMediaUrl({ key: "k" })).toBeUndefined();
  });
});

describe("isRetryableUploadStatus", () => {
  it("retries on network error (0)", () => {
    expect(isRetryableUploadStatus(0)).toBe(true);
  });
  it("retries on 408/429 and 5xx", () => {
    expect(isRetryableUploadStatus(408)).toBe(true);
    expect(isRetryableUploadStatus(429)).toBe(true);
    expect(isRetryableUploadStatus(500)).toBe(true);
    expect(isRetryableUploadStatus(503)).toBe(true);
    expect(isRetryableUploadStatus(599)).toBe(true);
  });
  it("does not retry on typical 4xx client errors", () => {
    expect(isRetryableUploadStatus(400)).toBe(false);
    expect(isRetryableUploadStatus(403)).toBe(false);
    expect(isRetryableUploadStatus(404)).toBe(false);
  });
  it("does not retry on success", () => {
    expect(isRetryableUploadStatus(200)).toBe(false);
    expect(isRetryableUploadStatus(204)).toBe(false);
  });
});

describe("uploadBackoffMs", () => {
  it("grows exponentially", () => {
    expect(uploadBackoffMs(1)).toBe(500);
    expect(uploadBackoffMs(2)).toBe(1000);
    expect(uploadBackoffMs(3)).toBe(2000);
  });
  it("caps the backoff", () => {
    expect(uploadBackoffMs(99)).toBe(8000);
  });
  it("treats attempt < 1 as 1", () => {
    expect(uploadBackoffMs(0)).toBe(500);
  });
});

describe("uploadProgressPct", () => {
  it("computes a clamped integer percent", () => {
    expect(uploadProgressPct(0, 100)).toBe(0);
    expect(uploadProgressPct(50, 100)).toBe(50);
    expect(uploadProgressPct(100, 100)).toBe(100);
    expect(uploadProgressPct(1, 3)).toBe(33);
  });
  it("clamps out-of-range and guards divide-by-zero", () => {
    expect(uploadProgressPct(200, 100)).toBe(100);
    expect(uploadProgressPct(-5, 100)).toBe(0);
    expect(uploadProgressPct(5, 0)).toBe(0);
    expect(uploadProgressPct(NaN, 100)).toBe(0);
  });
});

describe("MAX_UPLOAD_RETRIES", () => {
  it("is a small positive integer", () => {
    expect(MAX_UPLOAD_RETRIES).toBeGreaterThan(0);
    expect(Number.isInteger(MAX_UPLOAD_RETRIES)).toBe(true);
  });
});
