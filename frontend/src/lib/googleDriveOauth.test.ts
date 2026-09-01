import { describe, expect, it } from "vitest";

import {
  GOOGLE_DRIVE_PROVIDER,
  parseGoogleDriveCallbackParams,
  isGoogleDriveCallback,
  buildGoogleDriveReturnUrl,
  stripGoogleDriveCallbackParams,
} from "@/lib/googleDriveOauth";

describe("parseGoogleDriveCallbackParams", () => {
  it("parses code/state/provider/error with or without a leading ?", () => {
    const withMark = parseGoogleDriveCallbackParams(
      "?code=abc&state=xyz&provider=google_drive",
    );
    expect(withMark).toEqual({
      code: "abc",
      state: "xyz",
      provider: "google_drive",
      error: null,
    });

    const noMark = parseGoogleDriveCallbackParams("code=abc&state=xyz");
    expect(noMark.code).toBe("abc");
    expect(noMark.state).toBe("xyz");
    expect(noMark.provider).toBeNull();
    expect(noMark.error).toBeNull();
  });

  it("treats empty / whitespace-only values as null and tolerates empty input", () => {
    expect(parseGoogleDriveCallbackParams("")).toEqual({
      code: null,
      state: null,
      provider: null,
      error: null,
    });
    const blanks = parseGoogleDriveCallbackParams("code=%20&state=");
    expect(blanks.code).toBeNull();
    expect(blanks.state).toBeNull();
  });

  it("captures a provider error slug", () => {
    const declined = parseGoogleDriveCallbackParams("?error=access_denied&state=xyz");
    expect(declined.error).toBe("access_denied");
    expect(declined.code).toBeNull();
  });
});

describe("isGoogleDriveCallback", () => {
  it("is true for a complete google_drive redirect", () => {
    expect(
      isGoogleDriveCallback(
        parseGoogleDriveCallbackParams("?code=abc&state=xyz&provider=google_drive"),
      ),
    ).toBe(true);
  });

  it("tolerates a missing provider tag (bare code+state)", () => {
    expect(
      isGoogleDriveCallback(parseGoogleDriveCallbackParams("?code=abc&state=xyz")),
    ).toBe(true);
  });

  it("is false when code or state is missing", () => {
    expect(isGoogleDriveCallback(parseGoogleDriveCallbackParams("?code=abc"))).toBe(false);
    expect(isGoogleDriveCallback(parseGoogleDriveCallbackParams("?state=xyz"))).toBe(false);
    expect(isGoogleDriveCallback(parseGoogleDriveCallbackParams(""))).toBe(false);
  });

  it("is false on an error redirect even if state is present", () => {
    expect(
      isGoogleDriveCallback(
        parseGoogleDriveCallbackParams("?error=access_denied&state=xyz&code=abc"),
      ),
    ).toBe(false);
  });

  it("is false when the provider tag belongs to a different provider", () => {
    expect(
      isGoogleDriveCallback(
        parseGoogleDriveCallbackParams("?code=abc&state=xyz&provider=dropbox"),
      ),
    ).toBe(false);
  });
});

describe("buildGoogleDriveReturnUrl", () => {
  it("appends the provider marker and trims a trailing slash on origin", () => {
    expect(buildGoogleDriveReturnUrl("https://app.test/", "/projects/p1")).toBe(
      "https://app.test/projects/p1?provider=google_drive",
    );
  });

  it("preserves existing query params on the base path", () => {
    const url = buildGoogleDriveReturnUrl("https://app.test", "/projects/p1?tab=files");
    const parsed = new URL(url);
    expect(parsed.pathname).toBe("/projects/p1");
    expect(parsed.searchParams.get("tab")).toBe("files");
    expect(parsed.searchParams.get("provider")).toBe(GOOGLE_DRIVE_PROVIDER);
  });

  it("round-trips: the built URL is recognised as our callback once code+state land", () => {
    const ret = buildGoogleDriveReturnUrl("https://app.test", "/projects/p1");
    const search = new URL(ret).search + "&code=abc&state=xyz";
    expect(isGoogleDriveCallback(parseGoogleDriveCallbackParams(search))).toBe(true);
  });
});

describe("stripGoogleDriveCallbackParams", () => {
  it("removes handshake params but keeps unrelated ones", () => {
    expect(
      stripGoogleDriveCallbackParams("?tab=files&code=abc&state=xyz&provider=google_drive"),
    ).toBe("tab=files");
  });

  it("returns an empty string when only handshake params were present", () => {
    expect(
      stripGoogleDriveCallbackParams("?code=abc&state=xyz&provider=google_drive&error=x"),
    ).toBe("");
    expect(stripGoogleDriveCallbackParams("")).toBe("");
  });
});
