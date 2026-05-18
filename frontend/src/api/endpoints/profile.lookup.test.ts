import { beforeEach, describe, expect, it, vi } from "vitest";

import { getProfileByIdentifier, patchProfile, ProfileLookupError, clearProfileLookupCache } from "@/api/endpoints/profile";
import { api } from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import { useImpersonationStore } from "@/stores/impersonationStore";

describe("profile lookup endpoint contract", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    clearProfileLookupCache();
    useAuthStore.setState({
      userId: null,
      accessToken: null,
      isAuthenticated: false,
      logoutReason: null,
    });
    useImpersonationStore.getState().clear();
  });

  it("parses cross-user profile response", async () => {
    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        identifier: "alice",
        user_sub: "u_alice",
        audience: "public",
        profile: { display_name: "Alice" },
      }),
      headers: new Headers({ ETag: 'W/"etag-1"' }),
    } as Response);
    vi.stubGlobal("fetch", fetchSpy);

    const out = await getProfileByIdentifier("alice");
    expect(fetchSpy).toHaveBeenCalledWith("/ui/profiles/alice", expect.objectContaining({ method: "GET" }));
    expect(out.audience).toBe("public");
    expect(out.profile.display_name).toBe("Alice");
  });

  it("uses If-None-Match and returns cached payload on 304", async () => {
    const firstPayload = {
      identifier: "alice",
      user_sub: "u_alice",
      audience: "public",
      profile: { display_name: "Alice" },
    };
    const fetchSpy = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => firstPayload,
        headers: new Headers({ ETag: 'W/"etag-1"' }),
      } as Response)
      .mockResolvedValueOnce({
        ok: false,
        status: 304,
        json: async () => ({}),
        headers: new Headers({ ETag: 'W/"etag-1"' }),
      } as Response);
    vi.stubGlobal("fetch", fetchSpy);

    const out = await getProfileByIdentifier("alice");
    const out2 = await getProfileByIdentifier("alice");

    expect(out).toEqual(firstPayload);
    expect(out2).toEqual(firstPayload);
    const secondCall = fetchSpy.mock.calls[1];
    expect(secondCall?.[1]).toMatchObject({
      headers: expect.any(Headers),
    });
    const secondHeaders = secondCall?.[1]?.headers as Headers;
    expect(secondHeaders.get("If-None-Match")).toBe('W/"etag-1"');
  });

  it("retries once without If-None-Match when a 304 is returned but cache is absent", async () => {
    const fetchSpy = vi
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 304,
        json: async () => ({}),
        headers: new Headers({ ETag: 'W/"etag-1"' }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          identifier: "alice",
          user_sub: "u_alice",
          audience: "public",
          profile: { display_name: "Alice" },
        }),
        headers: new Headers({ ETag: 'W/"etag-2"' }),
      } as Response);
    vi.stubGlobal("fetch", fetchSpy);

    const out = await getProfileByIdentifier("alice");
    expect(out.profile.display_name).toBe("Alice");
    expect(fetchSpy).toHaveBeenCalledTimes(2);
    const firstHeaders = fetchSpy.mock.calls[0]?.[1]?.headers as Headers;
    const secondHeaders = fetchSpy.mock.calls[1]?.[1]?.headers as Headers;
    expect(firstHeaders.get("If-None-Match")).toBeNull();
    expect(secondHeaders.get("If-None-Match")).toBeNull();
  });

  it("maps 404 to not_found_or_suppressed", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: "Not Found",
        json: async () => ({ detail: "Profile not found" }),
        headers: new Headers(),
      } as Response),
    );

    await expect(getProfileByIdentifier("missing")).rejects.toMatchObject<Partial<ProfileLookupError>>({
      code: "not_found_or_suppressed",
      status: 404,
      message: "Profile not available",
    });
  });

  it("maps 429 to rate_limited", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 429,
        statusText: "Too Many Requests",
        json: async () => ({ detail: { code: "profile_lookup_rate_limited" } }),
        headers: new Headers({ "Retry-After": "17" }),
      } as Response),
    );

    await expect(getProfileByIdentifier("alice")).rejects.toMatchObject<Partial<ProfileLookupError>>({
      code: "rate_limited",
      status: 429,
      retryAfterSeconds: 17,
    });
  });

  it("maps 429 retry_after_seconds from response body when Retry-After header is absent", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 429,
        statusText: "Too Many Requests",
        json: async () => ({
          detail: {
            code: "profile_lookup_rate_limited",
            tier: "anonymous",
            retry_after_seconds: 33,
          },
        }),
        headers: new Headers(),
      } as Response),
    );

    await expect(getProfileByIdentifier("alice")).rejects.toMatchObject<Partial<ProfileLookupError>>({
      code: "rate_limited",
      status: 429,
      retryAfterSeconds: 33,
    });
  });

  it("validates empty identifiers before fetch", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    await expect(getProfileByIdentifier("   ")).rejects.toMatchObject<Partial<ProfileLookupError>>({
      code: "not_found_or_suppressed",
      status: 404,
    });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("clears lookup cache after successful profile patch", async () => {
    const fetchSpy = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          identifier: "alice",
          user_sub: "u_alice",
          audience: "public",
          profile: { display_name: "Alice" },
        }),
        headers: new Headers({ ETag: 'W/"etag-1"' }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          identifier: "alice",
          user_sub: "u_alice",
          audience: "public",
          profile: { display_name: "Alice Updated" },
        }),
        headers: new Headers({ ETag: 'W/"etag-2"' }),
      } as Response);
    vi.stubGlobal("fetch", fetchSpy);
    vi.spyOn(api, "patch").mockResolvedValue({ profile: {} } as never);

    await getProfileByIdentifier("alice");
    await patchProfile({ display_name: "Alice Updated" } as never);
    await getProfileByIdentifier("alice");

    expect(fetchSpy).toHaveBeenCalledTimes(2);
    const secondHeaders = fetchSpy.mock.calls[1]?.[1]?.headers as Headers;
    expect(secondHeaders.get("If-None-Match")).toBeNull();
  });
});
