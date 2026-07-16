import { describe, expect, it, vi, beforeEach } from "vitest";

import { reportDraftLifecycleEvent } from "../newsfeedDraftTelemetry";

describe("reportDraftLifecycleEvent", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("uses sendBeacon when available", () => {
    const beaconSpy = vi.fn((_url?: string, _data?: unknown) => true);
    Object.defineProperty(globalThis, "navigator", {
      value: { sendBeacon: beaconSpy },
      configurable: true,
    });

    reportDraftLifecycleEvent("save_success", "success");

    expect(beaconSpy).toHaveBeenCalledTimes(1);
    expect(beaconSpy.mock.calls[0]?.[0]).toBe("/telemetry/draft-lifecycle");
  });

  it("falls back to fetch when sendBeacon is unavailable", () => {
    Object.defineProperty(globalThis, "navigator", {
      value: {},
      configurable: true,
    });
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 200 }));

    reportDraftLifecycleEvent("delete_fail", "fail", "network_error");

    expect(fetchSpy).toHaveBeenCalledWith(
      "/telemetry/draft-lifecycle",
      expect.objectContaining({ method: "POST" }),
    );
  });
});
