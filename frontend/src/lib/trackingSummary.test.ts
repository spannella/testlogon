import { describe, expect, it } from "vitest";

import { summarizeTracking, formatTrackingStatus } from "./trackingSummary";
import type { CarrierTrackingView } from "@/api/types";

describe("formatTrackingStatus", () => {
  it("title-cases underscore tokens", () => {
    expect(formatTrackingStatus("in_transit")).toBe("In Transit");
  });

  it("title-cases hyphen tokens and collapses whitespace", () => {
    expect(formatTrackingStatus("out-for  delivery")).toBe("Out For Delivery");
  });

  it("returns Unknown for empty/null/undefined", () => {
    expect(formatTrackingStatus("")).toBe("Unknown");
    expect(formatTrackingStatus(null)).toBe("Unknown");
    expect(formatTrackingStatus(undefined)).toBe("Unknown");
  });
});

describe("summarizeTracking", () => {
  it("returns an honest-empty summary for null (degraded 404)", () => {
    const s = summarizeTracking(null);
    expect(s.hasTracking).toBe(false);
    expect(s.carrierLabel).toBe("");
    expect(s.trackingNumber).toBe("");
    expect(s.trackingUrl).toBeNull();
    expect(s.statusLabel).toBe("Unknown");
    expect(s.estimatedDelivery).toBeNull();
    expect(s.events).toEqual([]);
  });

  it("returns honest-empty for the backend no-carrier payload", () => {
    const view: CarrierTrackingView = {
      txn_id: "t1",
      tracking_url: null,
      carrier: null,
      tracking_number: null,
      status: null,
      carrier_events: null,
    };
    const s = summarizeTracking(view);
    expect(s.hasTracking).toBe(false);
    expect(s.events).toEqual([]);
  });

  it("marks hasTracking only when both carrier and tracking number present", () => {
    expect(
      summarizeTracking({ txn_id: "t", carrier: "ups", tracking_number: null }).hasTracking,
    ).toBe(false);
    expect(
      summarizeTracking({ txn_id: "t", carrier: null, tracking_number: "1Z" }).hasTracking,
    ).toBe(false);
    expect(
      summarizeTracking({ txn_id: "t", carrier: "ups", tracking_number: "1Z" }).hasTracking,
    ).toBe(true);
  });

  it("uppercases carrier and preserves tracking number", () => {
    const s = summarizeTracking({
      txn_id: "t",
      carrier: "fedex",
      tracking_number: "789012345",
    });
    expect(s.carrierLabel).toBe("FEDEX");
    expect(s.trackingNumber).toBe("789012345");
  });

  it("nulls out an empty tracking url and passes through a real one", () => {
    expect(
      summarizeTracking({ txn_id: "t", tracking_url: "   " }).trackingUrl,
    ).toBeNull();
    expect(
      summarizeTracking({ txn_id: "t", tracking_url: "https://track/1Z" }).trackingUrl,
    ).toBe("https://track/1Z");
  });

  it("maps status and estimated_delivery and returns events newest-first as given", () => {
    const view: CarrierTrackingView = {
      txn_id: "t",
      carrier: "usps",
      tracking_number: "94001",
      status: "in_transit",
      estimated_delivery: "2026-09-05",
      carrier_events: [
        { timestamp: "2026-09-02", description: "Departed facility", location: "NJ" },
        { timestamp: "2026-09-01", description: "Accepted", location: "NY" },
      ],
    };
    const s = summarizeTracking(view);
    expect(s.statusLabel).toBe("In Transit");
    expect(s.estimatedDelivery).toBe("2026-09-05");
    expect(s.events).toHaveLength(2);
    expect(s.events[0]?.description).toBe("Departed facility");
  });

  it("treats a whitespace-only estimated_delivery as absent", () => {
    expect(
      summarizeTracking({ txn_id: "t", estimated_delivery: "   " }).estimatedDelivery,
    ).toBeNull();
  });
});
