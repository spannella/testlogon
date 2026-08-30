import { describe, expect, it } from "vitest";
import {
  LIVE_DURATION_OPTIONS,
  UPDATE_INTERVAL_SEC,
  computeExpiresAt,
  isLiveActive,
  liveRemainingLabel,
  liveSecondsRemaining,
  shouldAutoStop,
} from "./liveLocation";

const T0 = 1_000_000; // an arbitrary epoch-second base

describe("LIVE_DURATION_OPTIONS", () => {
  it("offers 15m / 1h / 8h", () => {
    expect(LIVE_DURATION_OPTIONS.map((o) => o.seconds)).toEqual([900, 3600, 28800]);
  });
});

describe("UPDATE_INTERVAL_SEC", () => {
  it("is a small positive cadence", () => {
    expect(UPDATE_INTERVAL_SEC).toBeGreaterThan(0);
    expect(UPDATE_INTERVAL_SEC).toBeLessThanOrEqual(60);
  });
});

describe("computeExpiresAt", () => {
  it("adds the duration to the start", () => {
    expect(computeExpiresAt(T0, 900)).toBe(T0 + 900);
  });
  it("floors fractional inputs and clamps negative duration to 0", () => {
    expect(computeExpiresAt(T0 + 0.9, 900.9)).toBe(T0 + 900);
    expect(computeExpiresAt(T0, -5)).toBe(T0);
  });
});

describe("isLiveActive", () => {
  it("is active before expiry with no stop", () => {
    expect(isLiveActive(T0 + 900, null, T0)).toBe(true);
  });
  it("is inactive at/after expiry", () => {
    expect(isLiveActive(T0 + 900, null, T0 + 900)).toBe(false);
    expect(isLiveActive(T0 + 900, null, T0 + 901)).toBe(false);
  });
  it("is inactive once stopped, even before expiry", () => {
    expect(isLiveActive(T0 + 900, T0 + 100, T0 + 200)).toBe(false);
  });
});

describe("liveSecondsRemaining", () => {
  it("returns whole seconds left", () => {
    expect(liveSecondsRemaining(T0 + 900, T0)).toBe(900);
    expect(liveSecondsRemaining(T0 + 900, T0 + 135)).toBe(765);
  });
  it("clamps to 0 once expired", () => {
    expect(liveSecondsRemaining(T0, T0 + 50)).toBe(0);
  });
});

describe("liveRemainingLabel", () => {
  it("formats mm:ss under an hour", () => {
    // 900 - 645 = 255s = 4:15
    expect(liveRemainingLabel(T0 + 900, null, T0 + 645)).toBe("Live · 4:15 left");
  });
  it("formats h:mm:ss at/over an hour", () => {
    expect(liveRemainingLabel(T0 + 3725, null, T0)).toBe("Live · 1:02:05 left");
  });
  it("reports ended when stopped", () => {
    expect(liveRemainingLabel(T0 + 900, T0 + 10, T0 + 20)).toBe("Live location ended");
  });
  it("reports ended when expired", () => {
    expect(liveRemainingLabel(T0 + 900, null, T0 + 900)).toBe("Live location ended");
  });
});

describe("shouldAutoStop", () => {
  it("is false before expiry", () => {
    expect(shouldAutoStop(T0 + 900, T0 + 899)).toBe(false);
  });
  it("is true at and after expiry", () => {
    expect(shouldAutoStop(T0 + 900, T0 + 900)).toBe(true);
    expect(shouldAutoStop(T0 + 900, T0 + 901)).toBe(true);
  });
});
