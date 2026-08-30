import { describe, expect, it } from "vitest";

import {
  MUTE_OPTIONS,
  MUTE_FOREVER,
  computeMutedUntil,
  isMuted,
  isMutedForever,
  mutedLabel,
  formatMuteOption,
} from "./conversationMute";

// A fixed "now": 2026-06-17 10:00:00 local time. Building via the local
// Date ctor keeps these assertions timezone-agnostic.
const NOW = new Date(2026, 5, 17, 10, 0, 0);
const NOW_SEC = Math.floor(NOW.getTime() / 1000);

describe("MUTE_OPTIONS", () => {
  it("exposes the expected option ids", () => {
    expect(MUTE_OPTIONS.map((o) => o.id)).toEqual(["1h", "8h", "1w", "off"]);
  });

  it("has exactly one indefinite (durationSec=null) option", () => {
    expect(MUTE_OPTIONS.filter((o) => o.durationSec === null)).toHaveLength(1);
  });

  it("formatMuteOption returns the option label", () => {
    const first = MUTE_OPTIONS[0]!;
    expect(formatMuteOption(first)).toBe("For 1 hour");
  });
});

describe("computeMutedUntil", () => {
  it("adds the duration for a timed option", () => {
    expect(computeMutedUntil("1h", NOW_SEC)).toBe(NOW_SEC + 3600);
    expect(computeMutedUntil("8h", NOW_SEC)).toBe(NOW_SEC + 8 * 3600);
    expect(computeMutedUntil("1w", NOW_SEC)).toBe(NOW_SEC + 7 * 24 * 3600);
  });

  it("returns the far-future sentinel for the indefinite option", () => {
    expect(computeMutedUntil("off", NOW_SEC)).toBe(MUTE_FOREVER);
  });

  it("returns 0 (no-op) for an unknown option id", () => {
    expect(computeMutedUntil("nope", NOW_SEC)).toBe(0);
  });

  it("floors a fractional nowSec", () => {
    expect(computeMutedUntil("1h", NOW_SEC + 0.9)).toBe(NOW_SEC + 3600);
  });
});

describe("isMuted", () => {
  it("is false for 0 / undefined / null", () => {
    expect(isMuted(0, NOW_SEC)).toBe(false);
    expect(isMuted(undefined, NOW_SEC)).toBe(false);
    expect(isMuted(null, NOW_SEC)).toBe(false);
  });

  it("is false when the mute has expired", () => {
    expect(isMuted(NOW_SEC - 1, NOW_SEC)).toBe(false);
    expect(isMuted(NOW_SEC, NOW_SEC)).toBe(false);
  });

  it("is true when muted_until is in the future", () => {
    expect(isMuted(NOW_SEC + 1, NOW_SEC)).toBe(true);
    expect(isMuted(computeMutedUntil("1h", NOW_SEC), NOW_SEC)).toBe(true);
    expect(isMuted(MUTE_FOREVER, NOW_SEC)).toBe(true);
  });
});

describe("isMutedForever", () => {
  it("is true only at/above the sentinel", () => {
    expect(isMutedForever(MUTE_FOREVER)).toBe(true);
    expect(isMutedForever(MUTE_FOREVER + 100)).toBe(true);
    expect(isMutedForever(NOW_SEC + 3600)).toBe(false);
    expect(isMutedForever(0)).toBe(false);
    expect(isMutedForever(undefined)).toBe(false);
  });
});

describe("mutedLabel", () => {
  it("is empty when not muted", () => {
    expect(mutedLabel(0, NOW_SEC)).toBe("");
    expect(mutedLabel(NOW_SEC - 10, NOW_SEC)).toBe("");
  });

  it("is plain \"Muted\" for indefinite", () => {
    expect(mutedLabel(MUTE_FOREVER, NOW_SEC)).toBe("Muted");
  });

  it("shows a same-day clock time", () => {
    // 2 hours later is still the same calendar day.
    const until = NOW_SEC + 2 * 3600;
    expect(mutedLabel(until, NOW_SEC)).toBe("Muted until 12:00 PM");
  });

  it("shows a weekday for a later day", () => {
    // +2 days from Wed 2026-06-17 -> Fri.
    const until = NOW_SEC + 2 * 24 * 3600;
    expect(mutedLabel(until, NOW_SEC)).toBe("Muted until Fri");
  });
});
