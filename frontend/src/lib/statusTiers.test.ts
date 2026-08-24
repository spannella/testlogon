import { describe, it, expect } from "vitest";

import type { RewardsStatus } from "@/api/endpoints/rewards";
import {
  STATUS_TIERS,
  statusTierForPoints,
  nextStatusTier,
  pointsToNextTier,
  progressToNextFraction,
  multiplierLabel,
  resolveStatus,
} from "./statusTiers";

describe("STATUS_TIERS table", () => {
  it("is ascending by threshold and starts at 0", () => {
    expect(STATUS_TIERS[0]?.thresholdPoints).toBe(0);
    for (let i = 1; i < STATUS_TIERS.length; i++) {
      expect(STATUS_TIERS[i]!.thresholdPoints).toBeGreaterThan(
        STATUS_TIERS[i - 1]!.thresholdPoints,
      );
    }
  });

  it("matches the canonical thresholds/multipliers", () => {
    expect(STATUS_TIERS.map((t) => t.thresholdPoints)).toEqual([
      0, 1000, 5000, 25000, 100000, 500000,
    ]);
    expect(STATUS_TIERS.map((t) => t.multiplierBps)).toEqual([
      10000, 10500, 11000, 12500, 15000, 20000,
    ]);
  });
});

describe("statusTierForPoints", () => {
  it("returns Member at the floor and for 0 / negative / non-finite", () => {
    expect(statusTierForPoints(0).id).toBe("member");
    expect(statusTierForPoints(-500).id).toBe("member");
    expect(statusTierForPoints(Number.NaN).id).toBe("member");
    expect(statusTierForPoints(999).id).toBe("member");
  });

  it("returns the tier at exact thresholds", () => {
    expect(statusTierForPoints(1000).id).toBe("bronze");
    expect(statusTierForPoints(5000).id).toBe("silver");
    expect(statusTierForPoints(25000).id).toBe("gold");
    expect(statusTierForPoints(100000).id).toBe("platinum");
    expect(statusTierForPoints(500000).id).toBe("diamond");
  });

  it("returns the highest tier at/below the balance", () => {
    expect(statusTierForPoints(4999).id).toBe("bronze");
    expect(statusTierForPoints(24999).id).toBe("silver");
    expect(statusTierForPoints(9_000_000).id).toBe("diamond");
  });
});

describe("nextStatusTier", () => {
  it("returns the next rung by tier or id", () => {
    expect(nextStatusTier("member")?.id).toBe("bronze");
    expect(nextStatusTier(STATUS_TIERS[2]!)?.id).toBe("gold");
  });

  it("returns null at the top tier and for unknown ids", () => {
    expect(nextStatusTier("diamond")).toBeNull();
    expect(nextStatusTier("nope")).toBeNull();
  });
});

describe("pointsToNextTier", () => {
  it("computes the gap to the next threshold", () => {
    expect(pointsToNextTier(0)).toBe(1000);
    expect(pointsToNextTier(600)).toBe(400);
    expect(pointsToNextTier(1000)).toBe(4000); // bronze -> silver
  });

  it("is 0 at/above the top tier", () => {
    expect(pointsToNextTier(500000)).toBe(0);
    expect(pointsToNextTier(9_000_000)).toBe(0);
  });
});

describe("progressToNextFraction", () => {
  it("is 0 at the current threshold and ~mid partway", () => {
    expect(progressToNextFraction(0)).toBe(0);
    expect(progressToNextFraction(500)).toBeCloseTo(0.5, 5); // half of 0->1000
    expect(progressToNextFraction(3000)).toBeCloseTo(0.5, 5); // 1000->5000, +2000
  });

  it("clamps to [0,1] and is 1.0 at the top tier", () => {
    expect(progressToNextFraction(-100)).toBe(0);
    expect(progressToNextFraction(500000)).toBe(1);
    expect(progressToNextFraction(9_000_000)).toBe(1);
  });
});

describe("multiplierLabel", () => {
  it("formats bps and trims trailing zeros", () => {
    expect(multiplierLabel(10000)).toBe("1x");
    expect(multiplierLabel(10500)).toBe("1.05x");
    expect(multiplierLabel(12500)).toBe("1.25x");
    expect(multiplierLabel(15000)).toBe("1.5x");
    expect(multiplierLabel(20000)).toBe("2x");
  });

  it("guards non-finite / non-positive as 1x", () => {
    expect(multiplierLabel(Number.NaN)).toBe("1x");
    expect(multiplierLabel(0)).toBe("1x");
    expect(multiplierLabel(-5)).toBe("1x");
  });
});

describe("resolveStatus", () => {
  it("computes client-side (estimated) when no authoritative payload", () => {
    const r = resolveStatus(1500);
    expect(r.source).toBe("estimated");
    expect(r.tierId).toBe("bronze");
    expect(r.name).toBe("Bronze");
    expect(r.nextName).toBe("Silver");
    expect(r.nextThreshold).toBe(5000);
    expect(r.pointsToNext).toBe(3500);
    expect(r.perks).toContain("Bronze badge");
  });

  it("tops out cleanly at diamond (estimated)", () => {
    const r = resolveStatus(600000);
    expect(r.tierId).toBe("diamond");
    expect(r.nextName).toBeNull();
    expect(r.nextThreshold).toBeNull();
    expect(r.pointsToNext).toBe(0);
    expect(r.progressFraction).toBe(1);
  });

  it("prefers the authoritative payload when present", () => {
    const auth: RewardsStatus = {
      tier_id: "gold",
      name: "Gold",
      lifetime_points: 30000,
      points_multiplier_bps: 12500,
      next_tier: { name: "Platinum", threshold_points: 100000 },
      perks: ["25% bonus points"],
    };
    const r = resolveStatus(0, auth);
    expect(r.source).toBe("authoritative");
    expect(r.name).toBe("Gold");
    expect(r.lifetimePoints).toBe(30000);
    expect(r.multiplierBps).toBe(12500);
    expect(r.nextName).toBe("Platinum");
    expect(r.pointsToNext).toBe(70000);
  });

  it("falls back to client compute when the authoritative payload is unusable", () => {
    const bad = { name: "", points_multiplier_bps: Number.NaN } as unknown as RewardsStatus;
    const r = resolveStatus(5000, bad);
    expect(r.source).toBe("estimated");
    expect(r.tierId).toBe("silver");
  });
});
