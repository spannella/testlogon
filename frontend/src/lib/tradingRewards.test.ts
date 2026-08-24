import { describe, expect, it } from "vitest";

import type { TradingRewards } from "@/api/endpoints/rewards";
import {
  POINTS_PER_DOLLAR,
  tradingPointsForVolumeCents,
  tradingRewardsSummary,
  volumeForPoints,
} from "@/lib/tradingRewards";

describe("POINTS_PER_DOLLAR", () => {
  it("is the canonical 1 point per dollar", () => {
    expect(POINTS_PER_DOLLAR).toBe(1);
  });
});

describe("tradingPointsForVolumeCents", () => {
  it("floors to whole points at the default rate (1 pt / $1)", () => {
    expect(tradingPointsForVolumeCents(100_00)).toBe(100);
    expect(tradingPointsForVolumeCents(150_50)).toBe(150); // $150.50 -> 150
    expect(tradingPointsForVolumeCents(99)).toBe(0); // $0.99 -> 0
  });

  it("honors a custom rate", () => {
    expect(tradingPointsForVolumeCents(100_00, 2)).toBe(200);
    expect(tradingPointsForVolumeCents(100_00, 0.5)).toBe(50);
  });

  it("guards zero / negative / non-finite volume", () => {
    expect(tradingPointsForVolumeCents(0)).toBe(0);
    expect(tradingPointsForVolumeCents(-500_00)).toBe(0);
    expect(tradingPointsForVolumeCents(Number.NaN)).toBe(0);
    expect(tradingPointsForVolumeCents(Number.POSITIVE_INFINITY)).toBe(0);
  });

  it("guards a non-positive rate", () => {
    expect(tradingPointsForVolumeCents(100_00, 0)).toBe(0);
    expect(tradingPointsForVolumeCents(100_00, -1)).toBe(0);
    expect(tradingPointsForVolumeCents(100_00, Number.NaN)).toBe(0);
  });
});

describe("volumeForPoints", () => {
  it("is the inverse at the default rate (returns cents)", () => {
    expect(volumeForPoints(100)).toBe(100_00);
    expect(volumeForPoints(1)).toBe(1_00);
  });

  it("honors a custom rate", () => {
    expect(volumeForPoints(200, 2)).toBe(100_00);
    expect(volumeForPoints(50, 0.5)).toBe(100_00);
  });

  it("round-trips with tradingPointsForVolumeCents on whole dollars", () => {
    const cents = 1234_00;
    const pts = tradingPointsForVolumeCents(cents);
    expect(volumeForPoints(pts)).toBe(cents);
  });

  it("guards zero / negative / non-finite input", () => {
    expect(volumeForPoints(0)).toBe(0);
    expect(volumeForPoints(-10)).toBe(0);
    expect(volumeForPoints(Number.NaN)).toBe(0);
    expect(volumeForPoints(100, 0)).toBe(0);
  });
});

describe("tradingRewardsSummary", () => {
  it("estimates from volume when no authoritative payload is present", () => {
    const s = tradingRewardsSummary(250_00);
    expect(s.source).toBe("estimated");
    expect(s.pointsPerDollar).toBe(POINTS_PER_DOLLAR);
    expect(s.volume30dCents).toBe(250_00);
    expect(s.pointsEarned30d).toBe(250);
    expect(s.lifetimeTradingPoints).toBe(0);
  });

  it("clamps a negative estimate volume to zero", () => {
    const s = tradingRewardsSummary(-100_00);
    expect(s.volume30dCents).toBe(0);
    expect(s.pointsEarned30d).toBe(0);
    expect(s.source).toBe("estimated");
  });

  it("prefers a valid authoritative payload", () => {
    const auth: TradingRewards = {
      points_per_dollar: 2,
      volume_30d_cents: 500_00,
      points_earned_30d: 1000,
      lifetime_trading_points: 42_000,
    };
    const s = tradingRewardsSummary(1_00, auth);
    expect(s.source).toBe("authoritative");
    expect(s.pointsPerDollar).toBe(2);
    expect(s.volume30dCents).toBe(500_00);
    expect(s.pointsEarned30d).toBe(1000);
    expect(s.lifetimeTradingPoints).toBe(42_000);
  });

  it("derives points_earned_30d from volume when the payload omits it", () => {
    const auth = {
      points_per_dollar: 1,
      volume_30d_cents: 300_00,
      points_earned_30d: Number.NaN,
      lifetime_trading_points: Number.NaN,
    } as unknown as TradingRewards;
    const s = tradingRewardsSummary(0, auth);
    expect(s.source).toBe("authoritative");
    expect(s.pointsEarned30d).toBe(300);
    expect(s.lifetimeTradingPoints).toBe(0);
  });

  it("falls back to the estimate when the authoritative rate is invalid", () => {
    const auth = {
      points_per_dollar: 0,
      volume_30d_cents: 999_00,
      points_earned_30d: 999,
      lifetime_trading_points: 9,
    } as TradingRewards;
    const s = tradingRewardsSummary(120_00, auth);
    expect(s.source).toBe("estimated");
    expect(s.volume30dCents).toBe(120_00);
    expect(s.pointsEarned30d).toBe(120);
  });
});
