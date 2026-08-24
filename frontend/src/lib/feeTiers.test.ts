import { describe, expect, it } from "vitest";
import {
  FEE_TIERS,
  volume30dCents,
  tierForVolume,
  tierById,
  nextTier,
  progressToNextFraction,
  volumeToNextTierCents,
  makerTakerFeeCents,
  isTakerOrderType,
  orderFeeEstimateCents,
  type VolumeFill,
} from "./feeTiers";

const NOW = Date.parse("2026-06-15T00:00:00Z");
const DAY = 24 * 60 * 60 * 1000;
const daysAgoMs = (d: number) => NOW - d * DAY;

describe("FEE_TIERS canonical schedule", () => {
  it("has the six shared tiers in ascending threshold order", () => {
    expect(FEE_TIERS.map((t) => t.id)).toEqual([
      "standard",
      "bronze",
      "silver",
      "gold",
      "platinum",
      "diamond",
    ]);
    for (let i = 1; i < FEE_TIERS.length; i++) {
      expect(FEE_TIERS[i]!.minVolumeCents).toBeGreaterThan(FEE_TIERS[i - 1]!.minVolumeCents);
    }
  });

  it("matches the exact thresholds and rates", () => {
    expect(FEE_TIERS[0]).toMatchObject({ minVolumeCents: 0, makerBps: 10, takerBps: 15 });
    expect(FEE_TIERS[1]).toMatchObject({ minVolumeCents: 50_000_00, makerBps: 9, takerBps: 14 });
    expect(FEE_TIERS[2]).toMatchObject({ minVolumeCents: 250_000_00, makerBps: 8, takerBps: 12 });
    expect(FEE_TIERS[3]).toMatchObject({ minVolumeCents: 1_000_000_00, makerBps: 6, takerBps: 10 });
    expect(FEE_TIERS[4]).toMatchObject({ minVolumeCents: 5_000_000_00, makerBps: 4, takerBps: 8 });
    expect(FEE_TIERS[5]).toMatchObject({ minVolumeCents: 25_000_000_00, makerBps: 2, takerBps: 6 });
  });
});

describe("volume30dCents", () => {
  it("returns 0 for empty / non-array input", () => {
    expect(volume30dCents([], NOW)).toBe(0);
    expect(volume30dCents(undefined as never, NOW)).toBe(0);
  });

  it("sums notional (price*qty) of fills inside the window", () => {
    const fills: VolumeFill[] = [
      { ts: daysAgoMs(1), priceCents: 100_00, qty: 2 }, // 200_00
      { ts: daysAgoMs(10), priceCents: 50_00, qty: 3 }, // 150_00
    ];
    expect(volume30dCents(fills, NOW)).toBe(200_00 + 150_00);
  });

  it("excludes fills older than the window", () => {
    const fills: VolumeFill[] = [
      { ts: daysAgoMs(45), priceCents: 100_00, qty: 10 }, // outside 30d
      { ts: daysAgoMs(5), priceCents: 100_00, qty: 1 }, // inside
    ];
    expect(volume30dCents(fills, NOW)).toBe(100_00);
  });

  it("respects a custom window", () => {
    const fills: VolumeFill[] = [
      { ts: daysAgoMs(20), priceCents: 100_00, qty: 1 },
      { ts: daysAgoMs(3), priceCents: 100_00, qty: 1 },
    ];
    expect(volume30dCents(fills, NOW, 7)).toBe(100_00);
  });

  it("accepts second-precision timestamps", () => {
    const fills: VolumeFill[] = [{ ts: Math.floor(daysAgoMs(2) / 1000), priceCents: 10_00, qty: 5 }];
    expect(volume30dCents(fills, NOW)).toBe(50_00);
  });

  it("ignores non-positive / non-finite price or qty and floors notional", () => {
    const fills: VolumeFill[] = [
      { ts: daysAgoMs(1), priceCents: -100, qty: 5 },
      { ts: daysAgoMs(1), priceCents: 100, qty: 0 },
      { ts: daysAgoMs(1), priceCents: NaN, qty: 5 },
      { ts: daysAgoMs(1), priceCents: 333, qty: 1.5 }, // 499.5 -> 499
    ];
    expect(volume30dCents(fills, NOW)).toBe(499);
  });

  it("never returns negative", () => {
    expect(volume30dCents([{ ts: daysAgoMs(1), priceCents: -1, qty: -1 }], NOW)).toBe(0);
  });
});

describe("tierForVolume / tierById", () => {
  it("maps volume to the correct tier boundaries", () => {
    expect(tierForVolume(0).id).toBe("standard");
    expect(tierForVolume(49_999_99).id).toBe("standard");
    expect(tierForVolume(50_000_00).id).toBe("bronze");
    expect(tierForVolume(250_000_00).id).toBe("silver");
    expect(tierForVolume(1_000_000_00).id).toBe("gold");
    expect(tierForVolume(5_000_000_00).id).toBe("platinum");
    expect(tierForVolume(25_000_000_00).id).toBe("diamond");
    expect(tierForVolume(999_999_999_00).id).toBe("diamond");
  });

  it("guards negative / non-finite volume to Standard", () => {
    expect(tierForVolume(-100).id).toBe("standard");
    expect(tierForVolume(NaN).id).toBe("standard");
  });

  it("tierById resolves canonical ids", () => {
    expect(tierById("gold")?.makerBps).toBe(6);
    expect(tierById("nope")).toBeUndefined();
  });
});

describe("nextTier", () => {
  it("returns the next-higher tier", () => {
    expect(nextTier(FEE_TIERS[0]!)?.id).toBe("bronze");
    expect(nextTier(FEE_TIERS[4]!)?.id).toBe("diamond");
  });
  it("returns null at the top tier", () => {
    expect(nextTier(FEE_TIERS[5]!)).toBeNull();
  });
});

describe("progressToNextFraction", () => {
  it("is 0 at the current tier threshold", () => {
    expect(progressToNextFraction(0)).toBe(0);
    expect(progressToNextFraction(50_000_00)).toBe(0);
  });
  it("is ~0.5 halfway between thresholds", () => {
    // halfway between bronze(50k) and silver(250k) = 150k
    expect(progressToNextFraction(150_000_00)).toBeCloseTo(0.5, 5);
  });
  it("clamps to 1.0 at the top tier", () => {
    expect(progressToNextFraction(25_000_000_00)).toBe(1);
    expect(progressToNextFraction(999_999_999_00)).toBe(1);
  });
  it("guards negative volume", () => {
    expect(progressToNextFraction(-5)).toBe(0);
  });
});

describe("volumeToNextTierCents", () => {
  it("computes the remaining volume to the next tier", () => {
    expect(volumeToNextTierCents(0)).toBe(50_000_00);
    expect(volumeToNextTierCents(150_000_00)).toBe(100_000_00); // to silver 250k
  });
  it("is 0 at the top tier", () => {
    expect(volumeToNextTierCents(25_000_000_00)).toBe(0);
  });
});

describe("makerTakerFeeCents", () => {
  it("computes fee = notional * bps / 10000 (rounded)", () => {
    expect(makerTakerFeeCents(1_000_000_00, 15)).toBe(1_500_00); // $1,000,000 @ 15bps = $1,500
    expect(makerTakerFeeCents(100_00, 10)).toBe(10); // $100 @ 10bps = $0.10
  });
  it("rounds half-up", () => {
    expect(makerTakerFeeCents(3333, 15)).toBe(5); // 4.9995 -> 5
  });
  it("guards non-positive inputs", () => {
    expect(makerTakerFeeCents(0, 15)).toBe(0);
    expect(makerTakerFeeCents(100_00, 0)).toBe(0);
    expect(makerTakerFeeCents(-1, 15)).toBe(0);
    expect(makerTakerFeeCents(NaN, 15)).toBe(0);
  });
});


describe("isTakerOrderType", () => {
  it("classifies book-crossing types as taker", () => {
    expect(isTakerOrderType("market")).toBe(true);
    expect(isTakerOrderType("stop")).toBe(true);
    expect(isTakerOrderType("take_profit")).toBe(true);
  });
  it("classifies resting-limit types as maker", () => {
    expect(isTakerOrderType("limit")).toBe(false);
    expect(isTakerOrderType("stop_limit")).toBe(false);
  });
  it("post-only forces maker even for a would-be taker", () => {
    expect(isTakerOrderType("market", true)).toBe(false);
    expect(isTakerOrderType("limit", true)).toBe(false);
  });
  it("defaults unknown types to taker (conservative)", () => {
    expect(isTakerOrderType("weird" as never)).toBe(true);
    expect(isTakerOrderType("weird" as never, true)).toBe(false);
  });
});

describe("orderFeeEstimateCents", () => {
  it("uses the taker rate for a market order", () => {
    // $10,000 @ 15bps taker = $15.00
    expect(orderFeeEstimateCents(1_000_000, 10, 15, "market")).toBe(15_00);
  });
  it("uses the maker rate for a resting limit order", () => {
    // $10,000 @ 10bps maker = $10.00
    expect(orderFeeEstimateCents(1_000_000, 10, 15, "limit")).toBe(10_00);
  });
  it("post-only limit stays on the maker rate", () => {
    expect(orderFeeEstimateCents(1_000_000, 10, 15, "limit", true)).toBe(10_00);
  });
  it("post-only market drops from taker to maker rate", () => {
    expect(orderFeeEstimateCents(1_000_000, 10, 15, "market", true)).toBe(10_00);
  });
  it("guards non-positive notional to 0", () => {
    expect(orderFeeEstimateCents(0, 10, 15, "market")).toBe(0);
    expect(orderFeeEstimateCents(-5, 10, 15, "limit")).toBe(0);
  });
});
