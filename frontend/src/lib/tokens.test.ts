import { describe, expect, it } from "vitest";

import {
  bpsToFraction,
  bpsToPct,
  pctToBps,
  formatBps,
  formatCents,
  bpsToQty,
  qtyToBps,
  proRataShareCents,
  upkeepAmountDueCents,
  upkeepCoverageFraction,
  clearingSummary,
  UPKEEP_THRESHOLD_CENTS,
  CREATION_FEE_CENTS,
} from "./tokens";

describe("bps <-> pct/fraction", () => {
  it("converts bps to fraction and pct", () => {
    expect(bpsToFraction(10_000)).toBe(1);
    expect(bpsToFraction(250)).toBe(0.025);
    expect(bpsToPct(250)).toBeCloseTo(2.5, 6);
    expect(bpsToFraction(undefined)).toBe(0);
    expect(bpsToFraction(NaN)).toBe(0);
  });
  it("converts pct to bps with clamping + rounding", () => {
    expect(pctToBps(2.5)).toBe(250);
    expect(pctToBps(100)).toBe(10_000);
    expect(pctToBps(150)).toBe(10_000); // clamp to 100%
    expect(pctToBps(-5)).toBe(0);
    expect(pctToBps(1.234)).toBe(123); // round
  });
});

describe("formatters", () => {
  it("formats bps as percent", () => {
    expect(formatBps(250)).toBe("2.5%");
    expect(formatBps(10_000)).toBe("100%");
    expect(formatBps(0)).toBe("0%");
  });
  it("formats integer cents as dollars", () => {
    expect(formatCents(100_00)).toBe("$100.00");
    expect(formatCents(123456)).toBe("$1,234.56");
    expect(formatCents(undefined)).toBe("—");
    expect(formatCents(NaN)).toBe("—");
  });
});

describe("bps <-> qty", () => {
  it("computes qty from a bps slice of supply (floored)", () => {
    expect(bpsToQty(1_000_000, 2_000)).toBe(200_000); // 20%
    expect(bpsToQty(1000, 3333)).toBe(333); // floor
    expect(bpsToQty(0, 5000)).toBe(0);
    expect(bpsToQty(1000, 0)).toBe(0);
  });
  it("computes bps from a raw qty (rounded, clamped)", () => {
    expect(qtyToBps(200_000, 1_000_000)).toBe(2_000);
    expect(qtyToBps(1, 3)).toBe(3333); // round(3333.33)
    expect(qtyToBps(5, 0)).toBe(0);
    expect(qtyToBps(2_000_000, 1_000_000)).toBe(10_000); // clamp
  });
});

describe("proRataShareCents", () => {
  it("splits a bill by holding fraction (rounded)", () => {
    expect(proRataShareCents(100_00, 250_000, 1_000_000)).toBe(2500); // 25% of $100
    expect(proRataShareCents(100_00, 1_000_000, 1_000_000)).toBe(100_00); // sole holder
    expect(proRataShareCents(100_00, 0, 1_000_000)).toBe(0); // no holding
    expect(proRataShareCents(0, 500_000, 1_000_000)).toBe(0); // nothing due
    expect(proRataShareCents(100_00, 333_333, 1_000_000)).toBe(3333); // round
  });
});

describe("upkeep shortfall model", () => {
  it("charges the shortfall vs the $100 threshold", () => {
    expect(UPKEEP_THRESHOLD_CENTS).toBe(100_00);
    expect(CREATION_FEE_CENTS).toBe(100_00);
    expect(upkeepAmountDueCents(0)).toBe(100_00); // no fees -> full bill
    expect(upkeepAmountDueCents(40_00)).toBe(60_00); // partial coverage
    expect(upkeepAmountDueCents(100_00)).toBe(0); // exactly covered
    expect(upkeepAmountDueCents(250_00)).toBe(0); // over-covered -> 0
    expect(upkeepAmountDueCents(-5)).toBe(100_00); // negative fees treated as 0
  });
  it("reports a coverage fraction for the gauge", () => {
    expect(upkeepCoverageFraction(0)).toBe(0);
    expect(upkeepCoverageFraction(50_00)).toBe(0.5);
    expect(upkeepCoverageFraction(100_00)).toBe(1);
    expect(upkeepCoverageFraction(500_00)).toBe(1); // clamp
  });
});

describe("clearingSummary (single clearing price IPO)", () => {
  it("clears at the lowest price that fully sells the offered book", () => {
    // Offer 100 tokens. Bids: 60@120, 60@110, 40@100. Reserve 100.
    // demand@120=60, demand@110=120>=100, demand@100=160>=100.
    // Lowest fully-filling price = 100 -> all fill at 100.
    const s = clearingSummary(
      [
        { qty: 60, limit_price: 120 },
        { qty: 60, limit_price: 110 },
        { qty: 40, limit_price: 100 },
      ],
      100,
      100,
    );
    expect(s.cleared).toBe(true);
    expect(s.clearingPrice).toBe(100);
    expect(s.filledQty).toBe(100);
    expect(s.proceeds).toBe(10_000);
  });
  it("excludes bids below the reserve", () => {
    const s = clearingSummary(
      [
        { qty: 100, limit_price: 90 }, // below reserve -> ignored
        { qty: 50, limit_price: 100 },
      ],
      100,
      100,
    );
    // Only 50 qty is eligible -> cannot fully fill 100 -> partial at 100.
    expect(s.cleared).toBe(false);
    expect(s.clearingPrice).toBe(100);
    expect(s.filledQty).toBe(50);
  });
  it("returns not-cleared when nothing meets the reserve", () => {
    const s = clearingSummary([{ qty: 100, limit_price: 50 }], 100, 100);
    expect(s.cleared).toBe(false);
    expect(s.clearingPrice).toBeNull();
    expect(s.filledQty).toBe(0);
    expect(s.proceeds).toBe(0);
  });
  it("guards empty bids / non-positive offer", () => {
    expect(clearingSummary([], 100, 100).clearingPrice).toBeNull();
    expect(clearingSummary([{ qty: 10, limit_price: 100 }], 0, 100).clearingPrice).toBeNull();
  });
  it("partially fills at the top price when demand is thin", () => {
    // Offer 100 but only 70 total eligible demand -> partial at highest price.
    const s = clearingSummary(
      [
        { qty: 30, limit_price: 130 },
        { qty: 40, limit_price: 120 },
      ],
      100,
      100,
    );
    expect(s.cleared).toBe(false);
    expect(s.clearingPrice).toBe(130);
    expect(s.filledQty).toBe(30); // demand at top price (130) = 30
  });
});
