import { describe, expect, it } from "vitest";

import {
  CENTS_PER_POINT,
  MIN_REDEEM_POINTS,
  cashCentsForPoints,
  pointsForCashCents,
  validatePointsRedemption,
  formatCents,
  formatPoints,
} from "@/lib/rewardsCash";

describe("canonical constants", () => {
  it("uses the shared 1 cent / point rate (100 pts = $1.00)", () => {
    expect(CENTS_PER_POINT).toBe(1);
    expect(cashCentsForPoints(100)).toBe(100);
  });

  it("has a $5.00 minimum (500 points)", () => {
    expect(MIN_REDEEM_POINTS).toBe(500);
    expect(cashCentsForPoints(MIN_REDEEM_POINTS)).toBe(500);
  });
});

describe("cashCentsForPoints", () => {
  it("converts points to integer cents at the default rate", () => {
    expect(cashCentsForPoints(0)).toBe(0);
    expect(cashCentsForPoints(500)).toBe(500);
    expect(cashCentsForPoints(1234)).toBe(1234);
  });

  it("honors a custom cents-per-point rate", () => {
    expect(cashCentsForPoints(100, 2)).toBe(200);
  });

  it("floors fractional and clamps negative / non-finite input", () => {
    expect(cashCentsForPoints(10.9)).toBe(10);
    expect(cashCentsForPoints(-50)).toBe(0);
    expect(cashCentsForPoints(Number.NaN)).toBe(0);
    expect(cashCentsForPoints(100, -3)).toBe(0);
  });
});

describe("pointsForCashCents", () => {
  it("is the integer inverse at the default rate", () => {
    expect(pointsForCashCents(500)).toBe(500);
    expect(pointsForCashCents(0)).toBe(0);
  });

  it("rounds UP to whole points", () => {
    expect(pointsForCashCents(150, 100)).toBe(2); // $1.50 needs 2 pts @ 100c/pt
    expect(pointsForCashCents(101, 100)).toBe(2);
  });

  it("clamps bad input and a zero rate", () => {
    expect(pointsForCashCents(-100)).toBe(0);
    expect(pointsForCashCents(Number.NaN)).toBe(0);
    expect(pointsForCashCents(500, 0)).toBe(0);
  });
});

describe("validatePointsRedemption", () => {
  it("accepts a whole amount at/above min and within balance", () => {
    expect(validatePointsRedemption(500, 1000)).toEqual({ ok: true });
    expect(validatePointsRedemption(1000, 1000)).toEqual({ ok: true });
  });

  it("rejects below the minimum", () => {
    const r = validatePointsRedemption(499, 10000);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/at least/i);
  });

  it("rejects more than the balance", () => {
    const r = validatePointsRedemption(1500, 1000);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/enough/i);
  });

  it("rejects zero / negative / non-finite", () => {
    expect(validatePointsRedemption(0, 1000).ok).toBe(false);
    expect(validatePointsRedemption(-5, 1000).ok).toBe(false);
    expect(validatePointsRedemption(Number.NaN, 1000).ok).toBe(false);
  });

  it("rejects fractional points", () => {
    const r = validatePointsRedemption(500.5, 1000);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/whole/i);
  });
});

describe("formatters", () => {
  it("formats points with separators and optional unit", () => {
    expect(formatPoints(12345)).toBe("12,345 pts");
    expect(formatPoints(12345, false)).toBe("12,345");
    expect(formatPoints(Number.NaN)).toBe("0 pts");
  });

  it("formats integer cents as USD", () => {
    expect(formatCents(500)).toBe("$5.00");
    expect(formatCents(1234)).toBe("$12.34");
    expect(formatCents(Number.NaN)).toBe("$0.00");
  });
});
