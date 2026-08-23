import { describe, expect, it } from "vitest";

import {
  MIN_CASH_CENTS,
  dollarsToCents,
  formatCents,
  validateDeposit,
  validateWithdraw,
} from "@/lib/cashMath";

describe("dollarsToCents", () => {
  it("parses whole and fractional dollars to cents", () => {
    expect(dollarsToCents("1")).toBe(100);
    expect(dollarsToCents("10.50")).toBe(1050);
    expect(dollarsToCents(".99")).toBe(99);
    expect(dollarsToCents("0.01")).toBe(1);
  });

  it("rounds fractional inputs to whole cents", () => {
    expect(dollarsToCents("1.004")).toBe(100);
    expect(dollarsToCents("1.006")).toBe(101);
    expect(dollarsToCents(19.99)).toBe(1999);
    expect(dollarsToCents("0.125")).toBe(13);
  });

  it("returns NaN for blank / non-numeric / negative", () => {
    expect(dollarsToCents("")).toBeNaN();
    expect(dollarsToCents("   ")).toBeNaN();
    expect(dollarsToCents("abc")).toBeNaN();
    expect(dollarsToCents("-5")).toBeNaN();
    expect(dollarsToCents("1.2.3")).toBeNaN();
    expect(dollarsToCents(-1)).toBeNaN();
    expect(dollarsToCents(NaN)).toBeNaN();
  });
});

describe("formatCents", () => {
  it("formats USD cents", () => {
    expect(formatCents(100)).toBe("$1.00");
    expect(formatCents(1050)).toBe("$10.50");
    expect(formatCents(0)).toBe("$0.00");
  });

  it("falls back to $0.00 for non-finite input", () => {
    expect(formatCents(NaN)).toBe("$0.00");
  });
});

describe("validateDeposit", () => {
  it("accepts amounts at or above the minimum", () => {
    expect(validateDeposit("1")).toEqual({ cents: 100, valid: true, reason: null });
    expect(validateDeposit("250.00").valid).toBe(true);
  });

  it("rejects below the $1 minimum", () => {
    const r = validateDeposit("0.50");
    expect(r.valid).toBe(false);
    expect(r.cents).toBe(50);
    expect(r.reason).toContain("Minimum");
  });

  it("rejects unparseable input", () => {
    const r = validateDeposit("xyz");
    expect(r.valid).toBe(false);
    expect(r.cents).toBeNaN();
    expect(r.reason).toBe("Enter a valid amount");
  });

  it("uses MIN_CASH_CENTS as the floor", () => {
    expect(validateDeposit(MIN_CASH_CENTS / 100).valid).toBe(true);
    expect(validateDeposit((MIN_CASH_CENTS - 1) / 100).valid).toBe(false);
  });
});

describe("validateWithdraw", () => {
  it("accepts amounts within balance", () => {
    expect(validateWithdraw("10", 5000).valid).toBe(true);
    expect(validateWithdraw("50", 5000).valid).toBe(true);
  });

  it("rejects amounts exceeding balance", () => {
    const r = validateWithdraw("60", 5000);
    expect(r.valid).toBe(false);
    expect(r.reason).toContain("Exceeds balance");
  });

  it("rejects below minimum before checking balance", () => {
    const r = validateWithdraw("0.50", 100000);
    expect(r.valid).toBe(false);
    expect(r.reason).toContain("Minimum");
  });

  it("treats a non-finite balance as zero", () => {
    expect(validateWithdraw("1", NaN).valid).toBe(false);
  });
});
