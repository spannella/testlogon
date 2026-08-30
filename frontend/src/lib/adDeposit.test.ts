import { describe, expect, it } from "vitest";

import {
  PRESET_TOPUPS_CENTS,
  MIN_TOPUP_CENTS,
  MAX_TOPUP_CENTS,
  isValidTopUpCents,
  topUpLabel,
  newBalanceCents,
  dollarsToCents,
  centsToDollars,
} from "@/lib/adDeposit";

describe("adDeposit presets", () => {
  it("exposes ascending USD-cent presets", () => {
    expect(PRESET_TOPUPS_CENTS).toEqual([2500, 5000, 10000, 25000]);
    const sorted = [...PRESET_TOPUPS_CENTS].sort((a, b) => a - b);
    expect(PRESET_TOPUPS_CENTS).toEqual(sorted);
  });

  it("every preset is itself a valid top-up", () => {
    for (const c of PRESET_TOPUPS_CENTS) {
      expect(isValidTopUpCents(c)).toBe(true);
    }
  });
});

describe("isValidTopUpCents", () => {
  it("accepts the minimum and a mid value", () => {
    expect(isValidTopUpCents(MIN_TOPUP_CENTS)).toBe(true);
    expect(isValidTopUpCents(5000)).toBe(true);
    expect(isValidTopUpCents(MAX_TOPUP_CENTS)).toBe(true);
  });

  it("rejects below the $1 minimum", () => {
    expect(isValidTopUpCents(99)).toBe(false);
    expect(isValidTopUpCents(0)).toBe(false);
    expect(isValidTopUpCents(-100)).toBe(false);
  });

  it("rejects above the sane maximum", () => {
    expect(isValidTopUpCents(MAX_TOPUP_CENTS + 1)).toBe(false);
  });

  it("rejects non-integer and non-finite cents", () => {
    expect(isValidTopUpCents(100.5)).toBe(false);
    expect(isValidTopUpCents(NaN)).toBe(false);
    expect(isValidTopUpCents(Infinity)).toBe(false);
  });
});

describe("topUpLabel", () => {
  it("drops decimals for whole dollars", () => {
    expect(topUpLabel(2500)).toBe("$25");
    expect(topUpLabel(10000)).toBe("$100");
  });

  it("shows cents for fractional dollars", () => {
    expect(topUpLabel(12345)).toBe("$123.45");
    expect(topUpLabel(150)).toBe("$1.50");
  });

  it("thousands separators for large amounts", () => {
    expect(topUpLabel(1000000)).toBe("$10,000");
  });

  it("is safe for non-finite input", () => {
    expect(topUpLabel(NaN)).toBe("$0");
  });
});

describe("newBalanceCents", () => {
  it("adds current + top-up in cents", () => {
    expect(newBalanceCents(5000, 2500)).toBe(7500);
    expect(newBalanceCents(0, 10000)).toBe(10000);
  });

  it("treats non-finite inputs as 0", () => {
    expect(newBalanceCents(NaN, 2500)).toBe(2500);
    expect(newBalanceCents(5000, NaN)).toBe(5000);
    expect(newBalanceCents(NaN, NaN)).toBe(0);
  });

  it("rounds fractional cents defensively", () => {
    expect(newBalanceCents(100.4, 200.4)).toBe(300);
  });
});

describe("dollarsToCents / centsToDollars", () => {
  it("parses dollar strings to whole cents", () => {
    expect(dollarsToCents("25")).toBe(2500);
    expect(dollarsToCents("1.50")).toBe(150);
  });

  it("returns NaN for invalid dollar input", () => {
    expect(Number.isNaN(dollarsToCents("abc"))).toBe(true);
    expect(Number.isNaN(dollarsToCents(""))).toBe(true);
  });

  it("centsToDollars is the inverse for whole cents", () => {
    expect(centsToDollars(2500)).toBe(25);
    expect(centsToDollars(150)).toBe(1.5);
  });

  it("centsToDollars is safe for non-finite input", () => {
    expect(centsToDollars(NaN)).toBe(0);
  });
});
