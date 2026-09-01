import { describe, expect, it } from "vitest";

import {
  MAX_TIP_CENTS,
  parseTipDollarsToCents,
  validateTipCents,
} from "./videoCommentTip";

describe("validateTipCents", () => {
  it("accepts a normal positive integer cents value", () => {
    expect(validateTipCents(100)).toEqual({ ok: true, cents: 100 });
  });

  it("accepts the maximum allowed value", () => {
    expect(validateTipCents(MAX_TIP_CENTS)).toEqual({
      ok: true,
      cents: MAX_TIP_CENTS,
    });
  });

  it("rejects zero", () => {
    const r = validateTipCents(0);
    expect(r.ok).toBe(false);
    expect(r.cents).toBeUndefined();
    expect(r.error).toBeTruthy();
  });

  it("rejects negative amounts", () => {
    expect(validateTipCents(-50).ok).toBe(false);
  });

  it("rejects non-integer cents", () => {
    const r = validateTipCents(12.5);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/whole number/i);
  });

  it("rejects amounts over the ceiling", () => {
    expect(validateTipCents(MAX_TIP_CENTS + 1).ok).toBe(false);
  });

  it("rejects NaN and Infinity", () => {
    expect(validateTipCents(NaN).ok).toBe(false);
    expect(validateTipCents(Infinity).ok).toBe(false);
  });

  it("rejects non-number inputs", () => {
    expect(validateTipCents("100").ok).toBe(false);
    expect(validateTipCents(null).ok).toBe(false);
    expect(validateTipCents(undefined).ok).toBe(false);
  });
});

describe("parseTipDollarsToCents", () => {
  it("parses whole dollars", () => {
    expect(parseTipDollarsToCents("5")).toBe(500);
  });

  it("parses fractional dollars", () => {
    expect(parseTipDollarsToCents("2.50")).toBe(250);
  });

  it("rounds to the nearest cent", () => {
    expect(parseTipDollarsToCents("2.505")).toBe(251);
  });

  it("returns null for empty / whitespace input", () => {
    expect(parseTipDollarsToCents("")).toBeNull();
    expect(parseTipDollarsToCents("   ")).toBeNull();
  });

  it("returns null for non-numeric or non-positive input", () => {
    expect(parseTipDollarsToCents("abc")).toBeNull();
    expect(parseTipDollarsToCents("0")).toBeNull();
    expect(parseTipDollarsToCents("-3")).toBeNull();
  });

  it("round-trips into a valid tip", () => {
    const cents = parseTipDollarsToCents("2.50");
    expect(cents).not.toBeNull();
    expect(validateTipCents(cents as number)).toEqual({ ok: true, cents: 250 });
  });
});
