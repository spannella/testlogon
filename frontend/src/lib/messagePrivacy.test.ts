import { describe, expect, it } from "vitest";
import {
  defaultMessagePrivacy,
  normalizeMessagePrivacy,
  validateMinAmountCents,
  formatCents,
  isAllowlisted,
  isGatedForSender,
  describePrivacy,
  MAX_MIN_TIP_CENTS,
  type MessagePrivacy,
} from "./messagePrivacy";

describe("defaultMessagePrivacy", () => {
  it("returns an honest-empty gate", () => {
    expect(defaultMessagePrivacy()).toEqual({
      require_tip_to_message: false,
      min_tip_cents: 0,
      tip_free_allowlist: [],
    });
  });
  it("returns a fresh array each call (no shared mutation)", () => {
    const a = defaultMessagePrivacy();
    a.tip_free_allowlist.push("x");
    expect(defaultMessagePrivacy().tip_free_allowlist).toEqual([]);
  });
});

describe("normalizeMessagePrivacy", () => {
  it("defaults on null / non-object", () => {
    expect(normalizeMessagePrivacy(null)).toEqual(defaultMessagePrivacy());
    expect(normalizeMessagePrivacy(42)).toEqual(defaultMessagePrivacy());
    expect(normalizeMessagePrivacy(undefined)).toEqual(defaultMessagePrivacy());
  });
  it("coerces a well-formed record", () => {
    expect(
      normalizeMessagePrivacy({
        require_tip_to_message: true,
        min_tip_cents: 500,
        tip_free_allowlist: ["u1", "u2"],
      }),
    ).toEqual({ require_tip_to_message: true, min_tip_cents: 500, tip_free_allowlist: ["u1", "u2"] });
  });
  it("treats truthy-but-not-true require flag as false", () => {
    expect(normalizeMessagePrivacy({ require_tip_to_message: 1 }).require_tip_to_message).toBe(false);
  });
  it("floors fractional cents and zeroes negatives / NaN", () => {
    expect(normalizeMessagePrivacy({ min_tip_cents: 199.9 }).min_tip_cents).toBe(199);
    expect(normalizeMessagePrivacy({ min_tip_cents: -5 }).min_tip_cents).toBe(0);
    expect(normalizeMessagePrivacy({ min_tip_cents: "nope" }).min_tip_cents).toBe(0);
  });
  it("dedupes + trims + drops empties in the allowlist", () => {
    expect(
      normalizeMessagePrivacy({ tip_free_allowlist: ["a", " a ", "", "b", "a"] }).tip_free_allowlist,
    ).toEqual(["a", "b"]);
  });
});

describe("validateMinAmountCents", () => {
  it("accepts a valid integer cents value", () => {
    expect(validateMinAmountCents(500)).toEqual({ ok: true, cents: 500 });
  });
  it("accepts numeric strings", () => {
    expect(validateMinAmountCents("1234")).toEqual({ ok: true, cents: 1234 });
  });
  it("accepts zero", () => {
    expect(validateMinAmountCents(0)).toEqual({ ok: true, cents: 0 });
  });
  it("accepts the max boundary", () => {
    expect(validateMinAmountCents(MAX_MIN_TIP_CENTS)).toEqual({ ok: true, cents: MAX_MIN_TIP_CENTS });
  });
  it("rejects empty / non-numeric", () => {
    expect(validateMinAmountCents("").ok).toBe(false);
    expect(validateMinAmountCents("abc").ok).toBe(false);
  });
  it("rejects negatives", () => {
    const r = validateMinAmountCents(-1);
    expect(r.ok).toBe(false);
    expect(r.cents).toBe(0);
  });
  it("rejects fractional cents but reports the floor", () => {
    const r = validateMinAmountCents(10.5);
    expect(r.ok).toBe(false);
    expect(r.cents).toBe(10);
  });
  it("rejects over-cap and clamps the reported value", () => {
    const r = validateMinAmountCents(MAX_MIN_TIP_CENTS + 1);
    expect(r.ok).toBe(false);
    expect(r.cents).toBe(MAX_MIN_TIP_CENTS);
  });
});

describe("formatCents", () => {
  it("formats dollars and cents", () => {
    expect(formatCents(0)).toBe("$0.00");
    expect(formatCents(500)).toBe("$5.00");
    expect(formatCents(1234)).toBe("$12.34");
  });
  it("clamps negatives and rounds NaN to $0.00", () => {
    expect(formatCents(-100)).toBe("$0.00");
    expect(formatCents(Number.NaN)).toBe("$0.00");
  });
});

describe("isAllowlisted", () => {
  const p: MessagePrivacy = {
    require_tip_to_message: true,
    min_tip_cents: 100,
    tip_free_allowlist: ["friend-1", "friend-2"],
  };
  it("true for a listed user", () => {
    expect(isAllowlisted(p, "friend-1")).toBe(true);
    expect(isAllowlisted(p, " friend-2 ")).toBe(true);
  });
  it("false for an unlisted / empty user or null privacy", () => {
    expect(isAllowlisted(p, "stranger")).toBe(false);
    expect(isAllowlisted(p, "")).toBe(false);
    expect(isAllowlisted(null, "friend-1")).toBe(false);
  });
});

describe("isGatedForSender", () => {
  const p: MessagePrivacy = {
    require_tip_to_message: true,
    min_tip_cents: 100,
    tip_free_allowlist: ["friend-1"],
  };
  it("gates a stranger when the gate is on", () => {
    expect(isGatedForSender(p, "stranger")).toBe(true);
  });
  it("does not gate an allowlisted sender", () => {
    expect(isGatedForSender(p, "friend-1")).toBe(false);
  });
  it("does not gate when the gate is off", () => {
    expect(isGatedForSender({ ...p, require_tip_to_message: false }, "stranger")).toBe(false);
    expect(isGatedForSender(null, "stranger")).toBe(false);
  });
});

describe("describePrivacy", () => {
  it("describes an off gate", () => {
    expect(describePrivacy(defaultMessagePrivacy())).toBe("Anyone can message you for free.");
  });
  it("describes an on gate with no exemptions", () => {
    expect(
      describePrivacy({ require_tip_to_message: true, min_tip_cents: 250, tip_free_allowlist: [] }),
    ).toBe("New senders must tip at least $2.50 to reach your inbox.");
  });
  it("pluralizes the exemption count", () => {
    expect(
      describePrivacy({ require_tip_to_message: true, min_tip_cents: 100, tip_free_allowlist: ["a"] }),
    ).toContain("1 person is exempt");
    expect(
      describePrivacy({
        require_tip_to_message: true,
        min_tip_cents: 100,
        tip_free_allowlist: ["a", "b"],
      }),
    ).toContain("2 people are exempt");
  });
});
