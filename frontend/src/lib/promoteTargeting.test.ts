import { describe, expect, it } from "vitest";

import {
  PROMOTE_ENTITY_KINDS,
  PROMOTE_ENTITY_LABELS,
  SEGMENT_OPTIONS,
  respectsOptInNote,
  buildTargetingPayload,
  buildPromotePayload,
  validatePromoteCampaign,
  summarizeTargeting,
  formatEstimatedReach,
} from "@/lib/promoteTargeting";

describe("PROMOTE_ENTITY_KINDS", () => {
  it("has the three entity kinds with labels", () => {
    expect(PROMOTE_ENTITY_KINDS).toEqual(["market", "creator_token", "product"]);
    for (const k of PROMOTE_ENTITY_KINDS) {
      expect(PROMOTE_ENTITY_LABELS[k]).toBeTruthy();
    }
  });
});

describe("SEGMENT_OPTIONS + opt-in note", () => {
  it("exposes non-empty preset lists", () => {
    expect(SEGMENT_OPTIONS.age_ranges.length).toBeGreaterThan(0);
    expect(SEGMENT_OPTIONS.genders.length).toBeGreaterThan(0);
    expect(SEGMENT_OPTIONS.countries.length).toBeGreaterThan(0);
    expect(SEGMENT_OPTIONS.device_types.length).toBeGreaterThan(0);
    expect(SEGMENT_OPTIONS.content_categories.length).toBeGreaterThan(0);
  });
  it("countries carry code+label", () => {
    const us = SEGMENT_OPTIONS.countries.find((c) => c.code === "US");
    expect(us?.label).toBe("United States");
  });
  it("opt-in note mentions personalization", () => {
    expect(respectsOptInNote.toLowerCase()).toContain("opted into personalization");
  });
});

describe("buildTargetingPayload", () => {
  it("drops empty arrays and unset fields", () => {
    const body = buildTargetingPayload({
      age_ranges: [],
      genders: [],
      country_codes: [],
    });
    expect(body).toEqual({ name: "Default" });
  });
  it("keeps only non-empty segments and trims name", () => {
    const body = buildTargetingPayload({
      name: "  Q3 push  ",
      country_codes: ["US", "CA"],
      age_ranges: ["18-24"],
      device_types: [],
      new_user_only: true,
    });
    expect(body).toEqual({
      name: "Q3 push",
      country_codes: ["US", "CA"],
      age_ranges: ["18-24"],
      new_user_only: true,
    });
  });
  it("omits new_user_only when false", () => {
    const body = buildTargetingPayload({ new_user_only: false });
    expect(body.new_user_only).toBeUndefined();
  });
  it("defaults name to Default when blank", () => {
    expect(buildTargetingPayload({ name: "   " }).name).toBe("Default");
  });
});

describe("buildPromotePayload", () => {
  it("builds a descriptor and trims the id", () => {
    expect(buildPromotePayload("market", "  sym-42 ")).toEqual({
      promote_kind: "market",
      promote_entity_id: "sym-42",
    });
  });
});

describe("validatePromoteCampaign", () => {
  it("passes a complete draft", () => {
    expect(
      validatePromoteCampaign({
        name: "Launch",
        budgetCents: 5000,
        kind: "product",
        entityId: "item-1",
      }),
    ).toEqual([]);
  });
  it("collects every missing/invalid field", () => {
    const errs = validatePromoteCampaign({
      name: "  ",
      budgetCents: 50,
      kind: null,
      entityId: "",
    });
    expect(errs.length).toBe(4);
    expect(errs.some((e) => /name/i.test(e))).toBe(true);
    expect(errs.some((e) => /budget/i.test(e))).toBe(true);
    expect(errs.some((e) => /promote/i.test(e))).toBe(true);
    expect(errs.some((e) => /item/i.test(e))).toBe(true);
  });
  it("rejects NaN budget", () => {
    const errs = validatePromoteCampaign({
      name: "x",
      budgetCents: Number.NaN,
      kind: "market",
      entityId: "m1",
    });
    expect(errs.some((e) => /budget/i.test(e))).toBe(true);
  });
});

describe("summarizeTargeting", () => {
  it("appends the opt-in suffix always", () => {
    expect(summarizeTargeting(null)).toBe("Everyone - opt-in only");
    expect(summarizeTargeting({})).toBe("Everyone - opt-in only");
  });
  it("joins the set segments", () => {
    const s = summarizeTargeting({
      country_codes: ["US"],
      age_ranges: ["18-24", "25-34"],
      device_types: ["mobile"],
    });
    expect(s).toBe("US, 18-24, 25-34, mobile - opt-in only");
  });
  it("includes new users flag", () => {
    expect(summarizeTargeting({ new_user_only: true })).toBe(
      "new users - opt-in only",
    );
  });
});

describe("formatEstimatedReach", () => {
  it("formats small, thousands, millions", () => {
    expect(formatEstimatedReach(0)).toBe("0");
    expect(formatEstimatedReach(999)).toBe("999");
    expect(formatEstimatedReach(1234)).toBe("1.2K");
    expect(formatEstimatedReach(2_500_000)).toBe("2.5M");
  });
  it("guards against negatives/NaN", () => {
    expect(formatEstimatedReach(-5)).toBe("0");
    expect(formatEstimatedReach(Number.NaN)).toBe("0");
  });
});
