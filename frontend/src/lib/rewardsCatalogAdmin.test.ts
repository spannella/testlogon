import { describe, it, expect } from "vitest";

import {
  validateCatalogItem,
  emptyDraft,
  formatPoints,
  formatCents,
} from "./rewardsCatalogAdmin";

describe("validateCatalogItem", () => {
  const valid = {
    name: "Gift Card",
    cost_points: 1000,
    value_cents: 500,
    kind: "cash" as const,
  };

  it("accepts a valid cash item", () => {
    const r = validateCatalogItem(valid);
    expect(r.ok).toBe(true);
    expect(r.errors).toEqual({});
  });

  it("accepts a valid perk with zero value", () => {
    const r = validateCatalogItem({ ...valid, kind: "perk", value_cents: 0 });
    expect(r.ok).toBe(true);
  });

  it("rejects an empty / whitespace name", () => {
    expect(validateCatalogItem({ ...valid, name: "" }).errors.name).toBeDefined();
    expect(validateCatalogItem({ ...valid, name: "   " }).errors.name).toBeDefined();
    expect(validateCatalogItem({ ...valid, name: "   " }).ok).toBe(false);
  });

  it("rejects non-positive or non-integer cost_points", () => {
    expect(validateCatalogItem({ ...valid, cost_points: 0 }).errors.cost_points).toBeDefined();
    expect(validateCatalogItem({ ...valid, cost_points: -5 }).errors.cost_points).toBeDefined();
    expect(validateCatalogItem({ ...valid, cost_points: 1.5 }).errors.cost_points).toBeDefined();
  });

  it("rejects negative or non-integer value_cents", () => {
    expect(validateCatalogItem({ ...valid, value_cents: -1 }).errors.value_cents).toBeDefined();
    expect(validateCatalogItem({ ...valid, kind: "perk", value_cents: 2.5 }).errors.value_cents).toBeDefined();
  });

  it("rejects an unknown kind", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const r = validateCatalogItem({ ...valid, kind: "gift" as any });
    expect(r.errors.kind).toBeDefined();
    expect(r.ok).toBe(false);
  });

  it("requires a cash reward to have value_cents > 0", () => {
    const r = validateCatalogItem({ ...valid, kind: "cash", value_cents: 0 });
    expect(r.ok).toBe(false);
    expect(r.errors.value_cents).toBeDefined();
  });

  it("accumulates multiple errors at once", () => {
    const r = validateCatalogItem({ name: "", cost_points: 0, value_cents: -1, kind: "cash" });
    expect(r.ok).toBe(false);
    expect(Object.keys(r.errors).sort()).toEqual(["cost_points", "name", "value_cents"]);
  });

  it("treats a blank/undefined stock_limit as valid (unlimited)", () => {
    expect(validateCatalogItem({ ...valid }).ok).toBe(true);
    expect(validateCatalogItem({ ...valid, stock_limit: undefined }).ok).toBe(true);
    expect(validateCatalogItem({ ...valid, stock_limit: null }).ok).toBe(true);
  });

  it("accepts a whole-number stock_limit >= 0", () => {
    expect(validateCatalogItem({ ...valid, stock_limit: 0 }).ok).toBe(true);
    expect(validateCatalogItem({ ...valid, stock_limit: 250 }).ok).toBe(true);
  });

  it("rejects a negative or non-integer stock_limit", () => {
    expect(validateCatalogItem({ ...valid, stock_limit: -1 }).errors.stock_limit).toBeDefined();
    expect(validateCatalogItem({ ...valid, stock_limit: 3.5 }).errors.stock_limit).toBeDefined();
    expect(validateCatalogItem({ ...valid, stock_limit: NaN }).ok).toBe(false);
  });
});


describe("emptyDraft", () => {
  it("is an inactive-safe blank perk draft that FAILS validation until filled", () => {
    const d = emptyDraft();
    expect(d).toEqual({
      name: "",
      description: "",
      cost_points: 0,
      value_cents: 0,
      kind: "perk",
      active: true,
      stock_limit: null,
    });
    expect(validateCatalogItem(d).ok).toBe(false);
  });

  it("returns a fresh object each call (no shared mutation)", () => {
    const a = emptyDraft();
    const b = emptyDraft();
    expect(a).not.toBe(b);
    a.name = "changed";
    expect(b.name).toBe("");
  });
});

describe("re-exported formatters", () => {
  it("formatPoints adds a unit and thousands separators", () => {
    expect(formatPoints(12345)).toBe("12,345 pts");
    expect(formatPoints(12345, false)).toBe("12,345");
  });

  it("formatCents renders integer cents as USD", () => {
    expect(formatCents(500)).toBe("$5.00");
    expect(formatCents(0)).toBe("$0.00");
  });
});
