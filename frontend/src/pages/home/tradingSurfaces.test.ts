import { describe, expect, it } from "vitest";
import {
  TRADING_SURFACES,
  formatUnreadBadge,
  pickTopStrategy,
  formatReturnBps,
} from "./tradingSurfaces";

describe("TRADING_SURFACES", () => {
  it("lists the ten trading/investing surfaces with unique ids and absolute paths", () => {
    expect(TRADING_SURFACES).toHaveLength(10);
    const ids = new Set(TRADING_SURFACES.map((s) => s.id));
    expect(ids.size).toBe(10);
    for (const s of TRADING_SURFACES) {
      expect(s.path.startsWith("/")).toBe(true);
      expect(s.label.length).toBeGreaterThan(0);
      expect(s.desc.length).toBeGreaterThan(0);
      expect(typeof s.icon).toBe("object");
    }
  });

  it("covers the exact expected routes", () => {
    const paths = TRADING_SURFACES.map((s) => s.path).sort();
    expect(paths).toEqual(
      [
        "/invest",
        "/markets",
        "/strategies",
        "/portfolio/analytics",
        "/activity-center",
        "/algos",
        "/tokens",
        "/bailouts",
        "/custody/providers",
        "/reports/tax",
      ].sort(),
    );
  });
});

describe("formatUnreadBadge", () => {
  it("returns null for zero / negative / nullish / non-finite", () => {
    expect(formatUnreadBadge(0)).toBeNull();
    expect(formatUnreadBadge(-3)).toBeNull();
    expect(formatUnreadBadge(undefined)).toBeNull();
    expect(formatUnreadBadge(null)).toBeNull();
    expect(formatUnreadBadge(NaN)).toBeNull();
  });
  it("formats positive counts and caps at 99+", () => {
    expect(formatUnreadBadge(1)).toBe("1");
    expect(formatUnreadBadge(42)).toBe("42");
    expect(formatUnreadBadge(99)).toBe("99");
    expect(formatUnreadBadge(100)).toBe("99+");
    expect(formatUnreadBadge(2500)).toBe("99+");
  });
  it("floors fractional counts", () => {
    expect(formatUnreadBadge(3.9)).toBe("3");
  });
});

describe("pickTopStrategy", () => {
  it("returns undefined for empty / absent lists", () => {
    expect(pickTopStrategy(undefined)).toBeUndefined();
    expect(pickTopStrategy(null)).toBeUndefined();
    expect(pickTopStrategy([])).toBeUndefined();
  });
  it("picks the highest inception return", () => {
    const top = pickTopStrategy([
      { name: "A", inception_return_bps: 100 },
      { name: "B", inception_return_bps: 500 },
      { name: "C", inception_return_bps: 250 },
    ]);
    expect(top?.name).toBe("B");
  });
  it("tie-breaks by AUM", () => {
    const top = pickTopStrategy([
      { name: "A", inception_return_bps: 300, aum_cents: 1000 },
      { name: "B", inception_return_bps: 300, aum_cents: 9000 },
    ]);
    expect(top?.name).toBe("B");
  });
  it("treats missing return as lowest", () => {
    const top = pickTopStrategy([
      { name: "A" },
      { name: "B", inception_return_bps: 10 },
    ]);
    expect(top?.name).toBe("B");
  });
});

describe("formatReturnBps", () => {
  it("formats signed percentages", () => {
    expect(formatReturnBps(1230)).toBe("+12.3%");
    expect(formatReturnBps(-450)).toBe("-4.5%");
    expect(formatReturnBps(0)).toBe("0.0%");
  });
  it("degrades on nullish / non-finite", () => {
    expect(formatReturnBps(undefined)).toBe("—");
    expect(formatReturnBps(null)).toBe("—");
    expect(formatReturnBps(NaN)).toBe("—");
  });
});
