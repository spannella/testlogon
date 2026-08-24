import { describe, expect, it } from "vitest";

import type { CatalogReward, ReferralEntry } from "@/api/endpoints/rewards";
import {
  canRedeem,
  formatCents,
  formatPoints,
  isOutOfStock,
  pointsAfterRedeem,
  redeemableCatalog,
  referralEarnedCents,
  referralPendingCents,
  referralShareText,
  referralStatusCounts,
  remainingStock,
  stockLabel,
} from "@/lib/rewards";

function ref(partial: Partial<ReferralEntry>): ReferralEntry {
  return {
    id: partial.id ?? "r1",
    masked_name: partial.masked_name ?? "J•• D••",
    joined_ts: partial.joined_ts ?? 0,
    status: partial.status ?? "pending",
    reward_cents: partial.reward_cents ?? 0,
  };
}

function reward(partial: Partial<CatalogReward>): CatalogReward {
  return {
    id: partial.id ?? "c1",
    name: partial.name ?? "Reward",
    description: partial.description ?? "",
    cost_points: partial.cost_points ?? 100,
    value_cents: partial.value_cents ?? 100,
    kind: partial.kind ?? "cash",
    stock_limit: partial.stock_limit,
    redeemed_count: partial.redeemed_count,
  };
}

describe("canRedeem", () => {
  it("is true when points meet or exceed cost", () => {
    expect(canRedeem(100, 100)).toBe(true);
    expect(canRedeem(150, 100)).toBe(true);
  });
  it("is false when points are short", () => {
    expect(canRedeem(99, 100)).toBe(false);
  });
  it("is false for non-positive cost or bad input", () => {
    expect(canRedeem(100, 0)).toBe(false);
    expect(canRedeem(100, -5)).toBe(false);
    expect(canRedeem(NaN as unknown as number, 100)).toBe(false);
  });
});

describe("pointsAfterRedeem", () => {
  it("subtracts cost from points", () => {
    expect(pointsAfterRedeem(500, 200)).toBe(300);
  });
  it("never goes below zero", () => {
    expect(pointsAfterRedeem(100, 250)).toBe(0);
  });
  it("clamps negative cost", () => {
    expect(pointsAfterRedeem(100, -50)).toBe(100);
  });
});

describe("referralEarnedCents", () => {
  it("sums only rewarded referrals", () => {
    const list = [
      ref({ status: "rewarded", reward_cents: 500 }),
      ref({ status: "rewarded", reward_cents: 250 }),
      ref({ status: "qualified", reward_cents: 500 }),
      ref({ status: "pending", reward_cents: 500 }),
    ];
    expect(referralEarnedCents(list)).toBe(750);
  });
  it("returns 0 for empty / bad input", () => {
    expect(referralEarnedCents([])).toBe(0);
    expect(referralEarnedCents(undefined as unknown as ReferralEntry[])).toBe(0);
  });
});

describe("referralPendingCents", () => {
  it("sums pending + qualified referrals only", () => {
    const list = [
      ref({ status: "rewarded", reward_cents: 500 }),
      ref({ status: "qualified", reward_cents: 250 }),
      ref({ status: "pending", reward_cents: 100 }),
    ];
    expect(referralPendingCents(list)).toBe(350);
  });
});

describe("referralStatusCounts", () => {
  it("counts each status", () => {
    const list = [
      ref({ status: "pending" }),
      ref({ status: "pending" }),
      ref({ status: "qualified" }),
      ref({ status: "rewarded" }),
    ];
    expect(referralStatusCounts(list)).toEqual({ pending: 2, qualified: 1, rewarded: 1 });
  });
  it("returns zeros for empty", () => {
    expect(referralStatusCounts([])).toEqual({ pending: 0, qualified: 0, rewarded: 0 });
  });
});

describe("redeemableCatalog", () => {
  it("marks affordable vs locked based on points", () => {
    const catalog = [
      reward({ id: "a", cost_points: 100 }),
      reward({ id: "b", cost_points: 500 }),
    ];
    const out = redeemableCatalog(catalog, 200);
    expect(out.find((r) => r.id === "a")?.affordable).toBe(true);
    expect(out.find((r) => r.id === "b")?.affordable).toBe(false);
  });
  it("returns [] for bad input", () => {
    expect(redeemableCatalog(undefined as unknown as CatalogReward[], 100)).toEqual([]);
  });
});

describe("remainingStock", () => {
  it("returns null (unlimited) when no stock_limit is set", () => {
    expect(remainingStock(reward({}))).toBeNull();
    expect(remainingStock(reward({ stock_limit: null }))).toBeNull();
  });
  it("subtracts redeemed_count from the limit", () => {
    expect(remainingStock(reward({ stock_limit: 10, redeemed_count: 3 }))).toBe(7);
    expect(remainingStock(reward({ stock_limit: 5 }))).toBe(5);
  });
  it("clamps at zero when over-redeemed", () => {
    expect(remainingStock(reward({ stock_limit: 2, redeemed_count: 9 }))).toBe(0);
  });
});

describe("isOutOfStock", () => {
  it("is false for unlimited items", () => {
    expect(isOutOfStock(reward({}))).toBe(false);
  });
  it("is true only when a limited item has zero remaining", () => {
    expect(isOutOfStock(reward({ stock_limit: 3, redeemed_count: 3 }))).toBe(true);
    expect(isOutOfStock(reward({ stock_limit: 3, redeemed_count: 1 }))).toBe(false);
  });
});

describe("stockLabel", () => {
  it("labels unlimited, remaining, and sold-out", () => {
    expect(stockLabel(reward({}))).toBe("Unlimited");
    expect(stockLabel(reward({ stock_limit: 1200, redeemed_count: 200 }))).toBe("1,000 left");
    expect(stockLabel(reward({ stock_limit: 4, redeemed_count: 4 }))).toBe("Out of stock");
  });
});

describe("redeemableCatalog + stock", () => {
  it("marks an out-of-stock but affordable item as NOT affordable", () => {
    const catalog = [
      reward({ id: "u", cost_points: 100 }), // unlimited, affordable
      reward({ id: "s", cost_points: 100, stock_limit: 2, redeemed_count: 2 }), // sold out
    ];
    const out = redeemableCatalog(catalog, 1000);
    expect(out.find((r) => r.id === "u")?.affordable).toBe(true);
    expect(out.find((r) => r.id === "s")?.affordable).toBe(false);
  });
  it("keeps an in-stock affordable item redeemable", () => {
    const out = redeemableCatalog(
      [reward({ id: "k", cost_points: 100, stock_limit: 5, redeemed_count: 1 })],
      500,
    );
    expect(out.find((r) => r.id === "k")?.affordable).toBe(true);
  });
});

describe("formatPoints", () => {
  it("adds thousands separators and unit", () => {
    expect(formatPoints(12345)).toBe("12,345 pts");
  });
  it("can omit the unit and truncates fractional", () => {
    expect(formatPoints(1000.9, false)).toBe("1,000");
  });
});

describe("formatCents", () => {
  it("formats integer cents as USD", () => {
    expect(formatCents(1050)).toBe("$10.50");
    expect(formatCents(0)).toBe("$0.00");
  });
  it("treats non-finite as 0", () => {
    expect(formatCents(NaN)).toBe("$0.00");
  });
});

describe("referralShareText", () => {
  it("includes code and link", () => {
    const t = referralShareText("ABC123", "https://x.test/r/ABC123");
    expect(t).toContain("ABC123");
    expect(t).toContain("https://x.test/r/ABC123");
  });
  it("degrades when code or link missing", () => {
    expect(referralShareText("", "https://x.test")).toContain("https://x.test");
    expect(referralShareText("ABC", "")).toContain("ABC");
    expect(referralShareText("", "")).toBe("Join me here!");
  });
});
