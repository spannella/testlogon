import { describe, expect, it } from "vitest";

import type {
  ReferralLeaderboardEntry,
  ReferralLeaderboardYou,
} from "@/api/endpoints/rewards";
import {
  findYou,
  formatCount,
  formatRank,
  rankMedal,
  sortEntries,
  topN,
} from "@/lib/referralLeaderboard";

function entry(
  partial: Partial<ReferralLeaderboardEntry>,
): ReferralLeaderboardEntry {
  return {
    rank: partial.rank ?? 1,
    id: partial.id ?? "u1",
    masked_name: partial.masked_name ?? "A•• B••",
    is_you: partial.is_you ?? false,
    referred_count: partial.referred_count ?? 0,
    qualified_count: partial.qualified_count ?? 0,
    reward_cents: partial.reward_cents ?? 0,
  };
}

describe("rankMedal", () => {
  it("maps podium ranks to medals", () => {
    expect(rankMedal(1)).toBe("gold");
    expect(rankMedal(2)).toBe("silver");
    expect(rankMedal(3)).toBe("bronze");
  });

  it("returns null off the podium and for junk", () => {
    expect(rankMedal(4)).toBeNull();
    expect(rankMedal(0)).toBeNull();
    expect(rankMedal(-1)).toBeNull();
    expect(rankMedal(Number.NaN)).toBeNull();
  });
});

describe("sortEntries", () => {
  it("sorts by rank ascending", () => {
    const out = sortEntries([
      entry({ id: "c", rank: 3 }),
      entry({ id: "a", rank: 1 }),
      entry({ id: "b", rank: 2 }),
    ]);
    expect(out.map((e) => e.id)).toEqual(["a", "b", "c"]);
  });

  it("breaks rank ties by reward_cents descending, then referred_count", () => {
    const out = sortEntries([
      entry({ id: "lowReward", rank: 5, reward_cents: 100, referred_count: 9 }),
      entry({ id: "hiReward", rank: 5, reward_cents: 900, referred_count: 1 }),
    ]);
    expect(out.map((e) => e.id)).toEqual(["hiReward", "lowReward"]);
  });

  it("is pure (does not mutate input) and tolerates junk", () => {
    const input = [entry({ id: "b", rank: 2 }), entry({ id: "a", rank: 1 })];
    const copy = [...input];
    sortEntries(input);
    expect(input).toEqual(copy);
    // @ts-expect-error exercising defensive path
    expect(sortEntries(null)).toEqual([]);
  });
});

describe("topN", () => {
  const rows = [
    entry({ id: "a", rank: 1 }),
    entry({ id: "b", rank: 2 }),
    entry({ id: "c", rank: 3 }),
    entry({ id: "d", rank: 4 }),
  ];

  it("returns the first n sorted entries", () => {
    expect(topN(rows, 2).map((e) => e.id)).toEqual(["a", "b"]);
  });

  it("clamps out-of-range n", () => {
    expect(topN(rows, 0)).toEqual([]);
    expect(topN(rows, -5)).toEqual([]);
    expect(topN(rows, 99).map((e) => e.id)).toEqual(["a", "b", "c", "d"]);
  });
});

describe("findYou", () => {
  const rows = [
    entry({ id: "a", rank: 1 }),
    entry({ id: "b", rank: 2 }),
    entry({ id: "me", rank: 12, is_you: true, reward_cents: 500 }),
    entry({ id: "c", rank: 3 }),
  ];

  it("finds the is_you row and pins it when outside the shown slice", () => {
    const shown = topN(rows.filter((r) => !r.is_you), 2); // a, b
    const res = findYou(rows, shown);
    expect(res.entry?.id).toBe("me");
    expect(res.inShown).toBe(false);
    expect(res.pinned?.id).toBe("me");
  });

  it("does not pin when the caller is already shown", () => {
    const you = entry({ id: "me", rank: 1, is_you: true });
    const all = [you, entry({ id: "b", rank: 2 })];
    const shown = topN(all, 5);
    const res = findYou(all, shown);
    expect(res.inShown).toBe(true);
    expect(res.pinned).toBeNull();
  });

  it("synthesizes a pinned row from the `you` summary when no is_you row exists", () => {
    const all = [entry({ id: "a", rank: 1 }), entry({ id: "b", rank: 2 })];
    const you: ReferralLeaderboardYou = {
      rank: 42,
      referred_count: 7,
      qualified_count: 4,
      reward_cents: 1234,
    };
    const res = findYou(all, all, you);
    expect(res.entry).toBeNull();
    expect(res.pinned?.rank).toBe(42);
    expect(res.pinned?.reward_cents).toBe(1234);
    expect(res.pinned?.is_you).toBe(true);
  });

  it("returns no pin when the caller cannot be located", () => {
    const all = [entry({ id: "a", rank: 1 })];
    const res = findYou(all, all);
    expect(res.entry).toBeNull();
    expect(res.pinned).toBeNull();
  });
});

describe("formatRank / formatCount", () => {
  it("formats ranks", () => {
    expect(formatRank(4)).toBe("#4");
    expect(formatRank(0)).toBe("—");
    expect(formatRank(Number.NaN)).toBe("—");
  });

  it("formats counts with separators", () => {
    expect(formatCount(12345)).toBe("12,345");
    expect(formatCount(Number.NaN)).toBe("0");
  });
});
