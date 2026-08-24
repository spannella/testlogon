// Pure helpers for the REFERRAL LEADERBOARD surface.
// No React / no network — unit-testable in isolation.
// Money is INTEGER CENTS; ranks are whole positive integers.

import type {
  ReferralLeaderboardEntry,
  ReferralLeaderboardYou,
} from "@/api/endpoints/rewards";

export type RankMedal = "gold" | "silver" | "bronze" | null;

/** The medal for a podium rank (1→gold, 2→silver, 3→bronze), else null. */
export function rankMedal(rank: number): RankMedal {
  if (rank === 1) return "gold";
  if (rank === 2) return "silver";
  if (rank === 3) return "bronze";
  return null;
}

/**
 * Sort leaderboard entries by rank ascending; ties broken by reward_cents
 * descending, then referred_count descending. Returns a new array (pure).
 */
export function sortEntries(
  entries: ReferralLeaderboardEntry[],
): ReferralLeaderboardEntry[] {
  if (!Array.isArray(entries)) return [];
  return [...entries].sort((a, b) => {
    const ra = Number.isFinite(a.rank) ? a.rank : Number.MAX_SAFE_INTEGER;
    const rb = Number.isFinite(b.rank) ? b.rank : Number.MAX_SAFE_INTEGER;
    if (ra !== rb) return ra - rb;
    const rewA = Number.isFinite(a.reward_cents) ? a.reward_cents : 0;
    const rewB = Number.isFinite(b.reward_cents) ? b.reward_cents : 0;
    if (rewA !== rewB) return rewB - rewA;
    const refA = Number.isFinite(a.referred_count) ? a.referred_count : 0;
    const refB = Number.isFinite(b.referred_count) ? b.referred_count : 0;
    return refB - refA;
  });
}

/** The first `n` sorted entries. Non-positive `n` yields an empty list. */
export function topN(
  entries: ReferralLeaderboardEntry[],
  n: number,
): ReferralLeaderboardEntry[] {
  if (!Array.isArray(entries)) return [];
  const count = Number.isFinite(n) ? Math.max(0, Math.trunc(n)) : 0;
  return sortEntries(entries).slice(0, count);
}

/** Result of locating the caller relative to a shown top slice. */
export interface FoundYou {
  /** The caller's row from `entries` (is_you), if any. */
  entry: ReferralLeaderboardEntry | null;
  /** True when the caller's row is present within `shown`. */
  inShown: boolean;
  /**
   * A synthetic "your rank" row to pin below the list when the caller is
   * outside the shown slice. Null when the caller is in the slice or unknown.
   */
  pinned: ReferralLeaderboardEntry | null;
}

/**
 * Locate the caller within the leaderboard.
 *
 * Prefers the `is_you` row in `entries`; falls back to the `you` summary
 * (synthesizing a display row) when no `is_you` row exists. `shown` is the
 * already-sliced top-N list actually rendered. When the caller is outside
 * `shown`, `pinned` carries a row to render below; otherwise `pinned` is null.
 */
export function findYou(
  entries: ReferralLeaderboardEntry[],
  shown: ReferralLeaderboardEntry[],
  you?: ReferralLeaderboardYou | null,
): FoundYou {
  const all = Array.isArray(entries) ? entries : [];
  const slice = Array.isArray(shown) ? shown : [];

  const youEntry = all.find((e) => e.is_you) ?? null;
  const inShownById = youEntry
    ? slice.some((e) => e.id === youEntry.id)
    : false;

  // Build the row that represents the caller for pinning purposes.
  let row: ReferralLeaderboardEntry | null = youEntry;
  if (!row && you && Number.isFinite(you.rank)) {
    row = {
      rank: you.rank,
      id: "__you__",
      masked_name: "You",
      is_you: true,
      referred_count: you.referred_count ?? 0,
      qualified_count: you.qualified_count ?? 0,
      reward_cents: you.reward_cents ?? 0,
    };
  }

  const inShown = inShownById;
  const pinned = row && !inShown ? row : null;

  return { entry: youEntry, inShown, pinned };
}

/** Format a rank as an ordinal-style badge, e.g. 4 -> "#4". */
export function formatRank(rank: number): string {
  const safe = Number.isFinite(rank) ? Math.trunc(rank) : 0;
  return safe > 0 ? `#${safe}` : "—";
}

/** Format whole counts with thousands separators, e.g. 12345 -> "12,345". */
export function formatCount(count: number): string {
  const safe = Number.isFinite(count) ? Math.trunc(count) : 0;
  return new Intl.NumberFormat("en-US").format(safe);
}
