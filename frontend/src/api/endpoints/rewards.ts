import { api } from "@/api/client";

/**
 * REFERRALS + REWARDS surface (`/me/referral*` + `/me/rewards*`).
 *
 * A user shares a referral code/link, tracks the people they referred, and
 * earns a per-referral reward once a referral qualifies. Separately, a rewards
 * program accrues POINTS (and a small cash balance) for referrals/activity;
 * points are redeemed from a catalog for either CASH (credited to the USD cash
 * wallet, see `/custody/cash`) or non-cash PERKS.
 *
 * CONVENTIONS: every monetary amount is INTEGER CENTS; points are whole
 * integers. Reward CREDITING is server-side — the frontend owns the surfaces,
 * share + redeem UX only. NONE of these endpoints exist on the backend yet:
 * every GET degrades on 404/absent to an honest empty / "coming soon" state
 * (callers use `retry:false`), and the redeem mutation surfaces a clear error
 * toast on 404 (never silently "succeeds").
 */

export type ReferralStatus = "pending" | "qualified" | "rewarded";
export type RewardKind = "cash" | "perk";
export type RewardHistoryStatus = "pending" | "posted" | "reversed" | string;

/** Top-line referral program summary for the signed-in user. */
export interface ReferralSummary {
  code: string;
  link: string;
  referred_count: number;
  qualified_count: number;
  pending_reward_cents: number;
  earned_reward_cents: number;
  reward_per_referral_cents: number;
}

/** One referred user (name masked for privacy). */
export interface ReferralEntry {
  id: string;
  masked_name: string;
  joined_ts: number;
  status: ReferralStatus;
  reward_cents: number;
}

export interface ReferralList {
  referrals: ReferralEntry[];
}

/** A single way to earn points. */
export interface WayToEarn {
  id: string;
  title: string;
  points: number;
  detail: string;
}

/** Rewards balances + earn menu. */
export interface RewardsSummary {
  points: number;
  cash_cents: number;
  lifetime_points: number;
  ways_to_earn: WayToEarn[];
}

/** One rewards-ledger entry. */
export interface RewardHistoryEntry {
  ts: number;
  type: string;
  description: string;
  points: number;
  cash_cents: number;
  status: RewardHistoryStatus;
}

export interface RewardsHistory {
  entries: RewardHistoryEntry[];
}

/** A redeemable reward in the catalog. */
export interface CatalogReward {
  id: string;
  name: string;
  description: string;
  cost_points: number;
  value_cents: number;
  kind: RewardKind;
}

export interface RewardsCatalog {
  rewards: CatalogReward[];
}

export interface RedeemResult {
  ok: boolean;
  points_remaining: number;
}

// ── Referral leaderboard (degrade on 404 — NEW) ────────────────────

export type LeaderboardPeriod = "all" | "month";

/** One ranked referrer row on the leaderboard (name masked for privacy). */
export interface ReferralLeaderboardEntry {
  rank: number;
  id: string;
  masked_name: string;
  is_you: boolean;
  referred_count: number;
  qualified_count: number;
  reward_cents: number;
}

/** The signed-in user's own standing (present even when outside the top slice). */
export interface ReferralLeaderboardYou {
  rank: number;
  referred_count: number;
  qualified_count: number;
  reward_cents: number;
}

export interface ReferralLeaderboard {
  period: LeaderboardPeriod;
  updated_ts: number;
  entries: ReferralLeaderboardEntry[];
  you?: ReferralLeaderboardYou;
}


// ── Reads (degrade on 404 — callers use retry:false) ─────────────────

export const getReferralSummary = () =>
  api.get<ReferralSummary>("/me/referral");

export const getReferralList = () =>
  api.get<ReferralList>("/me/referral/list");

export const getRewards = () =>
  api.get<RewardsSummary>("/me/rewards");

export const getRewardsHistory = () =>
  api.get<RewardsHistory>("/me/rewards/history");

export const getRewardsCatalog = () =>
  api.get<RewardsCatalog>("/me/rewards/catalog");

export const getReferralLeaderboard = (period: LeaderboardPeriod = "all") =>
  api.get<ReferralLeaderboard>(`/me/referral/leaderboard?period=${period}`);

// ── Mutation (clear error on 404 — never silent) ─────────────────────

export const redeemReward = (rewardId: string) =>
  api.post<RedeemResult>("/me/rewards/redeem", { reward_id: rewardId });
