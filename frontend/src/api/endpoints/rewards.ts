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




// ── Rewards points expiry (optional authoritative — degrade on 404) ──

/**
 * One earn "lot" of points with its remaining balance and expiry date. Points
 * expire `policy_months` after they were earned; lots are consumed FIFO
 * (oldest-earned first) by redemptions/expirations.
 */
export interface RewardsExpiryLot {
  earned_ts: number;
  points_remaining: number;
  expires_ts: number;
}

/**
 * Authoritative points-EXPIRY read. Degrades on 404 -> the frontend computes
 * the same view client-side (FIFO) from the rewards history (see
 * `lib/pointsExpiry`). All timestamps are UNIX seconds; points are integers.
 */
export interface RewardsExpiry {
  policy_months: number;
  expiring_soon_points: number;
  next_expiry_ts: number | null;
  next_expiry_points: number;
  lots: RewardsExpiryLot[];
}


// ── Trading rewards (points earned by trading volume — NEW) ──────

/**
 * Authoritative TRADING-REWARDS read: points accrued from executed trading
 * volume. Points accrue server-side; the frontend shows the earn rate + an
 * estimate from the caller’s own 30-day volume, and swaps to these numbers
 * when the endpoint ships. Degrades on 404 -> client estimate (see
 * `lib/tradingRewards`). Rate is points per whole US dollar of volume.
 */
export interface TradingRewards {
  points_per_dollar: number;
  volume_30d_cents: number;
  points_earned_30d: number;
  lifetime_trading_points: number;
}


// ── Rewards STATUS / loyalty TIER LEVELS (optional authoritative — 404-degrade) ──

/**
 * Authoritative REWARDS-STATUS read: the user's LOYALTY-TIER standing driven by
 * LIFETIME reward points (DISTINCT from the maker/taker fee tiers, see
 * `lib/feeTiers`). Degrades on 404 -> the frontend computes the same view
 * client-side from `getRewards().lifetime_points` against the canonical
 * `STATUS_TIERS` table (see `lib/statusTiers`). Points are whole integers;
 * `points_multiplier_bps` is in BASIS POINTS where 10000 = 1.0x.
 */
export interface RewardsStatus {
  tier_id: string;
  name: string;
  lifetime_points: number;
  points_multiplier_bps: number;
  next_tier?: { name: string; threshold_points: number };
  perks: string[];
}

// ── Reads (degrade on 404 — callers use retry:false) ─────────────────

export const getReferralSummary = () =>
  api.get<ReferralSummary>("/me/referral");

export const getReferralList = () =>
  api.get<ReferralList>("/me/referral/list");

export const getRewards = () =>
  api.get<RewardsSummary>("/me/rewards");

export const getRewardsStatus = () =>
  api.get<RewardsStatus>("/me/rewards/status");

export const getRewardsHistory = () =>
  api.get<RewardsHistory>("/me/rewards/history");

export const getRewardsCatalog = () =>
  api.get<RewardsCatalog>("/me/rewards/catalog");

export const getTradingRewards = () =>
  api.get<TradingRewards>("/me/rewards/trading");

export const getRewardsExpiry = () =>
  api.get<RewardsExpiry>("/me/rewards/expiry");

export const getReferralLeaderboard = (period: LeaderboardPeriod = "all") =>
  api.get<ReferralLeaderboard>(`/me/referral/leaderboard?period=${period}`);

// ── Mutation (clear error on 404 — never silent) ─────────────────────

export const redeemReward = (rewardId: string) =>
  api.post<RedeemResult>("/me/rewards/redeem", { reward_id: rewardId });


/** Result of a DIRECT points-to-cash conversion. */
export interface RedeemCashResult {
  ok: boolean;
  cash_cents: number;
  points_remaining: number;
}

/**
 * DIRECT "convert points to USD cash wallet" redemption. The server debits the
 * points and credits the USD cash wallet (`/custody/cash`). Degrades on 404 —
 * the caller surfaces a clear error toast (never a silent success).
 */
export const redeemPointsForCash = (points: number) =>
  api.post<RedeemCashResult>("/me/rewards/redeem-cash", { points });
