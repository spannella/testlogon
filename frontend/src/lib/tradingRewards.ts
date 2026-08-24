// Pure helpers for the TRADING-REWARDS card on the Rewards surface.
// No React / no network — unit-testable in isolation.
//
// Trading earns reward POINTS by executed volume. Points accrue SERVER-SIDE;
// the frontend shows the earn RATE + an ESTIMATE of points from the user's own
// 30-day trading volume, plus an optional AUTHORITATIVE read when the backend
// ships `GET /me/rewards/trading`.
//
// CONVENTIONS: money is INTEGER CENTS; points are WHOLE integers.
// Canonical rate (shared with Android): 1 reward point per $1 of volume.

import type { TradingRewards } from "@/api/endpoints/rewards";

/** Canonical earn rate: reward points granted per whole US dollar of volume. */
export const POINTS_PER_DOLLAR = 1;

/**
 * Whole reward points earned for a given trading volume (integer cents).
 * Floors to whole points; guards against negative / non-finite input and a
 * non-positive rate.
 */
export function tradingPointsForVolumeCents(
  volumeCents: number,
  pointsPerDollar: number = POINTS_PER_DOLLAR,
): number {
  const cents = Number.isFinite(volumeCents) ? volumeCents : 0;
  const rate = Number.isFinite(pointsPerDollar) ? pointsPerDollar : 0;
  if (cents <= 0 || rate <= 0) return 0;
  const dollars = cents / 100;
  return Math.floor(dollars * rate);
}

/**
 * Inverse of `tradingPointsForVolumeCents`: the minimum trading volume (integer
 * cents) required to earn `points` at the given rate. Guards non-positive input.
 */
export function volumeForPoints(
  points: number,
  pointsPerDollar: number = POINTS_PER_DOLLAR,
): number {
  const p = Number.isFinite(points) ? points : 0;
  const rate = Number.isFinite(pointsPerDollar) ? pointsPerDollar : 0;
  if (p <= 0 || rate <= 0) return 0;
  const dollars = p / rate;
  return Math.round(dollars * 100);
}

/** Where the trading-rewards numbers came from. */
export type TradingRewardsSource = "authoritative" | "estimated";

/** Resolved trading-rewards summary for the card. */
export interface TradingRewardsSummary {
  /** Earn rate, points per whole US dollar of volume. */
  pointsPerDollar: number;
  /** 30-day trading volume backing the estimate/read, USD cents. */
  volume30dCents: number;
  /** Points earned from the last-30-day volume. */
  pointsEarned30d: number;
  /** Lifetime trading points (authoritative only; 0 when estimating). */
  lifetimeTradingPoints: number;
  /** Whether the numbers are authoritative or a client estimate. */
  source: TradingRewardsSource;
}

/**
 * Resolve the trading-rewards summary. Prefers the AUTHORITATIVE payload when
 * present; otherwise falls back to a client ESTIMATE computed from the caller's
 * 30-day volume. Never throws.
 */
export function tradingRewardsSummary(
  volumeCents: number,
  authoritative?: TradingRewards | null,
): TradingRewardsSummary {
  if (
    authoritative &&
    Number.isFinite(authoritative.points_per_dollar) &&
    authoritative.points_per_dollar > 0
  ) {
    const vol = Number.isFinite(authoritative.volume_30d_cents)
      ? authoritative.volume_30d_cents
      : 0;
    const earned = Number.isFinite(authoritative.points_earned_30d)
      ? Math.max(0, Math.floor(authoritative.points_earned_30d))
      : tradingPointsForVolumeCents(vol, authoritative.points_per_dollar);
    const lifetime = Number.isFinite(authoritative.lifetime_trading_points)
      ? Math.max(0, Math.floor(authoritative.lifetime_trading_points))
      : 0;
    return {
      pointsPerDollar: authoritative.points_per_dollar,
      volume30dCents: Math.max(0, vol),
      pointsEarned30d: earned,
      lifetimeTradingPoints: lifetime,
      source: "authoritative",
    };
  }

  const vol = Number.isFinite(volumeCents) ? Math.max(0, volumeCents) : 0;
  return {
    pointsPerDollar: POINTS_PER_DOLLAR,
    volume30dCents: vol,
    pointsEarned30d: tradingPointsForVolumeCents(vol, POINTS_PER_DOLLAR),
    lifetimeTradingPoints: 0,
    source: "estimated",
  };
}
