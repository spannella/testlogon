// Pure helpers for the REWARDS STATUS / loyalty TIER LEVELS surface.
// No React / no network — unit-testable in isolation.
//
// A loyalty membership ladder driven by LIFETIME reward points. This is
// DISTINCT from the maker/taker fee tiers (see `lib/feeTiers`): those key off
// trading volume and set trading fees; THESE key off lifetime reward points
// and set a points-earning multiplier + membership perks.
//
// CONVENTIONS: points are WHOLE integers; `multiplierBps` is in BASIS POINTS
// where 10000 = 1.0x. The table is ascending by `thresholdPoints`.

import type { RewardsStatus } from "@/api/endpoints/rewards";

/** One rung of the loyalty status ladder. */
export interface StatusTier {
  /** Stable machine id. */
  id: string;
  /** Display name. */
  name: string;
  /** LIFETIME points required to reach this tier. */
  thresholdPoints: number;
  /** Points-earning multiplier in basis points (10000 = 1.0x). */
  multiplierBps: number;
  /** Membership perks unlocked at this tier. */
  perks: string[];
}

/**
 * Canonical loyalty status ladder — MUST stay in sync with the Android client
 * and the (optional) authoritative `GET /me/rewards/status`. Ascending by
 * threshold; the first entry (0 pts) is the floor every account is at.
 */
export const STATUS_TIERS: readonly StatusTier[] = [
  {
    id: "member",
    name: "Member",
    thresholdPoints: 0,
    multiplierBps: 10000,
    perks: ["Base points earning"],
  },
  {
    id: "bronze",
    name: "Bronze",
    thresholdPoints: 1000,
    multiplierBps: 10500,
    perks: ["5% bonus points", "Bronze badge"],
  },
  {
    id: "silver",
    name: "Silver",
    thresholdPoints: 5000,
    multiplierBps: 11000,
    perks: ["10% bonus points", "Priority support"],
  },
  {
    id: "gold",
    name: "Gold",
    thresholdPoints: 25000,
    multiplierBps: 12500,
    perks: ["25% bonus points", "+5% referral bonus", "Gold badge"],
  },
  {
    id: "platinum",
    name: "Platinum",
    thresholdPoints: 100000,
    multiplierBps: 15000,
    perks: ["50% bonus points", "Reduced fees", "Priority withdrawals"],
  },
  {
    id: "diamond",
    name: "Diamond",
    thresholdPoints: 500000,
    multiplierBps: 20000,
    perks: ["2x points", "All perks", "Concierge support"],
  },
] as const;

/** Coerce any input to a safe, whole, non-negative lifetime-points count. */
function safePoints(lifetimePoints: number): number {
  if (!Number.isFinite(lifetimePoints)) return 0;
  return Math.max(0, Math.trunc(lifetimePoints));
}

/**
 * The current status tier for a lifetime-points balance: the highest tier whose
 * threshold is <= the balance. Always returns a tier (Member at the floor);
 * guards 0 / negative / non-finite input.
 */
export function statusTierForPoints(lifetimePoints: number): StatusTier {
  const pts = safePoints(lifetimePoints);
  let current: StatusTier = STATUS_TIERS[0] as StatusTier;
  for (const t of STATUS_TIERS) {
    if (pts >= t.thresholdPoints) current = t;
    else break;
  }
  return current;
}

/**
 * The next tier above the given one, or `null` when already at the top tier.
 * Accepts a tier or a tier id.
 */
export function nextStatusTier(tier: StatusTier | string): StatusTier | null {
  const id = typeof tier === "string" ? tier : tier.id;
  const idx = STATUS_TIERS.findIndex((t) => t.id === id);
  if (idx < 0 || idx >= STATUS_TIERS.length - 1) return null;
  return STATUS_TIERS[idx + 1] ?? null;
}

/**
 * Whole lifetime points still needed to reach the next tier, or 0 when already
 * at the top tier (or somehow past the last threshold).
 */
export function pointsToNextTier(lifetimePoints: number): number {
  const pts = safePoints(lifetimePoints);
  const current = statusTierForPoints(pts);
  const next = nextStatusTier(current);
  if (!next) return 0;
  return Math.max(0, next.thresholdPoints - pts);
}

/**
 * Progress from the CURRENT tier's threshold toward the NEXT tier's threshold,
 * as a fraction in [0, 1]. Returns 1.0 at (or above) the top tier.
 */
export function progressToNextFraction(lifetimePoints: number): number {
  const pts = safePoints(lifetimePoints);
  const current = statusTierForPoints(pts);
  const next = nextStatusTier(current);
  if (!next) return 1;
  const span = next.thresholdPoints - current.thresholdPoints;
  if (span <= 0) return 1;
  const gained = pts - current.thresholdPoints;
  const frac = gained / span;
  if (frac <= 0) return 0;
  if (frac >= 1) return 1;
  return frac;
}

/**
 * Human label for a basis-points multiplier, e.g. 12500 -> "1.25x",
 * 10000 -> "1x", 20000 -> "2x". Trims trailing zeros; guards non-finite.
 */
export function multiplierLabel(bps: number): string {
  const safe = Number.isFinite(bps) && bps > 0 ? bps : 10000;
  const x = safe / 10000;
  // Up to 2 decimals, but drop trailing zeros ("1.50x" -> "1.5x", "1.00x" -> "1x").
  const s = x.toFixed(2).replace(/\.?0+$/, "");
  return `${s}x`;
}

/** Where the resolved status view came from. */
export type StatusSource = "authoritative" | "estimated";

/** A resolved status view for the page, from either source. */
export interface ResolvedStatus {
  tierId: string;
  name: string;
  lifetimePoints: number;
  multiplierBps: number;
  perks: string[];
  nextName: string | null;
  nextThreshold: number | null;
  pointsToNext: number;
  progressFraction: number;
  source: StatusSource;
}

/**
 * Resolve the status view. Prefers the AUTHORITATIVE `/me/rewards/status`
 * payload when present & sane; otherwise computes it CLIENT-SIDE from the
 * lifetime-points balance against `STATUS_TIERS`. Never throws.
 */
export function resolveStatus(
  lifetimePoints: number,
  authoritative?: RewardsStatus | null,
): ResolvedStatus {
  if (
    authoritative &&
    typeof authoritative.name === "string" &&
    Number.isFinite(authoritative.points_multiplier_bps)
  ) {
    const lp = safePoints(authoritative.lifetime_points);
    const next = authoritative.next_tier ?? null;
    const nextThreshold =
      next && Number.isFinite(next.threshold_points)
        ? Math.max(0, Math.trunc(next.threshold_points))
        : null;
    return {
      tierId: authoritative.tier_id || statusTierForPoints(lp).id,
      name: authoritative.name,
      lifetimePoints: lp,
      multiplierBps: authoritative.points_multiplier_bps,
      perks: Array.isArray(authoritative.perks) ? authoritative.perks : [],
      nextName: next ? next.name : null,
      nextThreshold,
      pointsToNext: nextThreshold !== null ? Math.max(0, nextThreshold - lp) : 0,
      progressFraction: progressToNextFraction(lp),
      source: "authoritative",
    };
  }

  const lp = safePoints(lifetimePoints);
  const current = statusTierForPoints(lp);
  const next = nextStatusTier(current);
  return {
    tierId: current.id,
    name: current.name,
    lifetimePoints: lp,
    multiplierBps: current.multiplierBps,
    perks: current.perks,
    nextName: next ? next.name : null,
    nextThreshold: next ? next.thresholdPoints : null,
    pointsToNext: pointsToNextTier(lp),
    progressFraction: progressToNextFraction(lp),
    source: "estimated",
  };
}
