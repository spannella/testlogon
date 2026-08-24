// Pure helpers for the DIRECT "convert points to USD cash wallet" redemption.
// No React / no network — unit-testable in isolation.
// Money is INTEGER CENTS; points are whole integers.
//
// Canonical rate (shared with Android): 100 points = $1.00, i.e. 1 point = 1
// cent. Minimum redemption is 500 points ($5.00). All arithmetic is integer.

/** Cents credited per point redeemed. 1 point = 1 cent (100 pts = $1.00). */
export const CENTS_PER_POINT = 1;

/** Minimum points that may be converted to cash in a single redemption. */
export const MIN_REDEEM_POINTS = 500;

/** Coerce to a safe, whole, non-negative integer point count. */
function safePoints(points: number): number {
  return Number.isFinite(points) ? Math.trunc(points) : 0;
}

/** USD cents received for redeeming `points` at `centsPerPoint`. Integer. */
export function cashCentsForPoints(
  points: number,
  centsPerPoint: number = CENTS_PER_POINT,
): number {
  const p = Math.max(0, safePoints(points));
  const rate = Number.isFinite(centsPerPoint) ? Math.trunc(centsPerPoint) : CENTS_PER_POINT;
  return p * Math.max(0, rate);
}

/** Points required to receive `cents` USD (rounded UP to whole points). */
export function pointsForCashCents(
  cents: number,
  centsPerPoint: number = CENTS_PER_POINT,
): number {
  const c = Number.isFinite(cents) ? Math.max(0, Math.trunc(cents)) : 0;
  const rate = Number.isFinite(centsPerPoint) ? Math.trunc(centsPerPoint) : CENTS_PER_POINT;
  if (rate <= 0) return 0;
  return Math.ceil(c / rate);
}

export interface PointsRedemptionCheck {
  ok: boolean;
  reason?: string;
}

/**
 * Validate a proposed points-to-cash redemption against the caller's balance.
 * Requires: a whole positive integer, at least MIN_REDEEM_POINTS, and no more
 * than the available balance.
 */
export function validatePointsRedemption(
  points: number,
  balancePoints: number,
): PointsRedemptionCheck {
  const balance = Math.max(0, safePoints(balancePoints));

  if (!Number.isFinite(points) || points <= 0) {
    return { ok: false, reason: "Enter a number of points to redeem." };
  }
  if (!Number.isInteger(points)) {
    return { ok: false, reason: "Redeem a whole number of points." };
  }
  if (points < MIN_REDEEM_POINTS) {
    return {
      ok: false,
      reason: `Redeem at least ${MIN_REDEEM_POINTS.toLocaleString("en-US")} points.`,
    };
  }
  if (points > balance) {
    return { ok: false, reason: "You do not have enough points." };
  }
  return { ok: true };
}

/** Format whole points with thousands separators, e.g. 12345 -> "12,345 pts". */
export function formatPoints(points: number, withUnit = true): string {
  const n = new Intl.NumberFormat("en-US").format(safePoints(points));
  return withUnit ? `${n} pts` : n;
}

/** Format integer USD cents as a localized currency string. */
export function formatCents(cents: number, currency = "USD"): string {
  const safe = Number.isFinite(cents) ? cents : 0;
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: (currency || "USD").toUpperCase(),
  }).format(safe / 100);
}
