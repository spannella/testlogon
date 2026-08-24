// Pure helpers for the REFERRALS + REWARDS surface.
// No React / no network — unit-testable in isolation.
// Money is INTEGER CENTS; points are whole integers.

import type {
  CatalogReward,
  ReferralEntry,
  ReferralStatus,
} from "@/api/endpoints/rewards";

/** A catalog reward annotated with whether the user can currently afford it. */
export interface RedeemableReward extends CatalogReward {
  affordable: boolean;
}

/** True when the user has enough points to redeem a reward of `costPoints`. */
export function canRedeem(points: number, costPoints: number): boolean {
  const p = Number.isFinite(points) ? points : 0;
  const c = Number.isFinite(costPoints) ? costPoints : 0;
  if (c <= 0) return false;
  return p >= c;
}

/** Points remaining after redeeming `costPoints` (never below zero). */
export function pointsAfterRedeem(points: number, costPoints: number): number {
  const p = Number.isFinite(points) ? points : 0;
  const c = Number.isFinite(costPoints) ? costPoints : 0;
  return Math.max(0, p - Math.max(0, c));
}

/** Sum of earned (rewarded) referral cents. */
export function referralEarnedCents(referrals: ReferralEntry[]): number {
  if (!Array.isArray(referrals)) return 0;
  return referrals
    .filter((r) => r.status === "rewarded")
    .reduce((sum, r) => sum + (Number.isFinite(r.reward_cents) ? r.reward_cents : 0), 0);
}

/** Sum of pending + qualified (not-yet-rewarded) referral cents. */
export function referralPendingCents(referrals: ReferralEntry[]): number {
  if (!Array.isArray(referrals)) return 0;
  return referrals
    .filter((r) => r.status === "pending" || r.status === "qualified")
    .reduce((sum, r) => sum + (Number.isFinite(r.reward_cents) ? r.reward_cents : 0), 0);
}

/** Count of referrals by status. */
export function referralStatusCounts(
  referrals: ReferralEntry[],
): Record<ReferralStatus, number> {
  const counts: Record<ReferralStatus, number> = {
    pending: 0,
    qualified: 0,
    rewarded: 0,
  };
  if (!Array.isArray(referrals)) return counts;
  for (const r of referrals) {
    if (r.status === "pending" || r.status === "qualified" || r.status === "rewarded") {
      counts[r.status] += 1;
    }
  }
  return counts;
}

/**
 * Remaining redeemable stock for a catalog item.
 *  - null  -> UNLIMITED (no `stock_limit` set / null / not a finite number)
 *  - number -> max(0, stock_limit - redeemed_count) (clamped at zero)
 */
export function remainingStock(item: {
  stock_limit?: number | null;
  redeemed_count?: number;
}): number | null {
  const limit = item?.stock_limit;
  if (limit === null || limit === undefined || !Number.isFinite(limit)) return null;
  const redeemed = Number.isFinite(item?.redeemed_count) ? (item.redeemed_count as number) : 0;
  return Math.max(0, Math.trunc(limit) - Math.max(0, Math.trunc(redeemed)));
}

/** True only when the item is stock-limited AND has zero remaining. */
export function isOutOfStock(item: {
  stock_limit?: number | null;
  redeemed_count?: number;
}): boolean {
  return remainingStock(item) === 0;
}

/** Human stock label: "Unlimited", "N left", or "Out of stock". */
export function stockLabel(item: {
  stock_limit?: number | null;
  redeemed_count?: number;
}): string {
  const remaining = remainingStock(item);
  if (remaining === null) return "Unlimited";
  if (remaining === 0) return "Out of stock";
  const n = new Intl.NumberFormat("en-US").format(remaining);
  return `${n} left`;
}

/** Annotate each catalog reward with an `affordable` flag for the given points. */
export function redeemableCatalog(
  catalog: CatalogReward[],
  points: number,
): RedeemableReward[] {
  if (!Array.isArray(catalog)) return [];
  return catalog.map((r) => ({
    ...r,
    affordable: canRedeem(points, r.cost_points) && !isOutOfStock(r),
  }));
}

/** Format whole points with thousands separators, e.g. 12345 -> "12,345 pts". */
export function formatPoints(points: number, withUnit = true): string {
  const safe = Number.isFinite(points) ? Math.trunc(points) : 0;
  const n = new Intl.NumberFormat("en-US").format(safe);
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

/** Human, share-ready invite text combining the code and link. */
export function referralShareText(code: string, link: string): string {
  const c = (code ?? "").toString().trim();
  const l = (link ?? "").toString().trim();
  if (c && l) {
    return `Join me here and use my referral code ${c}: ${l}`;
  }
  if (l) return `Join me here: ${l}`;
  if (c) return `Join me here and use my referral code ${c}.`;
  return "Join me here!";
}
