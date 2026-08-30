// Pure helpers for funding an ad-account / campaign budget (FE-160, EPIC G).
//
// The ad-billing deposit surface tops up an advertiser account balance in
// integer USD cents. This module holds the small amount of pure, integer-safe
// math the top-up UI needs (preset amounts, validation, labels, new-balance
// projection) so it is unit-testable in isolation. No React / no network.
//
// Money math reuses the shared cents model in lib/cashMath.ts.

import { dollarsToCents as _dollarsToCents } from "@/lib/cashMath";

/** Re-export the shared parser so callers can import one place. */
export const dollarsToCents = _dollarsToCents;

/** Whole USD cents -> a plain dollars number (2dp). */
export function centsToDollars(cents: number): number {
  if (!isFinite(cents)) return 0;
  return Math.round(cents) / 100;
}

/** Minimum top-up: $1.00 (matches the cash wallet floor). */
export const MIN_TOPUP_CENTS = 100;

/** A sane upper bound on a single top-up ($100,000) to catch fat-finger input. */
export const MAX_TOPUP_CENTS = 10_000_000;

/** Quick top-up presets shown as buttons (USD cents): $25 / $50 / $100 / $250. */
export const PRESET_TOPUPS_CENTS: number[] = [2500, 5000, 10000, 25000];

/**
 * True when `cents` is a fundable top-up: a whole (integer) number of cents,
 * finite, at least the $1 minimum, and no more than the sane maximum.
 */
export function isValidTopUpCents(cents: number): boolean {
  if (!isFinite(cents)) return false;
  if (!Number.isInteger(cents)) return false;
  if (cents < MIN_TOPUP_CENTS) return false;
  if (cents > MAX_TOPUP_CENTS) return false;
  return true;
}

/** e.g. 2500 -> "$25", 12345 -> "$123.45". Whole dollars drop the ".00". */
export function topUpLabel(cents: number): string {
  const safe = isFinite(cents) ? Math.round(cents) : 0;
  const dollars = safe / 100;
  const whole = safe % 100 === 0;
  return `$${dollars.toLocaleString("en-US", {
    minimumFractionDigits: whole ? 0 : 2,
    maximumFractionDigits: 2,
  })}`;
}

/**
 * Project the new account balance after adding a top-up. Both args and the
 * result are integer USD cents; non-finite inputs are treated as 0 so the
 * projection never renders NaN.
 */
export function newBalanceCents(currentCents: number, addedCents: number): number {
  const cur = isFinite(currentCents) ? Math.round(currentCents) : 0;
  const add = isFinite(addedCents) ? Math.round(addedCents) : 0;
  return cur + add;
}
