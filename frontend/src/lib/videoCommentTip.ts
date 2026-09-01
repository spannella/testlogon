// TIP-303 (web): pure helpers for tipping a VIDEO COMMENT.
//
// The tip amount is expressed in whole cents (matching the backend
// VideoCommentTipIn contract: { amount_cents, currency, payment_method_id? }).
// These helpers keep the amount-validation logic out of the React component so
// it can be unit tested without a DOM.

/** Hard ceiling for a single comment tip (in cents) = $10,000. */
export const MAX_TIP_CENTS = 1_000_000;

export interface TipCentsResult {
  ok: boolean;
  /** Normalized integer cents, only present when ok. */
  cents?: number;
  /** Human-readable reason, only present when !ok. */
  error?: string;
}

/**
 * Validate a tip amount given in cents. Rejects non-finite, non-integer,
 * non-positive, and over-ceiling values. Returns the normalized cents on
 * success so callers can trust the value they send to the API.
 */
export function validateTipCents(cents: unknown): TipCentsResult {
  if (typeof cents !== "number" || !Number.isFinite(cents)) {
    return { ok: false, error: "Enter a tip amount." };
  }
  if (!Number.isInteger(cents)) {
    return { ok: false, error: "Tip must be a whole number of cents." };
  }
  if (cents <= 0) {
    return { ok: false, error: "Tip must be greater than $0." };
  }
  if (cents > MAX_TIP_CENTS) {
    return { ok: false, error: "Tip exceeds the maximum allowed." };
  }
  return { ok: true, cents };
}

/**
 * Parse a user-entered dollar string (e.g. "2.50") into integer cents.
 * Returns null when the input is empty or not a positive money value.
 * Rounds to the nearest cent to avoid float dust (2.505 -> 251).
 */
export function parseTipDollarsToCents(input: string): number | null {
  const trimmed = input.trim();
  if (!trimmed) return null;
  const dollars = Number(trimmed);
  if (!Number.isFinite(dollars) || dollars <= 0) return null;
  return Math.round(dollars * 100);
}
