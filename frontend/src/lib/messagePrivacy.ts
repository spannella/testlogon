// messagePrivacy.ts — pure, side-effect-free helpers for the pay-to-message
// (TIP-401 "require a tip to message me") privacy surface. All money is handled
// in INTEGER CENTS end to end, matching the backend contract
// (MessagePrivacyOut.min_tip_cents: int, 0..100_000).
//
// Nothing in here does I/O — it is unit-tested in messagePrivacy.test.ts and
// consumed by the API layer (endpoints/messaging.ts) and the settings dialog.

/** The shape the backend returns for GET/PUT /messaging/privacy/message. */
export interface MessagePrivacy {
  require_tip_to_message: boolean;
  /** Minimum tip required to reach the inbox, in integer cents. */
  min_tip_cents: number;
  /** User ids that bypass the tip gate entirely. */
  tip_free_allowlist: string[];
}

/** Backend cap on min_tip_cents (Field(ge=0, le=100_000)). */
export const MIN_TIP_CENTS_MIN = 0;
export const MAX_MIN_TIP_CENTS = 100_000;

/** The honest-empty default used when the endpoint 404s / user never set it. */
export function defaultMessagePrivacy(): MessagePrivacy {
  return { require_tip_to_message: false, min_tip_cents: 0, tip_free_allowlist: [] };
}

/**
 * Coerce an arbitrary server/JSON blob into a well-formed MessagePrivacy,
 * filling defaults for anything missing or malformed. Never throws.
 */
export function normalizeMessagePrivacy(raw: unknown): MessagePrivacy {
  const out = defaultMessagePrivacy();
  if (!raw || typeof raw !== "object") return out;
  const r = raw as Record<string, unknown>;
  out.require_tip_to_message = r.require_tip_to_message === true;
  const cents = Number(r.min_tip_cents);
  out.min_tip_cents = Number.isFinite(cents) && cents > 0 ? Math.floor(cents) : 0;
  if (Array.isArray(r.tip_free_allowlist)) {
    const seen = new Set<string>();
    for (const x of r.tip_free_allowlist) {
      const s = String(x ?? "").trim();
      if (s && !seen.has(s)) {
        seen.add(s);
        out.tip_free_allowlist.push(s);
      }
    }
  }
  return out;
}

export interface CentsValidation {
  ok: boolean;
  /** The clamped/parsed integer cents value (valid regardless of ok). */
  cents: number;
  /** Human-readable reason when ok === false. */
  error?: string;
}

/**
 * Validate a user-entered minimum-tip amount expressed in CENTS. Accepts a
 * number or a numeric string. Must be a non-negative integer within the
 * backend range [0, 100_000]. Returns a clamped cents value alongside the ok
 * flag so callers can both gate the save and show a sane field value.
 */
export function validateMinAmountCents(input: number | string): CentsValidation {
  const n = typeof input === "string" ? Number(input.trim()) : input;
  if (input === "" || input == null || !Number.isFinite(n)) {
    return { ok: false, cents: 0, error: "Enter an amount in cents" };
  }
  if (n < 0) {
    return { ok: false, cents: 0, error: "Amount cannot be negative" };
  }
  if (!Number.isInteger(n)) {
    return { ok: false, cents: Math.floor(n), error: "Amount must be a whole number of cents" };
  }
  if (n > MAX_MIN_TIP_CENTS) {
    return {
      ok: false,
      cents: MAX_MIN_TIP_CENTS,
      error: `Amount cannot exceed ${MAX_MIN_TIP_CENTS} cents`,
    };
  }
  return { ok: true, cents: n };
}

/** Format integer cents as a "$X.XX" USD string. Clamps negatives to $0.00. */
export function formatCents(cents: number): string {
  const c = Number.isFinite(cents) ? Math.max(0, Math.round(cents)) : 0;
  return `$${(c / 100).toFixed(2)}`;
}

/**
 * True if `userId` is currently on the tip-free allowlist (may message without
 * paying). Empty / falsy ids are never allowlisted.
 */
export function isAllowlisted(privacy: MessagePrivacy | null | undefined, userId: string): boolean {
  if (!privacy || !userId) return false;
  const target = String(userId).trim();
  if (!target) return false;
  return privacy.tip_free_allowlist.includes(target);
}

/**
 * Whether `senderId` would be gated (must attach a tip) when messaging a user
 * with these settings — the FRONTEND mirror of the backend bypass logic that is
 * knowable client-side: gate is off, or the sender is allowlisted, means no
 * gate. (Mutual-follow / established-conversation bypasses are server-only.)
 */
export function isGatedForSender(
  privacy: MessagePrivacy | null | undefined,
  senderId: string,
): boolean {
  if (!privacy || !privacy.require_tip_to_message) return false;
  if (isAllowlisted(privacy, senderId)) return false;
  return true;
}

/** One-line human summary of the current gate for the settings UI. */
export function describePrivacy(privacy: MessagePrivacy): string {
  if (!privacy.require_tip_to_message) {
    return "Anyone can message you for free.";
  }
  const amt = formatCents(privacy.min_tip_cents);
  const n = privacy.tip_free_allowlist.length;
  const allow = n === 0 ? "" : ` (${n} ${n === 1 ? "person is" : "people are"} exempt)`;
  return `New senders must tip at least ${amt} to reach your inbox${allow}.`;
}
