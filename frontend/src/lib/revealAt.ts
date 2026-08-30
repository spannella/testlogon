// FE-120 (EPIC C, ← BE-120/BE-121): scheduled "reveal at" helpers.
//
// A message may carry an optional `reveal_at` (epoch seconds). Before that
// instant, RECIPIENTS see a locked/blurred placeholder with a live countdown;
// the SENDER always sees the real content. At the reveal time (a local tick
// reaching it, or a `message:revealed` stream event) the content auto-reveals.
//
// Pure + integer-based. `nowSec` is always passed in (never reads the clock)
// so callers/tests stay deterministic.

/**
 * Minimum lead time (seconds) between "now" and a chosen reveal time for the
 * schedule to be meaningful. Composer should reject earlier picks.
 */
export const MIN_REVEAL_LEAD_SEC = 60;

/** Normalize an optional reveal_at to a finite integer epoch-seconds, or null. */
function normalizeRevealAt(revealAt: number | null | undefined): number | null {
  if (revealAt == null) return null;
  if (!Number.isFinite(revealAt)) return null;
  return Math.floor(revealAt);
}

/**
 * True when the message content is hidden from the current viewer.
 * - The sender is NEVER locked (always sees their own content).
 * - No reveal_at → never locked.
 * - Otherwise locked until nowSec reaches reveal_at.
 */
export function isRevealLocked(
  revealAt: number | null | undefined,
  isSender: boolean,
  nowSec: number,
): boolean {
  if (isSender) return false;
  const target = normalizeRevealAt(revealAt);
  if (target == null) return false;
  return nowSec < target;
}

/** Seconds remaining until reveal, clamped at >= 0. 0 if no reveal_at. */
export function secondsUntilReveal(
  revealAt: number | null | undefined,
  nowSec: number,
): number {
  const target = normalizeRevealAt(revealAt);
  if (target == null) return 0;
  return Math.max(0, target - Math.floor(nowSec));
}

/** True once the reveal time has arrived (content may now be shown). */
export function isRevealable(
  revealAt: number | null | undefined,
  nowSec: number,
): boolean {
  const target = normalizeRevealAt(revealAt);
  if (target == null) return true;
  return Math.floor(nowSec) >= target;
}

function pad2(n: number): string {
  return n.toString().padStart(2, "0");
}

/**
 * A human label for the locked card.
 *  - Far away (>= 1 day): "Reveals at <date/time>"
 *  - Within a day: relative "Reveals in 2h 05m" / "Reveals in 5m 03s"
 *  - Already revealable: "Revealing…"
 */
export function revealCountdownLabel(
  revealAt: number | null | undefined,
  nowSec: number,
): string {
  const target = normalizeRevealAt(revealAt);
  if (target == null) return "";
  const remaining = secondsUntilReveal(target, nowSec);
  if (remaining <= 0) return "Revealing…";

  // A day or more out: show an absolute clock time instead of a long countdown.
  if (remaining >= 86400) {
    const d = new Date(target * 1000);
    const at = d.toLocaleTimeString(undefined, {
      hour: "numeric",
      minute: "2-digit",
    });
    return `Reveals at ${at}`;
  }

  const h = Math.floor(remaining / 3600);
  const m = Math.floor((remaining % 3600) / 60);
  const s = remaining % 60;
  if (h > 0) return `Reveals in ${h}h ${pad2(m)}m`;
  if (m > 0) return `Reveals in ${m}m ${pad2(s)}s`;
  return `Reveals in ${s}s`;
}
