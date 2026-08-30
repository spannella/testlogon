// FE-140: per-conversation mute — pure helpers.
// All functions are pure and integer-based; callers pass `nowSec` (epoch
// seconds) so nothing here reads the clock directly (keeps them testable).

/** Sentinel used for "until I turn it off" — a far-future epoch second value. */
export const MUTE_FOREVER = 4102444800; // 2100-01-01T00:00:00Z

export interface MuteOption {
  id: string;
  label: string;
  /** Duration to add to `nowSec`, in seconds. `null` = mute forever. */
  durationSec: number | null;
}

export const MUTE_OPTIONS: readonly MuteOption[] = [
  { id: "1h", label: "For 1 hour", durationSec: 60 * 60 },
  { id: "8h", label: "For 8 hours", durationSec: 8 * 60 * 60 },
  { id: "1w", label: "For 1 week", durationSec: 7 * 24 * 60 * 60 },
  { id: "off", label: "Until I turn it back on", durationSec: null },
] as const;

/** Human label for a mute option (used by the menu). */
export function formatMuteOption(option: MuteOption): string {
  return option.label;
}

/**
 * Resolve the `muted_until` epoch-second value for a chosen option.
 * "Until off" resolves to the far-future sentinel. Unknown id -> 0 (no-op).
 */
export function computeMutedUntil(optionId: string, nowSec: number): number {
  const opt = MUTE_OPTIONS.find((o) => o.id === optionId);
  if (!opt) return 0;
  if (opt.durationSec === null) return MUTE_FOREVER;
  return Math.floor(nowSec) + opt.durationSec;
}

/** True when the conversation is muted at `nowSec`. 0/undefined = not muted. */
export function isMuted(mutedUntil: number | undefined | null, nowSec: number): boolean {
  if (!mutedUntil || mutedUntil <= 0) return false;
  return mutedUntil > Math.floor(nowSec);
}

/** True when this represents an indefinite ("until off") mute. */
export function isMutedForever(mutedUntil: number | undefined | null): boolean {
  return !!mutedUntil && mutedUntil >= MUTE_FOREVER;
}

function two(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

function clockLabel(d: Date): string {
  let h = d.getHours();
  const m = d.getMinutes();
  const ampm = h >= 12 ? "PM" : "AM";
  h = h % 12;
  if (h === 0) h = 12;
  return `${h}:${two(m)} ${ampm}`;
}

const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/**
 * Label describing mute state for display next to a conversation.
 * - not muted -> ""
 * - forever    -> "Muted"
 * - same day   -> "Muted until 3:00 PM"
 * - later day  -> "Muted until Tue"
 */
export function mutedLabel(mutedUntil: number | undefined | null, nowSec: number): string {
  if (!isMuted(mutedUntil, nowSec)) return "";
  if (isMutedForever(mutedUntil)) return "Muted";

  const until = new Date((mutedUntil as number) * 1000);
  const now = new Date(Math.floor(nowSec) * 1000);
  const sameDay =
    until.getFullYear() === now.getFullYear() &&
    until.getMonth() === now.getMonth() &&
    until.getDate() === now.getDate();

  if (sameDay) return `Muted until ${clockLabel(until)}`;
  return `Muted until ${WEEKDAYS[until.getDay()]}`;
}
