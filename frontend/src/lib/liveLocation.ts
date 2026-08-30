// Pure helpers for live-location sharing in chat (EPIC D: FE-131 ← BE-131).
// Kept dependency-light (no React, no network, integer/second math with `nowSec`
// injected) so the active/expiry/countdown logic is unit-testable in isolation.
// The rendering (LiveLocationCard) and the watcher/session (useLiveLocationShare)
// reuse these. Coordinate/maps helpers come from ./locationCards (FE-130).

/** Duration choices offered by the "Share live location" picker, in seconds. */
export const LIVE_DURATION_OPTIONS: ReadonlyArray<{ label: string; seconds: number }> = [
  { label: "15 minutes", seconds: 15 * 60 },
  { label: "1 hour", seconds: 60 * 60 },
  { label: "8 hours", seconds: 8 * 60 * 60 },
];

/**
 * How often the sharer pushes a position update (seconds). Used both as the
 * setInterval fallback cadence and as the geolocation `maximumAge` ceiling so a
 * watchPosition callback never relays a stale fix.
 */
export const UPDATE_INTERVAL_SEC = 15;

/** expires_at (epoch sec) for a share started at `startedAt` lasting `durationSec`. */
export function computeExpiresAt(startedAt: number, durationSec: number): number {
  return Math.floor(startedAt) + Math.max(0, Math.floor(durationSec));
}

/**
 * Is the share live right now? Live means not manually stopped AND not past
 * expiry. `stoppedAt` (epoch sec) is undefined/null while running.
 */
export function isLiveActive(
  expiresAt: number,
  stoppedAt: number | null | undefined,
  nowSec: number,
): boolean {
  if (stoppedAt != null) return false;
  return nowSec < expiresAt;
}

/** Whole seconds until expiry, clamped to >= 0. */
export function liveSecondsRemaining(expiresAt: number, nowSec: number): number {
  const rem = Math.floor(expiresAt) - Math.floor(nowSec);
  return rem > 0 ? rem : 0;
}

/** "42:15" for < 1h, "1:02:05" for >= 1h. */
function formatDuration(totalSec: number): string {
  const s = Math.max(0, Math.floor(totalSec));
  const hours = Math.floor(s / 3600);
  const mins = Math.floor((s % 3600) / 60);
  const secs = s % 60;
  const pad = (n: number) => String(n).padStart(2, "0");
  return hours > 0
    ? `${hours}:${pad(mins)}:${pad(secs)}`
    : `${mins}:${pad(secs)}`;
}

/**
 * Badge/countdown label. Live: "Live · 42:15 left". Ended (stopped or expired):
 * "Live location ended".
 */
export function liveRemainingLabel(
  expiresAt: number,
  stoppedAt: number | null | undefined,
  nowSec: number,
): string {
  if (!isLiveActive(expiresAt, stoppedAt, nowSec)) return "Live location ended";
  return `Live · ${formatDuration(liveSecondsRemaining(expiresAt, nowSec))} left`;
}

/**
 * The sharers session should auto-stop once now has reached/passed expiry.
 * (Manual stop and unmount are handled by the hook; this covers timeout.)
 */
export function shouldAutoStop(expiresAt: number, nowSec: number): boolean {
  return Math.floor(nowSec) >= Math.floor(expiresAt);
}
