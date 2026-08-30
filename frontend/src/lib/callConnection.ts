/**
 * callConnection — pure, deterministic helpers for WebRTC call connection
 * state (FE-143, EPIC E). These have no browser/RTC dependencies so they are
 * unit-testable in isolation. All time is passed in as integer epoch seconds
 * (nowSec injected) — nothing here reads the clock.
 *
 * Responsibilities:
 *  - mapConnectionStatus: collapse RTCPeerConnectionState + RTCIceConnectionState
 *    into a single UI status with a deterministic precedence.
 *  - connectionBadge: presentation (label + tone) for a status.
 *  - shouldIceRestart: decide when to trigger an ICE restart.
 *  - isTurnExpired / shouldRefreshTurn: TURN credential TTL math for long calls.
 */

/** Coarse connection status surfaced in the call UI. */
export type CallConnectionStatus =
  | "new"
  | "connecting"
  | "connected"
  | "reconnecting"
  | "failed"
  | "closed";

export interface ConnectionStatusResult {
  status: CallConnectionStatus;
  label: string;
}

/** Visual tone for a connection badge. */
export type ConnectionBadgeTone = "neutral" | "info" | "success" | "warning" | "danger";

export interface ConnectionBadge {
  label: string;
  tone: ConnectionBadgeTone;
}

/**
 * Seconds before a TURN credential's expiry at which we proactively refresh.
 * Kept comfortably ahead of typical fetch + ICE-reconfig latency so a long
 * call never runs on an expired allocation.
 */
export const TURN_REFRESH_LEAD_SEC = 60;

const STATUS_LABEL: Record<CallConnectionStatus, string> = {
  new: "Starting…",
  connecting: "Connecting…",
  connected: "Connected",
  reconnecting: "Reconnecting…",
  failed: "Connection failed",
  closed: "Call ended",
};

/**
 * Collapse the two native RTC state enums into one UI status.
 *
 * Precedence (highest first):
 *   failed > closed > connected > reconnecting(disconnected) > connecting > new
 *
 * The PeerConnection aggregate (pcState) is authoritative for terminal/success
 * states; the ICE state distinguishes a transient "disconnected" (-> reconnecting)
 * from a clean "connecting". A null for either enum is treated as "not yet known".
 */
export function mapConnectionStatus(
  pcState: RTCPeerConnectionState | null | undefined,
  iceState: RTCIceConnectionState | null | undefined,
): ConnectionStatusResult {
  // failed wins over everything
  if (pcState === "failed" || iceState === "failed") {
    return { status: "failed", label: STATUS_LABEL.failed };
  }
  if (pcState === "closed") {
    return { status: "closed", label: STATUS_LABEL.closed };
  }
  // connected/completed is a positive signal from either enum
  if (pcState === "connected" || iceState === "connected" || iceState === "completed") {
    return { status: "connected", label: STATUS_LABEL.connected };
  }
  // a live-but-interrupted connection: ICE dropped to disconnected
  if (pcState === "disconnected" || iceState === "disconnected") {
    return { status: "reconnecting", label: STATUS_LABEL.reconnecting };
  }
  if (pcState === "connecting" || iceState === "checking") {
    return { status: "connecting", label: STATUS_LABEL.connecting };
  }
  return { status: "new", label: STATUS_LABEL.new };
}

const BADGE_TONE: Record<CallConnectionStatus, ConnectionBadgeTone> = {
  new: "neutral",
  connecting: "info",
  connected: "success",
  reconnecting: "warning",
  failed: "danger",
  closed: "neutral",
};

/** Presentation for a connection status: label + tone. */
export function connectionBadge(status: CallConnectionStatus): ConnectionBadge {
  return { label: STATUS_LABEL[status], tone: BADGE_TONE[status] };
}

/**
 * Whether an ICE restart should be attempted for the given ICE state.
 *
 * - "failed": always restart (the connection is dead, negotiation is required).
 * - "disconnected": restart only once the grace period has elapsed — a brief
 *   blip often self-heals. `pastGrace` is decided by the caller (which owns the
 *   grace timer); default false so a bare "disconnected" does not thrash.
 */
export function shouldIceRestart(
  iceState: RTCIceConnectionState | null | undefined,
  pastGrace = false,
): boolean {
  if (iceState === "failed") return true;
  if (iceState === "disconnected") return pastGrace;
  return false;
}

/** Whether a TURN credential (expiry in epoch seconds) is already expired. */
export function isTurnExpired(expiresAtSec: number, nowSec: number): boolean {
  return nowSec >= expiresAtSec;
}

/**
 * Whether TURN credentials should be refreshed now: true once we are within
 * `leadSec` of expiry (and, a fortiori, once already expired).
 */
export function shouldRefreshTurn(
  expiresAtSec: number,
  nowSec: number,
  leadSec: number = TURN_REFRESH_LEAD_SEC,
): boolean {
  return nowSec >= expiresAtSec - leadSec;
}
