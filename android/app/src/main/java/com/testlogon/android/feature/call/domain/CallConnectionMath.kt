package com.testlogon.android.feature.call.domain

/**
 * FE-143 — pure (android-free, SDK-free) mapping + timing math for the WebRTC connection-state UI, ICE
 * restart, and TURN-credential refresh. All inputs are Strings / Longs so this is fully JVM-unit-testable
 * without pulling in the native WebRTC SDK (the ICE state is passed as its libwebrtc enum NAME).
 *
 * Reference for the ICE connection-state names (livekit.org.webrtc.PeerConnection.IceConnectionState):
 * NEW, CHECKING, CONNECTED, COMPLETED, FAILED, DISCONNECTED, CLOSED.
 */
object CallConnectionMath {

    /** Lead time (seconds) before TURN-credential expiry at which we proactively refresh on a long call. */
    const val TURN_REFRESH_LEAD_SEC: Long = 60

    /**
     * Grace (seconds) a peer may sit in DISCONNECTED before we treat it as needing an ICE restart. A brief
     * DISCONNECTED is often self-healing (WebRTC keeps probing), so we only restart once it persists.
     */
    const val ICE_DISCONNECT_GRACE_SEC: Long = 5

    /**
     * Maps a libwebrtc IceConnectionState enum NAME to the coarse UI connection status. Unknown/blank names
     * fall back to CONNECTING (the safest "still working" state) so a new/unexpected value never crashes.
     */
    fun mapConnectionStatus(iceState: String?): CallConnectionStatus =
        when (iceState?.trim()?.uppercase()) {
            "NEW", "CHECKING" -> CallConnectionStatus.CONNECTING
            "CONNECTED", "COMPLETED" -> CallConnectionStatus.CONNECTED
            "DISCONNECTED" -> CallConnectionStatus.RECONNECTING
            "FAILED" -> CallConnectionStatus.FAILED
            "CLOSED" -> CallConnectionStatus.CLOSED
            else -> CallConnectionStatus.CONNECTING
        }

    /**
     * Whether an ICE restart should be triggered for [iceState]. FAILED always restarts. DISCONNECTED
     * restarts only once it has persisted past [ICE_DISCONNECT_GRACE_SEC] (measured by the caller as
     * [disconnectedForSec]); a brief blip is left to WebRTC's own re-probing.
     */
    fun shouldIceRestart(iceState: String?, disconnectedForSec: Long = Long.MAX_VALUE): Boolean =
        when (iceState?.trim()?.uppercase()) {
            "FAILED" -> true
            "DISCONNECTED" -> disconnectedForSec >= ICE_DISCONNECT_GRACE_SEC
            else -> false
        }

    /** True once the TURN credentials have expired at [nowSec] (expiry is epoch SECONDS). */
    fun isTurnExpired(expiresAtSec: Long, nowSec: Long): Boolean = nowSec >= expiresAtSec

    /**
     * True when TURN credentials should be proactively refreshed: within [leadSec] of expiry (or already
     * expired). A non-positive [expiresAtSec] means "no known expiry" (e.g. STUN-only fallback) — never
     * refresh in that case.
     */
    fun shouldRefreshTurn(
        expiresAtSec: Long,
        nowSec: Long,
        leadSec: Long = TURN_REFRESH_LEAD_SEC,
    ): Boolean {
        if (expiresAtSec <= 0L) return false
        return nowSec >= expiresAtSec - leadSec
    }
}

/** FE-143 — coarse UI connection status derived from the peer ICE connection state. */
enum class CallConnectionStatus { CONNECTING, CONNECTED, RECONNECTING, FAILED, CLOSED }
