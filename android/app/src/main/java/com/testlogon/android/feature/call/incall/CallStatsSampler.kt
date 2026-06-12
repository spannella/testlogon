package com.testlogon.android.feature.call.incall

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import javax.inject.Inject

/**
 * AND-298 — connection-quality classifier + sampler.
 *
 * [classifyConnectionQuality] is the pure (android-free, SDK-free) decision function; it is unit-tested
 * directly. The real sampler (a future ticket, once native WebRTC is wired) will poll the peer's
 * RTCStatsReport every ~2s and feed RTT / packet-loss / ICE-disconnected / staleness into it. Because the
 * stats seam is FLAGGED (no real RTCStatsReport — the peer controller returns NotConfigured), [quality]
 * emits a single [ConnectionQuality.UNKNOWN].
 *
 * Thresholds:
 *  - iceDisconnected -> LOST
 *  - msSinceLastStats greater than 6000 -> LOST (stats went stale)
 *  - no stats yet (rttMs or packetLossPct null) -> UNKNOWN
 *  - rtt under 150 and loss under 2.0 -> EXCELLENT
 *  - rtt under 300 and loss under 5.0 -> GOOD
 *  - otherwise -> POOR
 */
class CallStatsSampler @Inject constructor() {

    /**
     * Quality stream. FLAGGED: the native stats seam is not wired, so this emits a single UNKNOWN. The real
     * impl will be a ticker that samples peer stats every 2s and maps via [classifyConnectionQuality].
     */
    fun quality(): Flow<ConnectionQuality> = flowOf(ConnectionQuality.UNKNOWN)
}

/**
 * Pure quality classifier (see [CallStatsSampler] KDoc for thresholds). Top-level so it is trivially
 * unit-testable without constructing the sampler.
 */
fun classifyConnectionQuality(
    rttMs: Long?,
    packetLossPct: Double?,
    iceDisconnected: Boolean,
    msSinceLastStats: Long?,
): ConnectionQuality {
    if (iceDisconnected) return ConnectionQuality.LOST
    if (msSinceLastStats != null && msSinceLastStats > 6_000) return ConnectionQuality.LOST
    if (rttMs == null || packetLossPct == null) return ConnectionQuality.UNKNOWN
    return when {
        rttMs < 150 && packetLossPct < 2.0 -> ConnectionQuality.EXCELLENT
        rttMs < 300 && packetLossPct < 5.0 -> ConnectionQuality.GOOD
        else -> ConnectionQuality.POOR
    }
}
