package com.testlogon.android.data.analytics

import java.util.concurrent.atomic.AtomicLong
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-171 §6 — local-only heartbeat configuration.
 *
 * CORRECTED (verified, §6/§16): there is NO `next_interval_ms` in any server response, so there is no
 * runtime server-driven override. The interval is configured locally; re-reading it on each tick lets
 * a local/remote-config change be picked up, but never a per-response server directive. Default 10s,
 * bounded 5s..60s ([HeartbeatLogic.clampInterval]).
 */
interface HeartbeatConfigStore {
    /** The current (clamped) interval in ms, read on each tick. */
    fun intervalMs(): Long

    /** Whether reporting is enabled (consent gate seam, §8; defaults on). */
    fun enabled(): Boolean

    /** Local override of the interval (e.g. from a future remote-config); clamped on read. */
    fun setIntervalMs(intervalMs: Long)
}

@Singleton
class DefaultHeartbeatConfigStore @Inject constructor() : HeartbeatConfigStore {
    private val interval = AtomicLong(HeartbeatLogic.DEFAULT_INTERVAL_MS)

    @Volatile
    private var enabledFlag = true

    override fun intervalMs(): Long = HeartbeatLogic.clampInterval(interval.get())

    override fun enabled(): Boolean = enabledFlag

    override fun setIntervalMs(intervalMs: Long) {
        interval.set(intervalMs)
    }
}
