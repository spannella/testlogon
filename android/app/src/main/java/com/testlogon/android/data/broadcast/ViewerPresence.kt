package com.testlogon.android.data.broadcast

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-285 — the live viewer-count exposure seam.
 *
 * The viewer presence lifecycle (join on play, a bounded heartbeat while watching, leave on
 * stop/background/dispose) is owned by the REUSED AND-171 PlaybackReporter + CoroutineHeartbeatSink
 * (no second heartbeat loop). Those calls already receive the authoritative `viewer_count` from the
 * `viewers/join` / `viewers/heartbeat` responses; this holder simply publishes that latest count so
 * the viewer ViewModel/UI can render a live badge without adding a parallel presence engine.
 *
 * Single active watch session (FR-5/FR-9), so a single [StateFlow] suffices. `null` means "no
 * count known yet" — the UI hides the badge rather than showing a misleading zero (FR-4). The sink
 * is the only writer; the count is in-memory only and intentionally NOT persisted (FR-6/§6).
 */
@Singleton
class ViewerPresence @Inject constructor() {

    private val _viewerCount = MutableStateFlow<Int?>(null)

    /** Latest server-reported viewer count for the active session, or null until first known. */
    val viewerCount: StateFlow<Int?> = _viewerCount.asStateFlow()

    /** Called by the sink on each successful join/heartbeat (and on a best-effort count poll). */
    fun update(count: Int) {
        _viewerCount.value = count
    }

    /** Called on session start/teardown so a stale count from a prior session never leaks. */
    fun reset() {
        _viewerCount.value = null
    }
}
