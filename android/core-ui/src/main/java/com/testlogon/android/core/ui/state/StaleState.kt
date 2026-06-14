package com.testlogon.android.core.ui.state

import com.testlogon.android.core.model.BackendStatus
import com.testlogon.android.core.model.Freshness
import com.testlogon.android.core.ui.R

/**
 * AND-117 — fully-derived presentation state for the per-screen stale/reconnect bar.
 *
 * Computed purely from [Freshness] + [BackendStatus] by [deriveStaleState]; the bar composable is
 * stateless w.r.t. this value (previewable, directly UI-testable).
 *
 * @param showBar       whether the bar is visible.
 * @param mode          severity/intent (drives icon + Material role).
 * @param messageRes    string resource for the bar copy (0 when hidden).
 * @param retryEnabled  whether the "Try again" action is enabled.
 */
data class StaleState(
    val showBar: Boolean = false,
    val mode: Mode = Mode.None,
    val messageRes: Int = 0,
    val retryEnabled: Boolean = false,
) {
    enum class Mode { None, Stale, RefreshFailed, Reconnecting }
}

/**
 * AND-117 — pure mapping from cache freshness + backend health to [StaleState]. No I/O.
 *
 * Precedence: no-cache (hidden, FR-6) → reconnecting (in flight) → refresh-failed (host down vs.
 * other) → TTL-stale → fresh (hidden, FR-5).
 *
 * NOTE: the project's [BackendStatus] is the 3-state `Unknown|Up|Down` model; [BackendStatus.Down]
 * yields the "Offline — showing saved data." copy, other states yield "Couldn't refresh…".
 */
fun deriveStaleState(
    freshness: Freshness,
    backend: BackendStatus,
): StaleState = when {
    !freshness.hasCachedValue -> StaleState() // FR-6: nothing to show yet

    freshness.isRefreshing -> StaleState(
        showBar = true,
        mode = StaleState.Mode.Reconnecting,
        messageRes = R.string.stale_reconnecting,
        retryEnabled = false, // FR-3 retry-storm guard
    )

    freshness.lastRefreshFailed && backend is BackendStatus.Down -> StaleState(
        showBar = true,
        mode = StaleState.Mode.RefreshFailed,
        messageRes = R.string.stale_offline_saved,
        retryEnabled = true,
    )

    freshness.lastRefreshFailed -> StaleState(
        showBar = true,
        mode = StaleState.Mode.RefreshFailed,
        messageRes = R.string.stale_refresh_failed,
        retryEnabled = true,
    )

    freshness.isStale -> StaleState(
        showBar = true,
        mode = StaleState.Mode.Stale,
        messageRes = R.string.stale_showing_saved,
        retryEnabled = true,
    )

    else -> StaleState() // fresh data → FR-5
}
