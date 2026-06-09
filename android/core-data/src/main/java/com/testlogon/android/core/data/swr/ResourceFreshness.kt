package com.testlogon.android.core.data.swr

import com.testlogon.android.core.model.Freshness

/**
 * AND-117 — distills an SWR [Resource] into the UI-facing [Freshness] consumed by the core-ui
 * stale/reconnect bar. This is the single adapter point: if the SWR emission contract changes, only
 * this mapping changes.
 *
 * - [Resource.Loading] with data present → a cached value is shown while a refresh runs.
 * - [Resource.Success] → fresh, DB-sourced value (not cache-stale, not refreshing).
 * - [Resource.Error] with data present → cached value served while the last refresh failed (stale).
 *
 * Total over the sealed hierarchy.
 */
fun Resource<*>.toFreshness(): Freshness = when (this) {
    is Resource.Loading -> Freshness(
        hasCachedValue = data != null,
        isStale = false,
        isRefreshing = true,
        lastRefreshFailed = false,
    )
    is Resource.Success -> Freshness(
        hasCachedValue = false,
        isStale = false,
        isRefreshing = false,
        lastRefreshFailed = false,
    )
    is Resource.Error -> Freshness(
        hasCachedValue = data != null,
        isStale = data != null,
        isRefreshing = false,
        lastRefreshFailed = true,
    )
}
