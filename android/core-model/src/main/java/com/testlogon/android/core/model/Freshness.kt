package com.testlogon.android.core.model

/**
 * AND-117 — distilled cache freshness metadata, decoupled from any specific SWR `Resource` type.
 *
 * Lives in `core-model` so both `core-data` (which produces it from its SWR `Resource`) and
 * `core-ui` (which renders the stale/reconnect bar from it) can share it without a module
 * dependency between them — `core-ui` performs NO network/cache I/O (AND-117 AC-6).
 *
 * @param hasCachedValue    a present, cache-sourced value exists (gates the bar; FR-6).
 * @param isStale           the cached value is older than its freshness TTL.
 * @param isRefreshing      a background revalidation is in flight.
 * @param lastRefreshFailed the most recent revalidation failed.
 */
data class Freshness(
    val hasCachedValue: Boolean,
    val isStale: Boolean,
    val isRefreshing: Boolean,
    val lastRefreshFailed: Boolean,
)
