package com.testlogon.android.feature.messaging.helpdesk

import com.testlogon.android.core.model.helpdesk.HelpdeskMetrics

/**
 * AND-377 — UI state for the helpdesk agent dashboard (FR-5).
 *
 * Distinct surfaces: first-load [Loading]; agent-gated [AccessDenied] (queue 403); [Content] with the
 * derived metrics + an optional stale banner; [Empty] (agent, but no data yet); and a retryable
 * [Error]. [Content.isStale] / [Content.cachedAtEpochSeconds] drive the "showing cached data" banner.
 */
sealed interface HelpdeskDashboardUiState {
    data object Loading : HelpdeskDashboardUiState
    data object AccessDenied : HelpdeskDashboardUiState
    data class Content(
        val metrics: HelpdeskMetrics,
        val isStale: Boolean,
        val cachedAtEpochSeconds: Long?,
    ) : HelpdeskDashboardUiState
    data object Empty : HelpdeskDashboardUiState
    data class Error(val message: String, val retryable: Boolean) : HelpdeskDashboardUiState
}
