package com.testlogon.android.feature.admin

import com.testlogon.android.core.model.admin.MessagingDashboard

/**
 * AND-404 - exhaustive UI state for the READ-ONLY admin email/SMS delivery dashboards (AND-404 §4 / FR4).
 *
 * Sealed so the screen renders mutually-exclusive surfaces and a new variant forces an exhaustive `when`. Reuses
 * the AND-403 [AdminErrorType] / [AdminUiError] PII-free error carrier (no raw `detail` strings reach the UI -
 * AND-404 §8/§10).
 *  - [Loading]   - first-load spinner.
 *  - [Content]   - the merged dashboard; [isRefreshing] is the pull-to-refresh spinner, [isStale] marks a
 *                  retained last-good dashboard after a refresh failure, [error] is a TRANSIENT error overlaid
 *                  on existing content (offline-with-cache stale path, FR4 / §7).
 *  - [Empty]     - loaded but stats are all-zero AND activity is empty AND activity did not fail (FR4 / TC-02).
 *  - [Forbidden] - non-admin (client gate verified-non-admin OR backend 403); read-only, offers Back; NO
 *                  dashboard fetch / render (AND-404 FR6 / AC5).
 *  - [Error]     - first load failed with no prior data; retryable per [AdminUiError] (FR4 / AC3). A persistent
 *                  401 is carried here as [AdminErrorType.AUTH] ("Session expired"), not a separate variant.
 */
sealed interface MessagingDashboardUiState {

    data object Loading : MessagingDashboardUiState

    data class Content(
        val dashboard: MessagingDashboard,
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false,
        val error: AdminUiError? = null,
    ) : MessagingDashboardUiState

    data object Empty : MessagingDashboardUiState

    data object Forbidden : MessagingDashboardUiState

    data class Error(val error: AdminUiError) : MessagingDashboardUiState
}
