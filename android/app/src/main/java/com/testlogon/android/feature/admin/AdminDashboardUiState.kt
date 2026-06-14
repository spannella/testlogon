package com.testlogon.android.feature.admin

import com.testlogon.android.core.model.admin.AdminDashboard

/**
 * AND-403 - normalized error kind for the admin dashboard (no raw `detail` strings that may carry identifiers -
 * AND-403 §8/§10). The screen maps each kind to a localised, retryable-or-not message.
 */
enum class AdminErrorType {
    /** Transport/offline (no HTTP response) or a 5xx server error: retryable. */
    NETWORK,

    /** A 5xx the server answered with: retryable. */
    SERVER,

    /** A persistent 401 after the shared refresh: hand off to the auth flow ("Session expired"). */
    AUTH,
}

/** AND-403 - the minimal, PII-free error carrier surfaced to the screen (type drives copy + retryability). */
data class AdminUiError(
    val type: AdminErrorType,
)

/**
 * AND-403 - exhaustive UI state for the READ-ONLY admin alerts/dashboards screen (AND-403 §4).
 *
 * Sealed so the screen renders mutually-exclusive surfaces and a new variant forces an exhaustive `when`.
 *  - [Loading]   - first-load spinner.
 *  - [Content]   - the aggregated dashboard; [isRefreshing] is the pull-to-refresh spinner, [isStale] marks a
 *                  retained last-good dashboard after a refresh failure, [error] is a TRANSIENT error overlaid
 *                  on existing content (AND-403 §6 / FR-9 / AC-6).
 *  - [Empty]     - loaded but BOTH alerts and metrics are empty (AND-403 FR-7 / AC-5 / TC-06).
 *  - [Forbidden] - the caller is not authorised (client gate verified-non-admin OR a backend 403); read-only,
 *                  non-destructive, offers Back; NO data fetched / rendered (AND-403 FR-8 / AC-2).
 *  - [Error]     - first load failed with no prior data; retryable per [AdminUiError] (AND-403 FR-9 / AC-6).
 *
 * A persistent 401 is carried as [Error] with [AdminErrorType.AUTH] ("Session expired" + hand off), NOT a
 * separate variant (AND-403 §5 / AC-7).
 */
sealed interface AdminDashboardUiState {

    data object Loading : AdminDashboardUiState

    data class Content(
        val dashboard: AdminDashboard,
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false,
        val error: AdminUiError? = null,
    ) : AdminDashboardUiState

    data object Empty : AdminDashboardUiState

    data object Forbidden : AdminDashboardUiState

    data class Error(val error: AdminUiError) : AdminDashboardUiState
}
