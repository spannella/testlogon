package com.testlogon.android.feature.maintenance

import com.testlogon.android.core.model.ApiError

/**
 * WOV — UI envelope + pure fold for the Maintenance Work Orders list surface. Android-free + JVM-testable.
 *
 * DEGRADE-ON-404: a 404 (the whole feature flag off) folds to a distinct [Unavailable] state — a calm
 * "not enabled" message, NOT an error with a retry. Any other failure with no prior content -> [Error].
 */
sealed interface MaintenanceOrdersUiState {

    data object Loading : MaintenanceOrdersUiState

    /** A non-empty, board-sorted list. */
    data class Content(
        val orders: List<MaintenanceOrder>,
        val isRefreshing: Boolean = false,
        val staleError: ApiError? = null,
    ) : MaintenanceOrdersUiState

    /** Loaded successfully with zero rows. */
    data object Empty : MaintenanceOrdersUiState

    /** The feature is not enabled on this server (404). */
    data object Unavailable : MaintenanceOrdersUiState

    /** A terminal load error with no prior content. */
    data class Error(val error: ApiError) : MaintenanceOrdersUiState
}

/**
 * PURE fold of a list-load result into a [MaintenanceOrdersUiState]. A 404 -> [Unavailable]; any other
 * error -> [Error]; empty list -> [Empty]; else [Content] (board-sorted).
 */
fun foldOrdersResult(
    orders: List<MaintenanceOrder>?,
    error: ApiError?,
): MaintenanceOrdersUiState = when {
    error != null && error.status == 404 -> MaintenanceOrdersUiState.Unavailable
    error != null -> MaintenanceOrdersUiState.Error(error)
    orders == null || orders.isEmpty() -> MaintenanceOrdersUiState.Empty
    else -> MaintenanceOrdersUiState.Content(orders = sortForBoard(orders))
}
