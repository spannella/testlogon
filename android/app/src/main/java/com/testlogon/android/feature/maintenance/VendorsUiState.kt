package com.testlogon.android.feature.maintenance

import com.testlogon.android.core.model.ApiError

/**
 * WOV-004 — UI envelope + pure fold for the Maintenance Vendor directory list surface. Android-free +
 * JVM-testable.
 *
 * DEGRADE-ON-404: a 404 (the whole feature flag off) folds to a distinct [Unavailable] state — a calm
 * "not enabled" message, NOT an error with a retry. Any other failure with no prior content -> [Error].
 */
sealed interface VendorsUiState {

    data object Loading : VendorsUiState

    /** A non-empty, sorted vendor list. */
    data class Content(
        val vendors: List<Vendor>,
        val isRefreshing: Boolean = false,
        val staleError: ApiError? = null,
    ) : VendorsUiState

    /** Loaded successfully with zero rows. */
    data object Empty : VendorsUiState

    /** The feature is not enabled on this server (404). */
    data object Unavailable : VendorsUiState

    /** A terminal load error with no prior content. */
    data class Error(val error: ApiError) : VendorsUiState
}

/**
 * PURE fold of a vendor-list-load result into a [VendorsUiState]. A 404 -> [Unavailable]; any other
 * error -> [Error]; empty list -> [Empty]; else [Content] (status-sorted).
 */
fun foldVendorsResult(
    vendors: List<Vendor>?,
    error: ApiError?,
): VendorsUiState = when {
    error != null && error.status == 404 -> VendorsUiState.Unavailable
    error != null -> VendorsUiState.Error(error)
    vendors == null || vendors.isEmpty() -> VendorsUiState.Empty
    else -> VendorsUiState.Content(vendors = sortVendors(vendors))
}
