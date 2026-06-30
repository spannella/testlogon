package com.testlogon.android.feature.vod.rental

import com.testlogon.android.data.vod.rental.RentalListItem

/** Stable testTags for the "My Rentals" list screen (web VodRentalsPage parity). */
object VodRentalsTestTags {
    const val SCREEN = "vod_rentals_screen"
    const val LIST = "vod_rentals_list"
    const val ROW = "vod_rentals_row"
    const val EMPTY = "vod_rentals_empty"
    const val ERROR_RETRY = "vod_rentals_error_retry"
}

/**
 * Exhaustive UI state for the "My Rentals" screen: the viewer's time-limited rentals + view-once purchases
 * with live status. Mirrors the web VodRentalsPage (list of VodRentalStatus rows). [Loading] first load;
 * [Content] the rows (possibly empty -> empty state); [Error] the retry surface.
 */
sealed interface VodRentalsUiState {

    data object Loading : VodRentalsUiState

    data class Content(val items: List<RentalListItem>) : VodRentalsUiState

    data class Error(val message: String) : VodRentalsUiState
}
