package com.testlogon.android.feature.licenses

import androidx.annotation.StringRes
import com.testlogon.android.data.licenses.IssuedLicensesPage
import com.testlogon.android.data.licenses.LicenseRequestsPage
import com.testlogon.android.data.licenses.RevenuePage

/**
 * The three sections the licensing hub switches between (SegmentedButton). Stable, locale-agnostic.
 */
enum class LicensesTab { ISSUED, REQUESTS, REVENUE }

/**
 * Single render-ready state for the licensing hub. One immutable data class (not a sealed hierarchy) so
 * content persists across refresh (show prior data while [isRefreshing]). [phase] is the mutually-
 * exclusive top-level surface for the CURRENTLY SELECTED [tab]; each tab loads independently and caches
 * its own page so switching tabs is instant once loaded.
 */
data class LicensesUiState(
    val tab: LicensesTab = LicensesTab.ISSUED,
    val phase: Phase = Phase.Loading,
    val issued: IssuedLicensesPage? = null,
    val requests: LicenseRequestsPage? = null,
    val revenue: RevenuePage? = null,
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Empty, SessionExpired, Error, Offline }
}

/** One-shot side effects (Channel-backed so they are not replayed on rotation). */
sealed interface LicensesEffect {
    data class ShowMessage(@StringRes val resId: Int) : LicensesEffect
}
