package com.testlogon.android.feature.ads.contentcontrols.ui

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ads.AdDensity
import com.testlogon.android.core.model.ads.AdRevenueBreakdown
import com.testlogon.android.core.model.ads.AdvertiserTransparency
import com.testlogon.android.core.model.ads.ContentAdOverride

/**
 * Hoisted UI state for the CONTENT AD-CONTROLS screen (web parity: ContentAdControlsPage.tsx +
 * AdRevenueBreakdownCard.tsx).
 *
 *  - [Loading] - the initial overrides + revenue-share + breakdown load is in flight.
 *  - [Error]   - a fatal initial load failure; retryable.
 *  - [Content] - the full screen: the per-content override editor [form], the active [overrides] list, the
 *    current revenue share [revenueShareBps] + its editor [shareInput], and the ad-revenue [breakdown] +
 *    [advertisers] transparency over [breakdownDays].
 */
sealed interface ContentAdControlsUiState {

    data object Loading : ContentAdControlsUiState

    data class Error(val error: ApiError) : ContentAdControlsUiState

    data class Content(
        // Override editor
        val form: OverrideForm = OverrideForm(),
        val saving: Boolean = false,
        val saveError: String? = null,
        val saved: Boolean = false,
        // Active overrides
        val overrides: List<ContentAdOverride> = emptyList(),
        val deletingContentId: String? = null,
        // Revenue share
        val revenueShareBps: Int = 7000,
        val shareInput: String = "",
        val savingShare: Boolean = false,
        val shareError: String? = null,
        // Breakdown / transparency
        val breakdownDays: Int = 30,
        val breakdown: AdRevenueBreakdown? = null,
        val advertisers: List<AdvertiserTransparency> = emptyList(),
        val breakdownLoading: Boolean = false,
    ) : ContentAdControlsUiState
}

/** The editable per-content override spec. [contentId] is required to save. */
data class OverrideForm(
    val contentId: String = "",
    val adEnabled: Boolean = true,
    val adDensity: AdDensity = AdDensity.STANDARD,
    val preRollEnabled: Boolean = true,
    val midRollEnabled: Boolean = true,
    val adsFreeForSubscribers: Boolean = false,
) {
    val canSave: Boolean get() = contentId.isNotBlank()
}
