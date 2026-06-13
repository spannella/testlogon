package com.testlogon.android.feature.sponsorship.ui

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.sponsorship.SponsorshipDeal
import com.testlogon.android.core.model.sponsorship.SponsorshipDealGroup

/**
 * AND-365 - the client-side filter selection for the sponsorship inbox.
 *
 * [ALL] shows every deal; the four group filters map to [SponsorshipDealGroup] (Pending / Active /
 * Completed / Cancelled), the same buckets the web client uses. The filter is applied CLIENT-SIDE over the
 * in-memory list (no query param). [key] is a stable testTag / string-resource suffix.
 */
enum class SponsorshipFilter(val key: String, val group: SponsorshipDealGroup?) {
    ALL("all", null),
    PENDING("pending", SponsorshipDealGroup.PENDING),
    ACTIVE("active", SponsorshipDealGroup.ACTIVE),
    COMPLETED("completed", SponsorshipDealGroup.COMPLETED),
    CANCELLED("cancelled", SponsorshipDealGroup.CANCELLED),
    ;

    /** True when [deal] passes this filter (ALL passes everything; else group-match). */
    fun matches(deal: SponsorshipDeal): Boolean =
        group == null || deal.statusEnum.group == group
}

/**
 * AND-365 - the exhaustive UI state for the READ-ONLY sponsorship inbox.
 *
 * [Loading] is the first-load spinner; [Content] carries the CLIENT-SIDE sorted (newest-first) + filtered
 * deals plus the active [SponsorshipFilter] and an in-memory [isStale] flag (last-good kept on a refresh
 * failure); [Empty] is the zero-deals state (the whole inbox is empty, distinct from a filter that windows
 * to nothing - the chips stay visible in [Content]); [Error] carries the [ApiError] for the retry surface.
 */
sealed interface SponsorshipInboxUiState {

    data object Loading : SponsorshipInboxUiState

    data class Content(
        val deals: List<SponsorshipDeal>,
        val filter: SponsorshipFilter = SponsorshipFilter.ALL,
        val isStale: Boolean = false,
    ) : SponsorshipInboxUiState

    data object Empty : SponsorshipInboxUiState

    data class Error(val error: ApiError) : SponsorshipInboxUiState
}

/** A one-shot navigation effect: open the deal detail (owned downstream by AND-366). */
sealed interface SponsorshipInboxEffect {
    data class OpenDeal(val dealId: String) : SponsorshipInboxEffect
}
