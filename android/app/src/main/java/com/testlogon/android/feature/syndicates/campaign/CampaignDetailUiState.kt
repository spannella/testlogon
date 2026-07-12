package com.testlogon.android.feature.syndicates.campaign

/** UI state for the syndicate campaign DETAIL screen. */
sealed interface CampaignDetailUiState {

    data object Loading : CampaignDetailUiState

    data class Content(
        val campaign: SyndicateCampaign,
        val analytics: CampaignAnalytics?,
        /** Whether the viewer administers this syndicate (gates status / add-budget controls). */
        val isAdmin: Boolean,
        val mutating: Boolean = false,
        val actionError: String? = null,
        val isStale: Boolean = false,
    ) : CampaignDetailUiState

    data class Error(val message: String) : CampaignDetailUiState
}
