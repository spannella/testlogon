package com.testlogon.android.feature.groups

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.groups.GroupCampaign
import com.testlogon.android.core.model.groups.GroupCampaignStats

/**
 * AND-355 (sub-pages) - render-ready state for the group ADS (advertising campaigns) screen. Lists
 * campaigns with their per-campaign [stats] (keyed by campaignId; best-effort, may be absent). The create
 * action is admin-gated at the service layer -> a 403 surfaces a non-fatal snackbar notice.
 */
sealed interface GroupAdsUiState {

    data object Loading : GroupAdsUiState

    data class Content(
        val campaigns: List<GroupCampaign>,
        val stats: Map<String, GroupCampaignStats> = emptyMap(),
        val isCreating: Boolean = false,
        val notice: String? = null,
    ) : GroupAdsUiState

    data class Error(val error: ApiError) : GroupAdsUiState
}
