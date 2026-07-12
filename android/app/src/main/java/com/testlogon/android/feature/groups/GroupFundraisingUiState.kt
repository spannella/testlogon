package com.testlogon.android.feature.groups

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.groups.GroupFundraiser

/**
 * AND-355 (sub-pages) - render-ready state for the group FUNDRAISING screen (lists fundraisers; offers a
 * create action that is admin-gated at the service layer -> a 403 surfaces a non-fatal snackbar notice).
 */
sealed interface GroupFundraisingUiState {

    data object Loading : GroupFundraisingUiState

    data class Content(
        val fundraisers: List<GroupFundraiser>,
        val isCreating: Boolean = false,
        val notice: String? = null,
    ) : GroupFundraisingUiState

    data class Error(val error: ApiError) : GroupFundraisingUiState
}
