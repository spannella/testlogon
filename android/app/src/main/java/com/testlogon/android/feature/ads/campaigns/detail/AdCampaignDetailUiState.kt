package com.testlogon.android.feature.ads.campaigns.detail

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ads.AdCampaign

/**
 * ADV3-4 (B2) - hoisted UI state for the campaign MANAGEMENT (detail) screen.
 *
 *  - [Loading] - the initial campaign read is in flight.
 *  - [Content] - the loaded campaign. [action] is a SEPARATE mutation sub-state so a pause/resume/edit in
 *    flight / error never clobbers the rendered campaign; on success the VM re-reads and clears it to Idle.
 *  - [Error]   - a fatal first-load failure (no campaign); retryable.
 */
sealed interface AdCampaignDetailUiState {

    data object Loading : AdCampaignDetailUiState

    data class Content(
        val campaign: AdCampaign,
        val action: ActionState = ActionState.Idle,
    ) : AdCampaignDetailUiState

    data class Error(val error: ApiError) : AdCampaignDetailUiState
}

/**
 * ADV3-4 - the SEPARATE campaign-mutation sub-state (pause/resume/edit/archive). [Submitting] disables the
 * action buttons + guards against a double-submit; [Error] carries a friendly message. Every mutation is
 * NON-idempotent (the server validates the status transition) so there is NO auto-retry.
 */
sealed interface ActionState {
    data object Idle : ActionState
    data object Submitting : ActionState
    data class Error(val message: String) : ActionState
}
