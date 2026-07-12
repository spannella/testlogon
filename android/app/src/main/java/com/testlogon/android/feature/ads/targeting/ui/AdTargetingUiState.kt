package com.testlogon.android.feature.ads.targeting.ui

import com.testlogon.android.core.model.ApiError

/**
 * Hoisted UI state for the ad TARGETING editor (web parity: TargetingEditor.tsx).
 *
 *  - [Loading] - resolving the campaign + loading its targeting set.
 *  - [NoCampaign] - the caller has no ad account / campaign to target (terminal, non-retryable here).
 *  - [Error] - a fatal load failure; retryable.
 *  - [Content] - the editable targeting form for [campaignId] / [campaignName]. [form] is the live edit
 *    buffer; [estimatedReach] is the latest audience estimate (null until first estimate returns);
 *    [estimating] / [saving] drive progress affordances; [saved] flips true after a successful save;
 *    [actionError] holds a transient save/estimate error message.
 */
sealed interface AdTargetingUiState {

    data object Loading : AdTargetingUiState

    data object NoCampaign : AdTargetingUiState

    data class Error(val error: ApiError) : AdTargetingUiState

    data class Content(
        val campaignId: String,
        val campaignName: String,
        val targetSetId: String?,
        val form: TargetingForm,
        val estimatedReach: Long? = null,
        val estimating: Boolean = false,
        val saving: Boolean = false,
        val saved: Boolean = false,
        val actionError: String? = null,
    ) : AdTargetingUiState
}

/** The editable targeting spec (mirrors the backend TargetingCreateIn fields the editor exposes). */
data class TargetingForm(
    val name: String = "Default",
    val ageRanges: Set<String> = emptySet(),
    val genders: Set<String> = emptySet(),
    val countryCodes: List<String> = emptyList(),
    val contentCategories: Set<String> = emptySet(),
    val deviceTypes: Set<String> = emptySet(),
    val activeHours: Set<Int> = emptySet(),
    val newUserOnly: Boolean = false,
)
