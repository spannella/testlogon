package com.testlogon.android.feature.ads.optimization.ui

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.network.ads.AdRecommendationDto
import com.testlogon.android.core.network.ads.BudgetRecommendationDto
import com.testlogon.android.core.network.ads.SuggestedBidDto

/**
 * Hoisted UI state for the ad OPTIMIZATION panel (web parity: AdOptimizationPanel.tsx +
 * AdOptimizationRecommendationCards).
 *
 *  - [Loading] - resolving the campaign + loading recommendations + bid/budget summary.
 *  - [NoCampaign] - nothing to optimize.
 *  - [Error] - fatal load failure; retryable.
 *  - [Content] - the recommendations list + suggested-bid/budget cards + auto-optimize toggle.
 */
sealed interface AdOptimizationUiState {

    data object Loading : AdOptimizationUiState

    data object NoCampaign : AdOptimizationUiState

    data class Error(val error: ApiError) : AdOptimizationUiState

    data class Content(
        val campaignId: String,
        val campaignName: String,
        val recommendations: List<AdRecommendationDto>,
        val suggestedBid: SuggestedBidDto? = null,
        val budgetRecommendation: BudgetRecommendationDto? = null,
        val autoOptimizeEnabled: Boolean = false,
        val generating: Boolean = false,
        /** recommendation ids with an apply/dismiss action in flight. */
        val busyRecIds: Set<String> = emptySet(),
        val togglingAuto: Boolean = false,
        val actionError: String? = null,
    ) : AdOptimizationUiState
}
