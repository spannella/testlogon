package com.testlogon.android.feature.ads.scheduling.ui

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.network.ads.CampaignFlightDto

/**
 * Hoisted UI state for the ad SCHEDULING editor (web parity: AdSchedulePage.tsx + DaypartingGrid +
 * FlightScheduler).
 *
 *  - [Loading] - resolving the campaign + loading schedule/templates.
 *  - [NoCampaign] - nothing to schedule.
 *  - [Error] - fatal load failure; retryable.
 *  - [Content] - the editable dayparting grid + timezone + read-only flights + pacing/eligibility summary.
 */
sealed interface AdSchedulingUiState {

    data object Loading : AdSchedulingUiState

    data object NoCampaign : AdSchedulingUiState

    data class Error(val error: ApiError) : AdSchedulingUiState

    data class Content(
        val campaignId: String,
        val campaignName: String,
        val timezone: String,
        /** day-of-week (lowercase) -> set of active hours (0-23). */
        val schedule: Map<String, Set<Int>>,
        val templateNames: List<String>,
        val flights: List<CampaignFlightDto>,
        val eligibleNow: Boolean? = null,
        val hourlyBudgetCents: Long? = null,
        val saving: Boolean = false,
        val saved: Boolean = false,
        val actionError: String? = null,
    ) : AdSchedulingUiState
}

/** Canonical day order for the 7-row dayparting grid. */
val DAY_ORDER: List<String> = listOf(
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
)
