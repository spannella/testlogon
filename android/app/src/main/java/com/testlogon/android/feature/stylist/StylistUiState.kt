package com.testlogon.android.feature.stylist

import androidx.annotation.StringRes
import com.testlogon.android.data.stylist.DesignOverview
import com.testlogon.android.data.stylist.DesignRule
import com.testlogon.android.data.stylist.UIReview

/**
 * Render-ready state for the Stylist "Design Overview" screen (web StylistDesignOverviewPage).
 * One immutable data class so content persists across refresh; [phase] enumerates the mutually
 * exclusive top-level surfaces. [isTriggering] drives the "Run Review" spinner.
 */
data class StylistOverviewUiState(
    val phase: Phase = Phase.Loading,
    val overview: DesignOverview? = null,
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val isTriggering: Boolean = false,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Empty, SessionExpired, Error, Offline }
}

/**
 * Render-ready state for the Stylist "Design Rules" screen (web StylistDesignRulesPage).
 * [create] carries the add-rule dialog form.
 */
data class StylistRulesUiState(
    val phase: Phase = Phase.Loading,
    val rules: List<DesignRule> = emptyList(),
    val isRefreshing: Boolean = false,
    val errorMessage: String? = null,
    val create: RuleFormState = RuleFormState(),
) {
    enum class Phase { Loading, Content, Empty, SessionExpired, Error, Offline }
}

/** Add-rule dialog form. Mirrors the web validation (name + description required). */
data class RuleFormState(
    val isOpen: Boolean = false,
    val name: String = "",
    val category: String = "spacing",
    val description: String = "",
    val severity: String = "warning",
    val isSubmitting: Boolean = false,
) {
    val canSubmit: Boolean
        get() = !isSubmitting && name.trim().isNotEmpty() && description.trim().isNotEmpty()

    companion object {
        val CATEGORIES = listOf(
            "spacing", "color", "typography", "layout", "component", "responsive", "accessibility",
        )
        val SEVERITIES = listOf("error", "warning", "info")
    }
}

/** Render-ready state for the Stylist review-detail screen (web StylistReviewDetailPage). */
data class StylistReviewUiState(
    val phase: Phase = Phase.Loading,
    val review: UIReview? = null,
    val creatingTicketIssueId: String? = null,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, SessionExpired, Error, Offline }
}

/** One-shot side effects (Channel-backed, not replayed on rotation). */
sealed interface StylistEffect {
    data class ShowMessage(@StringRes val resId: Int) : StylistEffect
}
