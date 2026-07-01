package com.testlogon.android.feature.marketing

import androidx.annotation.StringRes
import com.testlogon.android.data.marketing.CalendarEntry
import com.testlogon.android.data.marketing.EngagementSummary
import com.testlogon.android.data.marketing.MarketingContent
import com.testlogon.android.data.marketing.MarketingContentPage

/** Content-type filter tabs (mirror the web dashboard TABS). null type = All. */
enum class MarketingTab(val label: String, val type: String?) {
    ALL("All", null),
    BLOG("Blog", "blog_post"),
    SOCIAL("Social", "social_twitter"),
    NEWSLETTER("Newsletter", "newsletter"),
    RELEASE_NOTES("Release Notes", "release_notes"),
    CHANGELOG("Changelog", "changelog"),
}

/** Render-ready state for the Marketing content dashboard (web MarketingContentDashboardPage). */
data class MarketingDashboardUiState(
    val phase: Phase = Phase.Loading,
    val tab: MarketingTab = MarketingTab.ALL,
    val page: MarketingContentPage? = null,
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val errorMessage: String? = null,
    val create: CreateContentFormState = CreateContentFormState(),
    val busyContentId: String? = null,
) {
    enum class Phase { Loading, Content, Empty, SessionExpired, Error, Offline }
}

/** Create-draft form. Mirrors the web validation (title + body required). */
data class CreateContentFormState(
    val isOpen: Boolean = false,
    val contentType: String = "blog_post",
    val title: String = "",
    val body: String = "",
    val isSubmitting: Boolean = false,
) {
    val canSubmit: Boolean
        get() = !isSubmitting && title.trim().isNotEmpty() && body.trim().isNotEmpty()

    companion object {
        val CONTENT_TYPES = listOf(
            "blog_post", "social_twitter", "social_linkedin", "newsletter",
            "release_notes", "changelog", "landing_page", "meta_seo",
        )
    }
}

/** Render-ready state for the content editor (web MarketingContentEditorPage). */
data class MarketingEditorUiState(
    val phase: Phase = Phase.Loading,
    val content: MarketingContent? = null,
    val title: String = "",
    val body: String = "",
    val summary: String = "",
    val tags: String = "",
    val seoTitle: String = "",
    val seoDescription: String = "",
    val scheduleAtSeconds: Long? = null,
    val isSaving: Boolean = false,
    val isApproving: Boolean = false,
    val isScheduling: Boolean = false,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, SessionExpired, Error, Offline }
}

/** Render-ready state for the content calendar (web MarketingContentCalendarPage). */
data class MarketingCalendarUiState(
    val phase: Phase = Phase.Loading,
    val month: String = "",
    val entries: List<CalendarEntry> = emptyList(),
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Empty, SessionExpired, Error, Offline }
}

/** Render-ready state for the engagement dashboard (web MarketingEngagementDashboardPage). */
data class MarketingEngagementUiState(
    val phase: Phase = Phase.Loading,
    val summary: EngagementSummary? = null,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, SessionExpired, Error, Offline }
}

/** One-shot side effects (Channel-backed, not replayed on rotation). */
sealed interface MarketingEffect {
    data class ShowMessage(@StringRes val resId: Int) : MarketingEffect
}
