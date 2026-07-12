package com.testlogon.android.feature.pmideas

import androidx.annotation.StringRes
import com.testlogon.android.data.pmideas.PmIdea
import com.testlogon.android.data.pmideas.PmIdeaStatus

enum class PmIdeasPhase { Loading, Content, Empty, SessionExpired, Error, Offline }

sealed interface PmIdeasEffect {
    data class ShowMessage(@StringRes val resId: Int) : PmIdeasEffect
}

/**
 * Single render-ready state for the PM-idea triage screen (web /agents/pm/ideas). [tab] selects the
 * status filter; [ideas] holds the current tab's list. [rejectForm] drives the reject-reason dialog;
 * [detail] drives the read-only idea-detail dialog.
 */
data class PmIdeasUiState(
    val phase: PmIdeasPhase = PmIdeasPhase.Loading,
    val tab: PmIdeaStatus = PmIdeaStatus.PENDING,
    val ideas: List<PmIdea> = emptyList(),
    val isRefreshing: Boolean = false,
    val isTriggeringReview: Boolean = false,
    val errorMessage: String? = null,
    val rejectForm: RejectFormState = RejectFormState(),
    val detail: PmIdea? = null,
)

/** Reject-reason dialog state. Mirrors the web reject flow (a required reason). */
data class RejectFormState(
    val ideaId: String? = null,
    val reason: String = "",
    val isSubmitting: Boolean = false,
) {
    val isOpen: Boolean get() = ideaId != null
    val canSubmit: Boolean get() = !isSubmitting && reason.trim().isNotEmpty()
}
