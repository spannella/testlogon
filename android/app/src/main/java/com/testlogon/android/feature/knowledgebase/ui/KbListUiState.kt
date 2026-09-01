package com.testlogon.android.feature.knowledgebase.ui

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.kb.KbArticleSummary
import com.testlogon.android.core.model.kb.KbCategory

/**
 * KB-AND-1 - the exhaustive UI state for the Knowledge Base LIST / SEARCH screen.
 *
 * Sealed so the screen renders mutually-exclusive surfaces; a new variant forces an exhaustive `when`.
 * [Loading] is the first-load spinner; [Content] carries the articles + the (optional) category chips + the
 * active query + an in-memory [isStale] flag (last-good kept on a refresh failure) + [isRefreshing];
 * [Empty] is the zero-results state (also the degrade-on-404 state - the KB flag is off); [Error] carries the
 * [ApiError]. A terminal 401 is NOT a variant - it is a one-shot [KbEffect.NavigateToLogin].
 */
sealed interface KbListUiState {

    data object Loading : KbListUiState

    data class Content(
        val articles: List<KbArticleSummary>,
        val categories: List<KbCategory> = emptyList(),
        val selectedCategoryId: String? = null,
        val query: String = "",
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false,
    ) : KbListUiState

    data object Empty : KbListUiState

    data class Error(val error: ApiError) : KbListUiState
}

/**
 * KB-AND-1 - one-shot navigation effects for the KB ViewModels. [NavigateToLogin] is emitted on a TERMINAL 401
 * so the screen routes to the login / unauthenticated graph (re-auth handoff) rather than a generic error.
 */
sealed interface KbEffect {
    data object NavigateToLogin : KbEffect
}
