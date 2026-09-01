package com.testlogon.android.feature.knowledgebase.ui

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.kb.KbArticle

/**
 * KB-AND-1 - the exhaustive UI state for the Knowledge Base ARTICLE DETAIL screen.
 *
 * [Loading] is the first-load spinner; [Content] carries the full article (body already plain-text) plus an
 * in-memory [isStale] flag; [NotFound] is the degrade-on-404 state (KB flag off OR unknown id -> Success(null)
 * from the repo); [Error] carries the [ApiError]. A terminal 401 is emitted as a one-shot
 * [KbEffect.NavigateToLogin], not a variant.
 */
sealed interface KbDetailUiState {

    data object Loading : KbDetailUiState

    data class Content(
        val article: KbArticle,
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false,
    ) : KbDetailUiState

    data object NotFound : KbDetailUiState

    data class Error(val error: ApiError) : KbDetailUiState
}
