package com.testlogon.android.feature.knowledgebase.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.kb.KbArticleSummary
import com.testlogon.android.core.model.kb.KbCategory
import com.testlogon.android.data.knowledgebase.KbMath
import com.testlogon.android.feature.knowledgebase.data.KbRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * KB-AND-1 - drives the [KbListUiState] for the Knowledge Base LIST / SEARCH screen.
 *
 * On init it loads the categories (best-effort) + the first page of published articles. A non-blank query
 * routes to the search endpoint; clearing the query (or a too-short query) falls back to the category-scoped
 * list. Selecting a category chip re-lists scoped to it. Pull-to-refresh re-reads but, on a NON-401 failure,
 * KEEPS the last-good content and flips isStale (IN-MEMORY only). A TERMINAL 401 -> one-shot
 * [KbEffect.NavigateToLogin]. Degrade-on-404 (KB flag off) resolves to the clean [KbListUiState.Empty].
 */
@HiltViewModel
class KbListViewModel @Inject constructor(
    private val repository: KbRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<KbListUiState>(KbListUiState.Loading)
    val uiState: StateFlow<KbListUiState> = _uiState.asStateFlow()

    private val _effects = Channel<KbEffect>(Channel.BUFFERED)
    val effects: Flow<KbEffect> = _effects.receiveAsFlow()

    private var categories: List<KbCategory> = emptyList()
    private var query: String = ""
    private var selectedCategoryId: String? = null
    private var loadJob: Job? = null

    init {
        load()
    }

    fun load() {
        if (loadJob?.isActive == true) return
        _uiState.value = KbListUiState.Loading
        fetch(isRefresh = false)
    }

    fun onRetry() = load()

    fun refresh() {
        if (loadJob?.isActive == true) return
        (_uiState.value as? KbListUiState.Content)?.let {
            _uiState.value = it.copy(isRefreshing = true)
        }
        fetch(isRefresh = true)
    }

    /** Called as the user edits the search box. Empty / too-short -> the category-scoped list. */
    fun onQueryChange(newQuery: String) {
        query = newQuery
        if (loadJob?.isActive == true) return
        _uiState.value = KbListUiState.Loading
        fetch(isRefresh = false)
    }

    /** Selecting a category chip (null clears the filter). Ignored while a query is active. */
    fun onSelectCategory(categoryId: String?) {
        selectedCategoryId = categoryId
        if (loadJob?.isActive == true) return
        _uiState.value = KbListUiState.Loading
        fetch(isRefresh = false)
    }

    private fun fetch(isRefresh: Boolean) {
        loadJob = viewModelScope.launch {
            // Categories are best-effort; a failure there never blocks the article list.
            if (categories.isEmpty()) {
                (repository.listCategories() as? ApiResult.Success)?.let { categories = it.data }
            }

            val result: ApiResult<List<KbArticleSummary>> =
                if (KbMath.isSearchable(query)) {
                    repository.search(query.trim())
                } else {
                    repository.listArticles(categoryId = selectedCategoryId)
                }

            when (result) {
                is ApiResult.Success -> emitSuccess(result.data)
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _effects.send(KbEffect.NavigateToLogin)
                        clearRefreshing()
                    } else {
                        emitFailure(isRefresh, result.error)
                    }
                }
                is ApiResult.NetworkError ->
                    emitFailure(isRefresh, ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK))
            }
        }
    }

    private fun emitSuccess(articles: List<KbArticleSummary>) {
        _uiState.value = if (articles.isEmpty()) {
            // Distinguish a filtered/searched-but-empty result from a raw empty: still Empty, but keep the
            // chrome (chips + query) so the user can clear the filter — only when there is a query/filter.
            if (query.isBlank() && selectedCategoryId == null) {
                KbListUiState.Empty
            } else {
                KbListUiState.Content(
                    articles = emptyList(),
                    categories = categories,
                    selectedCategoryId = selectedCategoryId,
                    query = query,
                )
            }
        } else {
            KbListUiState.Content(
                articles = articles,
                categories = categories,
                selectedCategoryId = selectedCategoryId,
                query = query,
            )
        }
    }

    private fun emitFailure(isRefresh: Boolean, error: ApiError) {
        val prior = _uiState.value as? KbListUiState.Content
        _uiState.value = if (isRefresh && prior != null) {
            prior.copy(isRefreshing = false, isStale = true)
        } else {
            KbListUiState.Error(error)
        }
    }

    private fun clearRefreshing() {
        (_uiState.value as? KbListUiState.Content)?.let {
            _uiState.value = it.copy(isRefreshing = false)
        }
    }

    private companion object {
        const val HTTP_UNAUTHORIZED = 401
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
