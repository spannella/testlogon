package com.testlogon.android.feature.knowledgebase.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.knowledgebase.data.KbRepository
import com.testlogon.android.navigation.KbArticleDetailDest
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
 * KB-AND-1 - drives the [KbDetailUiState] for the Knowledge Base ARTICLE DETAIL screen.
 *
 * articleId arrives as a nav arg via [SavedStateHandle] (survives process death). [load] fetches the full
 * article (repo maps a 404 to Success(null) -> [KbDetailUiState.NotFound], degrade-on-404). Pull-to-refresh
 * re-reads but, on a NON-401 failure, KEEPS the last-good Content and flips isStale (IN-MEMORY only). A
 * TERMINAL 401 -> one-shot [KbEffect.NavigateToLogin] (re-auth handoff).
 */
@HiltViewModel
class KbDetailViewModel @Inject constructor(
    private val repository: KbRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val articleId: String =
        checkNotNull(savedState[KbArticleDetailDest.ARG_ARTICLE_ID]) {
            "missing ${KbArticleDetailDest.ARG_ARTICLE_ID} nav arg"
        }

    private val _uiState = MutableStateFlow<KbDetailUiState>(KbDetailUiState.Loading)
    val uiState: StateFlow<KbDetailUiState> = _uiState.asStateFlow()

    private val _effects = Channel<KbEffect>(Channel.BUFFERED)
    val effects: Flow<KbEffect> = _effects.receiveAsFlow()

    private var loadJob: Job? = null

    init {
        load()
    }

    fun load() {
        if (loadJob?.isActive == true) return
        _uiState.value = KbDetailUiState.Loading
        fetch(isRefresh = false)
    }

    fun onRetry() = load()

    fun refresh() {
        if (loadJob?.isActive == true) return
        (_uiState.value as? KbDetailUiState.Content)?.let {
            _uiState.value = it.copy(isRefreshing = true)
        }
        fetch(isRefresh = true)
    }

    private fun fetch(isRefresh: Boolean) {
        loadJob = viewModelScope.launch {
            when (val result = repository.getArticle(articleId)) {
                is ApiResult.Success -> {
                    val article = result.data
                    _uiState.value = if (article == null) {
                        KbDetailUiState.NotFound
                    } else {
                        KbDetailUiState.Content(article = article, isRefreshing = false, isStale = false)
                    }
                }
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

    private fun emitFailure(isRefresh: Boolean, error: ApiError) {
        val prior = _uiState.value as? KbDetailUiState.Content
        _uiState.value = if (isRefresh && prior != null) {
            prior.copy(isRefreshing = false, isStale = true)
        } else {
            KbDetailUiState.Error(error)
        }
    }

    private fun clearRefreshing() {
        (_uiState.value as? KbDetailUiState.Content)?.let {
            _uiState.value = it.copy(isRefreshing = false)
        }
    }

    private companion object {
        const val HTTP_UNAUTHORIZED = 401
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
