package com.testlogon.android.feature.questionnaire.builder.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.questionnaire.builder.data.QuestionnaireBuilderRepository
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
 * Drives the [DraftsListUiState] for the questionnaire-builder DRAFTS list. A single GET loads the
 * caller's drafts; pull-to-refresh re-reads. A TERMINAL 401 -> one-shot [BuilderEffect.NavigateToLogin].
 * No poll loop, no pagination (the list is a single small page like apikeys). Mirrors ApiKeysListViewModel.
 */
@HiltViewModel
class DraftsListViewModel @Inject constructor(
    private val repo: QuestionnaireBuilderRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<DraftsListUiState>(DraftsListUiState.Loading)
    val uiState: StateFlow<DraftsListUiState> = _uiState.asStateFlow()

    private val _effects = Channel<BuilderEffect>(Channel.BUFFERED)
    val effects: Flow<BuilderEffect> = _effects.receiveAsFlow()

    private var loadJob: Job? = null

    init {
        load()
    }

    fun load() {
        if (loadJob?.isActive == true) return
        _uiState.value = DraftsListUiState.Loading
        fetch(isRefresh = false)
    }

    fun onRetry() = load()

    fun refresh() {
        if (loadJob?.isActive == true) return
        val current = _uiState.value
        if (current is DraftsListUiState.Content) {
            _uiState.value = current.copy(isRefreshing = true)
        }
        fetch(isRefresh = true)
    }

    private fun fetch(isRefresh: Boolean) {
        loadJob = viewModelScope.launch {
            when (val result = repo.listDrafts(includeArchived = false)) {
                is ApiResult.Success -> {
                    val items = result.data
                    _uiState.value = if (items.isEmpty()) {
                        DraftsListUiState.Empty
                    } else {
                        DraftsListUiState.Content(items = items, isRefreshing = false)
                    }
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _effects.send(BuilderEffect.NavigateToLogin)
                        clearRefreshing()
                    } else {
                        emitFailure(isRefresh, result.error.message)
                    }
                }
                is ApiResult.NetworkError -> emitFailure(isRefresh, OFFLINE_FALLBACK)
            }
        }
    }

    private fun emitFailure(isRefresh: Boolean, message: String) {
        val prior = _uiState.value as? DraftsListUiState.Content
        _uiState.value = if (isRefresh && prior != null) {
            prior.copy(isRefreshing = false)
        } else {
            DraftsListUiState.Error(message)
        }
    }

    private fun clearRefreshing() {
        val prior = _uiState.value as? DraftsListUiState.Content
        if (prior != null) _uiState.value = prior.copy(isRefreshing = false)
    }

    private companion object {
        const val HTTP_UNAUTHORIZED = 401
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
