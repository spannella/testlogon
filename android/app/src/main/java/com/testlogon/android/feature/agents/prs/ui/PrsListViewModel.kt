package com.testlogon.android.feature.agents.prs.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.agents.prs.data.PrsRepository
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
 * AGENTS-BASICS (web-parity) - drives the READ-ONLY agent-PR list (web /agents/prs). A single GET loads the
 * caller's PRs; pull-to-refresh re-reads. A terminal 401 -> [PrsEffect.NavigateToLogin]. No poll loop.
 */
@HiltViewModel
class PrsListViewModel @Inject constructor(
    private val repo: PrsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<PrsListUiState>(PrsListUiState.Loading)
    val uiState: StateFlow<PrsListUiState> = _uiState.asStateFlow()

    private val _effects = Channel<PrsEffect>(Channel.BUFFERED)
    val effects: Flow<PrsEffect> = _effects.receiveAsFlow()

    private var loadJob: Job? = null

    init { load() }

    fun load() {
        if (loadJob?.isActive == true) return
        _uiState.value = PrsListUiState.Loading
        fetch(isRefresh = false)
    }

    fun onRetry() = load()

    fun refresh() {
        if (loadJob?.isActive == true) return
        (_uiState.value as? PrsListUiState.Content)?.let { _uiState.value = it.copy(isRefreshing = true) }
        fetch(isRefresh = true)
    }

    private fun fetch(isRefresh: Boolean) {
        loadJob = viewModelScope.launch {
            when (val result = repo.list()) {
                is ApiResult.Success ->
                    _uiState.value = if (result.data.isEmpty()) PrsListUiState.Empty
                    else PrsListUiState.Content(items = result.data)
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _effects.send(PrsEffect.NavigateToLogin); clearRefreshing()
                    } else emitFailure(isRefresh, result.error.message)
                }
                is ApiResult.NetworkError -> emitFailure(isRefresh, OFFLINE)
            }
        }
    }

    private fun emitFailure(isRefresh: Boolean, message: String) {
        val prior = _uiState.value as? PrsListUiState.Content
        _uiState.value = if (isRefresh && prior != null) prior.copy(isRefreshing = false)
        else PrsListUiState.Error(message)
    }

    private fun clearRefreshing() {
        (_uiState.value as? PrsListUiState.Content)?.let { _uiState.value = it.copy(isRefreshing = false) }
    }

    private companion object {
        const val HTTP_UNAUTHORIZED = 401
        const val OFFLINE = "Couldn't reach the server. Pull down to retry."
    }
}
