package com.testlogon.android.feature.agents.docs.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.agents.docs.data.DocsRepository
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
 * AGENTS-BASICS (web-parity) - drives the DOC-COVERAGE dashboard (web /agents/docs). Loads the summary + the
 * coverage-details list together; pull-to-refresh re-reads; a "Run freshness check" action POSTs then re-reads.
 * A terminal 401 -> [DocsEffect.NavigateToLogin]. No poll loop.
 */
@HiltViewModel
class DocCoverageViewModel @Inject constructor(
    private val repo: DocsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<DocCoverageUiState>(DocCoverageUiState.Loading)
    val uiState: StateFlow<DocCoverageUiState> = _uiState.asStateFlow()

    private val _effects = Channel<DocsEffect>(Channel.BUFFERED)
    val effects: Flow<DocsEffect> = _effects.receiveAsFlow()

    private var loadJob: Job? = null

    init { load() }

    fun load() {
        if (loadJob?.isActive == true) return
        _uiState.value = DocCoverageUiState.Loading
        fetch(isRefresh = false)
    }

    fun onRetry() = load()

    fun refresh() {
        if (loadJob?.isActive == true) return
        (_uiState.value as? DocCoverageUiState.Content)?.let { _uiState.value = it.copy(isRefreshing = true) }
        fetch(isRefresh = true)
    }

    private fun fetch(isRefresh: Boolean) {
        loadJob = viewModelScope.launch {
            val summaryR = repo.coverage()
            val detailsR = repo.coverageDetails()
            if (summaryR is ApiResult.Success && detailsR is ApiResult.Success) {
                _uiState.value = DocCoverageUiState.Content(summary = summaryR.data, docs = detailsR.data)
            } else {
                val terminal = listOf(summaryR, detailsR).any {
                    it is ApiResult.Failure && it.error.status == HTTP_UNAUTHORIZED
                }
                if (terminal) _effects.send(DocsEffect.NavigateToLogin)
                emitFailure(isRefresh, messageOf(summaryR, detailsR))
            }
        }
    }

    fun runFreshnessCheck() {
        val current = _uiState.value as? DocCoverageUiState.Content ?: return
        if (current.checkingFreshness) return
        _uiState.value = current.copy(checkingFreshness = true, actionMessage = null)
        viewModelScope.launch {
            when (val result = repo.freshnessCheck()) {
                is ApiResult.Success -> {
                    val summaryR = repo.coverage()
                    val detailsR = repo.coverageDetails()
                    _uiState.value = if (summaryR is ApiResult.Success && detailsR is ApiResult.Success) {
                        DocCoverageUiState.Content(
                            summary = summaryR.data,
                            docs = detailsR.data,
                            actionMessage = "Checked ${result.data.total} docs (${result.data.stale} stale)",
                        )
                    } else {
                        current.copy(
                            checkingFreshness = false,
                            actionMessage = "Checked ${result.data.total} docs (${result.data.stale} stale)",
                        )
                    }
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(DocsEffect.NavigateToLogin)
                    _uiState.value = current.copy(checkingFreshness = false, actionMessage = result.error.message)
                }
                is ApiResult.NetworkError ->
                    _uiState.value = current.copy(checkingFreshness = false, actionMessage = OFFLINE)
            }
        }
    }

    private fun emitFailure(isRefresh: Boolean, message: String) {
        val prior = _uiState.value as? DocCoverageUiState.Content
        _uiState.value = if (isRefresh && prior != null) prior.copy(isRefreshing = false, actionMessage = message)
        else DocCoverageUiState.Error(message)
    }

    private fun messageOf(vararg results: ApiResult<*>): String {
        results.forEach {
            when (it) {
                is ApiResult.Failure -> return it.error.message
                is ApiResult.NetworkError -> return OFFLINE
                else -> Unit
            }
        }
        return "Something went wrong."
    }

    private companion object {
        const val HTTP_UNAUTHORIZED = 401
        const val OFFLINE = "Couldn't reach the server. Pull down to retry."
    }
}
