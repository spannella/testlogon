package com.testlogon.android.feature.agents.llmkeys.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.agents.llmkeys.data.LlmKeysRepository
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
 * AGENTS-BASICS (web-parity) - drives the LLM KEYS LIST. A single GET loads the caller's provider keys;
 * pull-to-refresh re-reads. Per-row delete (revoke) + test actions set a per-row busy flag. A terminal 401 ->
 * [LlmKeysEffect.NavigateToLogin]. No poll loop.
 */
@HiltViewModel
class LlmKeysListViewModel @Inject constructor(
    private val repo: LlmKeysRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<LlmKeysListUiState>(LlmKeysListUiState.Loading)
    val uiState: StateFlow<LlmKeysListUiState> = _uiState.asStateFlow()

    private val _effects = Channel<LlmKeysEffect>(Channel.BUFFERED)
    val effects: Flow<LlmKeysEffect> = _effects.receiveAsFlow()

    private var loadJob: Job? = null

    init { load() }

    fun load() {
        if (loadJob?.isActive == true) return
        _uiState.value = LlmKeysListUiState.Loading
        fetch(false)
    }

    fun onRetry() = load()

    fun refresh() {
        if (loadJob?.isActive == true) return
        (_uiState.value as? LlmKeysListUiState.Content)?.let {
            _uiState.value = it.copy(isRefreshing = true)
        }
        fetch(true)
    }

    /** Called after a successful add: refreshes so the new key row appears. */
    fun onAdded() = refresh()

    private fun fetch(isRefresh: Boolean) {
        loadJob = viewModelScope.launch {
            when (val result = repo.list()) {
                is ApiResult.Success ->
                    _uiState.value = if (result.data.isEmpty()) {
                        LlmKeysListUiState.Empty
                    } else {
                        LlmKeysListUiState.Content(items = result.data)
                    }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _effects.send(LlmKeysEffect.NavigateToLogin)
                        clearRefreshing()
                    } else {
                        emitFailure(isRefresh, result.error.message)
                    }
                }
                is ApiResult.NetworkError -> emitFailure(isRefresh, OFFLINE)
            }
        }
    }

    fun delete(keyId: String) {
        val current = _uiState.value as? LlmKeysListUiState.Content ?: return
        if (current.busyId != null) return
        _uiState.value = current.copy(busyId = keyId, actionError = null, testResult = null)
        viewModelScope.launch {
            when (val result = repo.delete(keyId)) {
                is ApiResult.Success -> {
                    val now = _uiState.value as? LlmKeysListUiState.Content ?: return@launch
                    val remaining = now.items.filterNot { it.id == keyId }
                    _uiState.value = if (remaining.isEmpty()) {
                        LlmKeysListUiState.Empty
                    } else {
                        now.copy(items = remaining, busyId = null)
                    }
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(LlmKeysEffect.NavigateToLogin)
                    clearBusy(result.error.message)
                }
                is ApiResult.NetworkError -> clearBusy(OFFLINE)
            }
        }
    }

    fun test(keyId: String) {
        val current = _uiState.value as? LlmKeysListUiState.Content ?: return
        if (current.busyId != null) return
        _uiState.value = current.copy(busyId = keyId, actionError = null, testResult = null)
        viewModelScope.launch {
            when (val result = repo.test(keyId)) {
                is ApiResult.Success -> {
                    val r = result.data
                    val msg = if (r.ok) {
                        "Key OK (${r.latencyMs}ms" + (if (r.models.isNotEmpty()) ", ${r.models.size} models)" else ")")
                    } else {
                        "Test failed: ${r.error.ifBlank { "unknown error" }}"
                    }
                    val now = _uiState.value as? LlmKeysListUiState.Content ?: return@launch
                    _uiState.value = now.copy(busyId = null, testResult = msg)
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(LlmKeysEffect.NavigateToLogin)
                    clearBusy(result.error.message)
                }
                is ApiResult.NetworkError -> clearBusy(OFFLINE)
            }
        }
    }

    private fun clearBusy(message: String?) {
        val current = _uiState.value as? LlmKeysListUiState.Content ?: return
        _uiState.value = current.copy(busyId = null, actionError = message)
    }

    private fun emitFailure(isRefresh: Boolean, message: String) {
        val prior = _uiState.value as? LlmKeysListUiState.Content
        _uiState.value = if (isRefresh && prior != null) {
            prior.copy(isRefreshing = false, actionError = message)
        } else {
            LlmKeysListUiState.Error(message)
        }
    }

    private fun clearRefreshing() {
        (_uiState.value as? LlmKeysListUiState.Content)?.let {
            _uiState.value = it.copy(isRefreshing = false)
        }
    }

    private companion object {
        const val HTTP_UNAUTHORIZED = 401
        const val OFFLINE = "Couldn't reach the server. Pull down to retry."
    }
}
