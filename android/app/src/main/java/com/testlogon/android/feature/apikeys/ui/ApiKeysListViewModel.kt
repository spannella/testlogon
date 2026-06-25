package com.testlogon.android.feature.apikeys.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.apikeys.data.ApiKeysRepository
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
 * B-APIKEY (batch 7) - drives the [ApiKeysListUiState] for the API-keys LIST.
 *
 * A single GET loads the caller's keys (the list is a single small page - no pagination). Pull-to-refresh
 * re-reads but, on a non-401 failure, KEEPS the last-good list and flips isStale (the repository's in-memory
 * snapshot serves the fallback data). A TERMINAL 401 -> one-shot [ApiKeysEffect.NavigateToLogin]. There is NO
 * poll loop. [revoke] removes a key (with a per-row in-flight flag) and the repository updates its snapshot.
 * [showNewSecret] surfaces the one-time secret returned by a create round-trip (held in Content state).
 */
@HiltViewModel
class ApiKeysListViewModel @Inject constructor(
    private val repo: ApiKeysRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<ApiKeysListUiState>(ApiKeysListUiState.Loading)
    val uiState: StateFlow<ApiKeysListUiState> = _uiState.asStateFlow()

    private val _effects = Channel<ApiKeysEffect>(Channel.BUFFERED)
    val effects: Flow<ApiKeysEffect> = _effects.receiveAsFlow()

    private var loadJob: Job? = null

    init {
        load()
    }

    fun load() {
        if (loadJob?.isActive == true) return
        _uiState.value = ApiKeysListUiState.Loading
        fetch(isRefresh = false)
    }

    fun onRetry() = load()

    fun refresh() {
        if (loadJob?.isActive == true) return
        val current = _uiState.value
        if (current is ApiKeysListUiState.Content) {
            _uiState.value = current.copy(isRefreshing = true)
        }
        fetch(isRefresh = true)
    }

    private fun fetch(isRefresh: Boolean) {
        loadJob = viewModelScope.launch {
            when (val result = repo.list()) {
                is ApiResult.Success -> {
                    val items = result.data
                    val priorSecret = (_uiState.value as? ApiKeysListUiState.Content)?.newSecret
                    _uiState.value = if (items.isEmpty() && priorSecret == null) {
                        ApiKeysListUiState.Empty
                    } else {
                        ApiKeysListUiState.Content(
                            items = items,
                            isStale = false,
                            isRefreshing = false,
                            newSecret = priorSecret,
                        )
                    }
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _effects.send(ApiKeysEffect.NavigateToLogin)
                        clearRefreshing()
                    } else {
                        emitFailure(isRefresh, result.error.message)
                    }
                }
                is ApiResult.NetworkError -> emitFailure(isRefresh, OFFLINE_FALLBACK)
            }
        }
    }

    /** Surfaces the one-time secret from a create round-trip; forces a refresh so the new key row appears. */
    fun showNewSecret(secret: String) {
        val current = _uiState.value
        if (current is ApiKeysListUiState.Content) {
            _uiState.value = current.copy(newSecret = secret)
        } else {
            // Not yet on a Content state (e.g. Empty after a first load); stash it and let the refresh fold it in.
            _uiState.value = ApiKeysListUiState.Content(items = emptyList(), newSecret = secret)
        }
        refresh()
    }

    fun dismissNewSecret() {
        val current = _uiState.value as? ApiKeysListUiState.Content ?: return
        _uiState.value = if (current.items.isEmpty()) {
            ApiKeysListUiState.Empty
        } else {
            current.copy(newSecret = null)
        }
    }

    fun revoke(keyId: String) {
        val current = _uiState.value as? ApiKeysListUiState.Content ?: return
        if (current.revokingId != null) return
        _uiState.value = current.copy(revokingId = keyId, actionError = null)
        viewModelScope.launch {
            when (val result = repo.revoke(keyId)) {
                is ApiResult.Success -> {
                    val now = _uiState.value as? ApiKeysListUiState.Content ?: return@launch
                    val remaining = now.items.filterNot { it.id == keyId }
                    _uiState.value = if (remaining.isEmpty() && now.newSecret == null) {
                        ApiKeysListUiState.Empty
                    } else {
                        now.copy(items = remaining, revokingId = null)
                    }
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _effects.send(ApiKeysEffect.NavigateToLogin)
                    }
                    clearRevoking(result.error.message)
                }
                is ApiResult.NetworkError -> clearRevoking(OFFLINE_FALLBACK)
            }
        }
    }

    private fun clearRevoking(message: String) {
        val current = _uiState.value as? ApiKeysListUiState.Content ?: return
        _uiState.value = current.copy(revokingId = null, actionError = message)
    }

    private fun emitFailure(isRefresh: Boolean, message: String) {
        val prior = _uiState.value as? ApiKeysListUiState.Content
        _uiState.value = if (isRefresh && prior != null) {
            prior.copy(isRefreshing = false, isStale = true)
        } else {
            ApiKeysListUiState.Error(message = message, retryable = true)
        }
    }

    private fun clearRefreshing() {
        val prior = _uiState.value as? ApiKeysListUiState.Content
        if (prior != null) _uiState.value = prior.copy(isRefreshing = false)
    }

    private companion object {
        const val HTTP_UNAUTHORIZED = 401
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
