package com.testlogon.android.feature.webhooks.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.webhooks.data.WebhooksRepository
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
 * AND-398 - drives the [WebhooksListUiState] for the webhook-endpoints LIST (screen 1).
 *
 * A single GET loads the caller's endpoints (the list is a single small page - FR-6 says no pagination).
 * Pull-to-refresh re-reads but, on a NON-401 failure, KEEPS the last-good list and flips isStale true (FR-5
 * stale banner - the repository's in-memory snapshot already serves the fallback data, so a refresh failure
 * resolves to a Success carrying the cached list, which the VM renders with isStale=true via [refreshFailed]).
 * A TERMINAL 401 -> one-shot [WebhooksEffect.NavigateToLogin] (re-auth handoff). There is NO poll loop.
 */
@HiltViewModel
class WebhooksListViewModel @Inject constructor(
    private val repo: WebhooksRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<WebhooksListUiState>(WebhooksListUiState.Loading)
    val uiState: StateFlow<WebhooksListUiState> = _uiState.asStateFlow()

    private val _effects = Channel<WebhooksEffect>(Channel.BUFFERED)
    val effects: Flow<WebhooksEffect> = _effects.receiveAsFlow()

    /** Collapses concurrent load()/refresh() onto a single in-flight repository read (rapid double pull). */
    private var loadJob: Job? = null

    init {
        load()
    }

    /** First load (no cached content): goes through Loading and may resolve to Content / Empty / Error / login. */
    fun load() {
        if (loadJob?.isActive == true) return
        _uiState.value = WebhooksListUiState.Loading
        fetch(isRefresh = false)
    }

    fun onRetry() = load()

    /** Pull-to-refresh. On a non-401 failure the last-good Content is kept with isStale=true (FR-5). */
    fun refresh() {
        if (loadJob?.isActive == true) return
        val current = _uiState.value
        if (current is WebhooksListUiState.Content) {
            _uiState.value = current.copy(isRefreshing = true)
        }
        fetch(isRefresh = true)
    }

    private fun fetch(isRefresh: Boolean) {
        loadJob = viewModelScope.launch {
            when (val result = repo.list(forceRefresh = true)) {
                is ApiResult.Success -> {
                    val items = result.data
                    _uiState.value = if (items.isEmpty()) {
                        WebhooksListUiState.Empty
                    } else {
                        // A refresh that fell back to the repo's cached snapshot returns Success too; we can't
                        // distinguish fresh-vs-stale here, so a successful refresh always renders fresh content
                        // (the stale path is taken only on an explicit Failure/NetworkError below).
                        WebhooksListUiState.Content(items = items, isStale = false, isRefreshing = false)
                    }
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _effects.send(WebhooksEffect.NavigateToLogin)
                        clearRefreshing()
                    } else {
                        emitFailure(isRefresh, result.error.message, retryable = true)
                    }
                }
                is ApiResult.NetworkError ->
                    emitFailure(isRefresh, OFFLINE_FALLBACK, retryable = true)
            }
        }
    }

    /** A non-401 failure: keep stale content on a refresh that has prior content, else surface Error. */
    private fun emitFailure(isRefresh: Boolean, message: String, retryable: Boolean) {
        val prior = _uiState.value as? WebhooksListUiState.Content
        _uiState.value = if (isRefresh && prior != null) {
            prior.copy(isRefreshing = false, isStale = true)
        } else {
            WebhooksListUiState.Error(message = message, retryable = retryable)
        }
    }

    /** Drops the pull-to-refresh spinner when a 401 takes over (content, if any, stays unchanged). */
    private fun clearRefreshing() {
        val prior = _uiState.value as? WebhooksListUiState.Content
        if (prior != null) _uiState.value = prior.copy(isRefreshing = false)
    }

    private companion object {
        const val HTTP_UNAUTHORIZED = 401
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
