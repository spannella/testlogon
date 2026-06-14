package com.testlogon.android.feature.tickets.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.tickets.data.TicketsRepository
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
 * AND-372 - drives the READ-ONLY [SpacesListUiState] for the ticket-spaces LIST (screen 1).
 *
 * A single GET loads the caller's spaces (the spaces list is not paged this wave). Pull-to-refresh re-reads but,
 * on a NON-401 failure, KEEPS the last-good list and flips isStale true (FR-6 stale banner - IN-MEMORY only, NOT
 * persisted; Room persistence is DEFERRED, no migration this wave). A TERMINAL 401 -> one-shot
 * [TicketsEffect.NavigateToLogin] (re-auth handoff), NOT a generic error. There is NO poll loop and NO mutation
 * (composing / member edits are AND-373).
 */
@HiltViewModel
class SpacesListViewModel @Inject constructor(
    private val repository: TicketsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<SpacesListUiState>(SpacesListUiState.Loading)
    val uiState: StateFlow<SpacesListUiState> = _uiState.asStateFlow()

    private val _effects = Channel<TicketsEffect>(Channel.BUFFERED)
    val effects: Flow<TicketsEffect> = _effects.receiveAsFlow()

    /**
     * AND-375 (FR-7 / AC-3) - the in-flight load guard: concurrent load()/refresh() calls collapse to a SINGLE
     * repository getSpaces() while one is still running, so a rapid double pull-to-refresh fires one read.
     */
    private var loadJob: Job? = null

    init {
        load()
    }

    /** First load (no cached content): goes through Loading and may resolve to Empty / Error / NavigateToLogin. */
    fun load() {
        if (loadJob?.isActive == true) return // AND-375 FR-7: collapse onto the in-flight read.
        _uiState.value = SpacesListUiState.Loading
        fetch(isRefresh = false)
    }

    fun onRetry() = load()

    /** Pull-to-refresh. On a non-401 failure the last-good Content is kept with isStale=true (FR-6). */
    fun refresh() {
        if (loadJob?.isActive == true) return // AND-375 FR-7: a rapid second refresh collapses onto the first.
        val current = _uiState.value
        if (current is SpacesListUiState.Content) {
            _uiState.value = current.copy(isRefreshing = true)
        }
        fetch(isRefresh = true)
    }

    private fun fetch(isRefresh: Boolean) {
        loadJob = viewModelScope.launch {
            when (val result = repository.getSpaces()) {
                is ApiResult.Success -> {
                    val spaces = result.data
                    _uiState.value = if (spaces.isEmpty()) {
                        SpacesListUiState.Empty
                    } else {
                        SpacesListUiState.Content(
                            spaces = spaces,
                            isRefreshing = false,
                            isStale = false,
                        )
                    }
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _effects.send(TicketsEffect.NavigateToLogin)
                        clearRefreshing()
                    } else {
                        emitFailure(isRefresh, result.error)
                    }
                }
                is ApiResult.NetworkError ->
                    emitFailure(
                        isRefresh,
                        ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK),
                    )
            }
        }
    }

    /** A non-401 failure: keep stale content on a refresh that has prior content, else surface Error. */
    private fun emitFailure(isRefresh: Boolean, error: ApiError) {
        val prior = _uiState.value as? SpacesListUiState.Content
        _uiState.value = if (isRefresh && prior != null) {
            prior.copy(isRefreshing = false, isStale = true)
        } else {
            SpacesListUiState.Error(error)
        }
    }

    /** Drops the pull-to-refresh spinner when a 401 takes over (content, if any, stays unchanged). */
    private fun clearRefreshing() {
        val prior = _uiState.value as? SpacesListUiState.Content
        if (prior != null) _uiState.value = prior.copy(isRefreshing = false)
    }

    private companion object {
        const val HTTP_UNAUTHORIZED = 401
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
