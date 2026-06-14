package com.testlogon.android.feature.discover

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.discover.DiscoverContent
import com.testlogon.android.data.discover.DiscoverRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-182 — discover screen state. */
sealed interface DiscoverUiState {
    data object Loading : DiscoverUiState
    data class Content(
        val content: DiscoverContent,
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false,
    ) : DiscoverUiState
    data object Empty : DiscoverUiState
    data class Error(val message: String) : DiscoverUiState
    data object Offline : DiscoverUiState
}

/** AND-182 — one-shot navigation effects from the discover screen. */
sealed interface DiscoverNavEvent {
    data class OpenProfile(val userId: String) : DiscoverNavEvent
    data class OpenTag(val tag: String) : DiscoverNavEvent
}

/**
 * AND-182 — discover presentation logic. Loads the client-composed sections (suggested / trending
 * creators / trending tags) from [DiscoverRepository] and maps [ApiResult] to a [DiscoverUiState]
 * (Loading / Content / Empty / Error / Offline). On a refresh failure that follows a prior success, the
 * existing content is kept and flagged stale rather than blanked. Navigation is modelled as one-shot
 * effects via a Channel (never re-emitted on config change).
 */
@HiltViewModel
class DiscoverViewModel @Inject constructor(
    private val repository: DiscoverRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<DiscoverUiState>(DiscoverUiState.Loading)
    val uiState: StateFlow<DiscoverUiState> = _uiState.asStateFlow()

    private val _navEvents = Channel<DiscoverNavEvent>(Channel.BUFFERED)
    val navEvents: Flow<DiscoverNavEvent> = _navEvents.receiveAsFlow()

    init {
        load(isRefresh = false)
    }

    fun refresh() = load(isRefresh = true)

    fun retry() = load(isRefresh = false)

    private fun load(isRefresh: Boolean) {
        if (isRefresh) {
            _uiState.update { s -> if (s is DiscoverUiState.Content) s.copy(isRefreshing = true) else s }
        } else if (_uiState.value !is DiscoverUiState.Content) {
            _uiState.value = DiscoverUiState.Loading
        }
        viewModelScope.launch {
            _uiState.value = repository.getDiscover().toUiState()
        }
    }

    private fun ApiResult<DiscoverContent>.toUiState(): DiscoverUiState = when (this) {
        is ApiResult.Success ->
            if (data.isEmpty) DiscoverUiState.Empty
            else DiscoverUiState.Content(content = data, isRefreshing = false, isStale = false)
        is ApiResult.Failure -> failureState()
        is ApiResult.NetworkError -> failureState(offline = true)
    }

    private fun ApiResult.Failure.failureState(): DiscoverUiState = staleOr {
        DiscoverUiState.Error(error.message)
    }

    private fun ApiResult.NetworkError.failureState(offline: Boolean): DiscoverUiState = staleOr {
        if (offline) DiscoverUiState.Offline else DiscoverUiState.Error(OFFLINE_MESSAGE)
    }

    /** If a cached snapshot exists, keep showing it (stale); otherwise produce the terminal state. */
    private inline fun staleOr(terminal: () -> DiscoverUiState): DiscoverUiState {
        val cached = repository.cached()
        return if (cached != null && !cached.isEmpty) {
            DiscoverUiState.Content(content = cached, isRefreshing = false, isStale = true)
        } else {
            terminal()
        }
    }

    fun onCreatorClick(userId: String) {
        viewModelScope.launch { _navEvents.send(DiscoverNavEvent.OpenProfile(userId)) }
    }

    fun onTagClick(tag: String) {
        viewModelScope.launch { _navEvents.send(DiscoverNavEvent.OpenTag(tag)) }
    }

    companion object {
        const val OFFLINE_MESSAGE = "You're offline. Tap to retry."
    }
}
