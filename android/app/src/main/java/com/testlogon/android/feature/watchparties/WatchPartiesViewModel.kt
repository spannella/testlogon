package com.testlogon.android.feature.watchparties

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.watchparties.WatchPartiesRepository
import com.testlogon.android.data.watchparties.WatchParty
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

/**
 * Drives [WatchPartiesListUiState] from [WatchPartiesRepository].
 *
 * Loads the list on first composition / pull-to-refresh. The create action POSTs a new party (behind
 * an in-flight guard) and, on success, emits [WatchPartiesListEffect.OpenParty] so the caller can
 * navigate into the new party's detail. A hard 401 (after the network layer refresh+retry) maps to
 * SessionExpired; a failed refresh with a cached list shows a stale banner, else Error/Offline.
 */
@HiltViewModel
class WatchPartiesViewModel @Inject constructor(
    private val repository: WatchPartiesRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(WatchPartiesListUiState())
    val uiState: StateFlow<WatchPartiesListUiState> = _uiState.asStateFlow()

    private val _effects = Channel<WatchPartiesListEffect>(Channel.BUFFERED)
    val effects: Flow<WatchPartiesListEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)

    fun onRetry() = load(fromUser = true)

    /** Creates a party around [videoId]; navigates into it on success. */
    fun onCreateParty(videoId: String, title: String, maxParticipants: Int?) {
        if (_uiState.value.create.isSubmitting) return
        val trimmedVideo = videoId.trim()
        if (trimmedVideo.isEmpty()) {
            viewModelScope.launch {
                _effects.send(WatchPartiesListEffect.ShowMessage(R.string.watch_parties_create_video_required))
            }
            return
        }
        _uiState.update { it.copy(create = it.create.copy(isSubmitting = true)) }
        viewModelScope.launch {
            when (val result = repository.createParty(trimmedVideo, title, maxParticipants)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(create = it.create.copy(isSubmitting = false)) }
                    _effects.send(WatchPartiesListEffect.OpenParty(result.data.id))
                }
                else -> {
                    _uiState.update { it.copy(create = it.create.copy(isSubmitting = false)) }
                    _effects.send(WatchPartiesListEffect.ShowMessage(R.string.watch_parties_create_failed))
                }
            }
        }
    }

    private fun load(fromUser: Boolean) {
        val state = _uiState.value
        if (state.isRefreshing) return
        val hasContent = state.parties.isNotEmpty()
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else WatchPartiesListUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
                errorMessage = if (hasContent) it.errorMessage else null,
            )
        }
        viewModelScope.launch {
            when (val result = repository.loadParties()) {
                is ApiResult.Success -> reduceSuccess(result.data)
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update {
                            it.copy(phase = WatchPartiesListUiState.Phase.SessionExpired, isRefreshing = false)
                        }
                    } else {
                        reduceFailure(result.error.message, offline = false)
                    }
                }
                is ApiResult.NetworkError -> reduceFailure(OFFLINE_FALLBACK, offline = true)
            }
        }
    }

    private fun reduceSuccess(data: List<WatchParty>) {
        _uiState.update {
            it.copy(
                phase = if (data.isEmpty()) WatchPartiesListUiState.Phase.Empty else WatchPartiesListUiState.Phase.Content,
                parties = data,
                isRefreshing = false,
                isStale = false,
                errorMessage = null,
            )
        }
    }

    private suspend fun reduceFailure(message: String, offline: Boolean) {
        val cached = repository.cached()
        if (cached != null) {
            _uiState.update {
                it.copy(
                    phase = if (cached.isEmpty()) WatchPartiesListUiState.Phase.Empty else WatchPartiesListUiState.Phase.Content,
                    parties = cached,
                    isRefreshing = false,
                    isStale = true,
                    errorMessage = null,
                )
            }
            _effects.send(WatchPartiesListEffect.ShowMessage(R.string.watch_parties_refresh_failed_stale))
        } else {
            _uiState.update {
                it.copy(
                    phase = if (offline) WatchPartiesListUiState.Phase.Offline else WatchPartiesListUiState.Phase.Error,
                    parties = emptyList(),
                    isRefreshing = false,
                    isStale = false,
                    errorMessage = message,
                )
            }
        }
    }

    private companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Could not reach the server. Pull down to retry."
    }
}
