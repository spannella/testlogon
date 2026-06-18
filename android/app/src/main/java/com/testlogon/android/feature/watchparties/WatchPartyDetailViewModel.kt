package com.testlogon.android.feature.watchparties

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.watchparties.WatchParty
import com.testlogon.android.data.watchparties.WatchPartiesRepository
import com.testlogon.android.data.watchparties.WatchPartyParticipant
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
 * Drives [WatchPartyDetailUiState] for a single party.
 *
 * Reads its [partyId] from [SavedStateHandle] (the nav arg) and loads the party + participants once on
 * construction. Join / Leave POST against the REST endpoints (in-flight guarded) and reload on success.
 * Realtime playback sync is intentionally NOT implemented - the screen shows the static party state and
 * an honest note. A hard 401 maps to SessionExpired.
 */
@HiltViewModel
class WatchPartyDetailViewModel @Inject constructor(
    private val repository: WatchPartiesRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val partyId: String = checkNotNull(savedStateHandle[ARG_PARTY_ID]) {
        "WatchPartyDetailViewModel requires a '$ARG_PARTY_ID' nav argument"
    }

    private val _uiState = MutableStateFlow(WatchPartyDetailUiState())
    val uiState: StateFlow<WatchPartyDetailUiState> = _uiState.asStateFlow()

    private val _effects = Channel<WatchPartyDetailEffect>(Channel.BUFFERED)
    val effects: Flow<WatchPartyDetailEffect> = _effects.receiveAsFlow()

    init {
        load()
    }

    fun onRetry() = load()

    fun onJoin() {
        if (_uiState.value.isMutating) return
        _uiState.update { it.copy(isMutating = true) }
        viewModelScope.launch {
            when (repository.joinParty(partyId)) {
                is ApiResult.Success -> {
                    _effects.send(WatchPartyDetailEffect.ShowMessage(R.string.watch_parties_join_success))
                    reload()
                }
                else -> {
                    _uiState.update { it.copy(isMutating = false) }
                    _effects.send(WatchPartyDetailEffect.ShowMessage(R.string.watch_parties_join_failed))
                }
            }
        }
    }

    fun onLeave() {
        if (_uiState.value.isMutating) return
        _uiState.update { it.copy(isMutating = true) }
        viewModelScope.launch {
            when (repository.leaveParty(partyId)) {
                is ApiResult.Success -> {
                    _effects.send(WatchPartyDetailEffect.ShowMessage(R.string.watch_parties_leave_success))
                    reload()
                }
                else -> {
                    _uiState.update { it.copy(isMutating = false) }
                    _effects.send(WatchPartyDetailEffect.ShowMessage(R.string.watch_parties_leave_failed))
                }
            }
        }
    }

    /** Refresh after a mutation; clears the mutation guard regardless of outcome. */
    private fun reload() {
        viewModelScope.launch {
            val partyResult = repository.getParty(partyId)
            val participantsResult = repository.loadParticipants(partyId)
            applyLoaded(partyResult, participantsResult, clearMutating = true)
        }
    }

    private fun load() {
        _uiState.update {
            it.copy(
                phase = if (it.party != null) it.phase else WatchPartyDetailUiState.Phase.Loading,
                errorMessage = if (it.party != null) it.errorMessage else null,
            )
        }
        viewModelScope.launch {
            val partyResult = repository.getParty(partyId)
            val participantsResult = repository.loadParticipants(partyId)
            applyLoaded(partyResult, participantsResult, clearMutating = false)
        }
    }

    private suspend fun applyLoaded(
        partyResult: ApiResult<WatchParty>,
        participantsResult: ApiResult<List<WatchPartyParticipant>>,
        clearMutating: Boolean,
    ) {
        when (partyResult) {
            is ApiResult.Success -> {
                val participants = (participantsResult as? ApiResult.Success)?.data ?: emptyList()
                _uiState.update {
                    it.copy(
                        phase = WatchPartyDetailUiState.Phase.Content,
                        party = partyResult.data,
                        participants = participants,
                        isMutating = false,
                        errorMessage = null,
                    )
                }
            }
            is ApiResult.Failure -> {
                if (partyResult.error.status == HTTP_UNAUTHORIZED) {
                    _uiState.update {
                        it.copy(phase = WatchPartyDetailUiState.Phase.SessionExpired, isMutating = false)
                    }
                } else {
                    reduceFailure(partyResult.error.message, offline = false, clearMutating = clearMutating)
                }
            }
            is ApiResult.NetworkError ->
                reduceFailure(OFFLINE_FALLBACK, offline = true, clearMutating = clearMutating)
        }
    }

    private fun reduceFailure(message: String, offline: Boolean, clearMutating: Boolean) {
        val hasContent = _uiState.value.party != null
        if (hasContent && clearMutating) {
            // A mutation succeeded but the refresh failed: keep showing prior content.
            _uiState.update { it.copy(isMutating = false) }
            return
        }
        _uiState.update {
            it.copy(
                phase = if (offline) WatchPartyDetailUiState.Phase.Offline else WatchPartyDetailUiState.Phase.Error,
                isMutating = false,
                errorMessage = message,
            )
        }
    }

    companion object {
        const val ARG_PARTY_ID = "partyId"
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Could not reach the server. Retry."
    }
}
