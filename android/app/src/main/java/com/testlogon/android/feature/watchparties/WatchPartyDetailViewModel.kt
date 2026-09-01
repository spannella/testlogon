package com.testlogon.android.feature.watchparties

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.watchparties.WatchParty
import com.testlogon.android.data.watchparties.WatchPartiesRepository
import com.testlogon.android.data.watchparties.WatchPartyMath
import com.testlogon.android.data.watchparties.WatchPartyParticipant
import com.testlogon.android.data.messaging.realtime.MessagingEvent
import com.testlogon.android.data.messaging.realtime.MessagingEventStream
import com.testlogon.android.data.messaging.realtime.MessagingStreamEvent
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
 * Participants RECEIVE host-authoritative playback over the realtime stream ([observePlaybackSync]);
 * the HOST (or an active co-host) additionally DRIVES it via [onPlay]/[onPause]/[onSeek] plus the
 * host-only [onGrantCoHost]/[onKick]/[onEnd]. All host-control mutations are permission-gated through
 * [WatchPartyMath] and guarded by [WatchPartyDetailUiState.isControlling]. A hard 401 maps to
 * SessionExpired.
 */
@HiltViewModel
class WatchPartyDetailViewModel @Inject constructor(
    private val repository: WatchPartiesRepository,
    private val eventStream: MessagingEventStream,
    private val authStateStore: AuthStateStore,
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
        _uiState.update { it.copy(currentUserSub = authStateStore.userSub.value) }
        load()
        observePlaybackSync()
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

    // ---- Host controls ----

    fun onPlay() = control("play", positionSeconds = null)

    fun onPause() = control("pause", positionSeconds = currentSyncPosition())

    fun onSeek(positionSeconds: Double) = control("seek", positionSeconds = positionSeconds.coerceAtLeast(0.0))

    /**
     * POST a playback control. Permission-gated (host / active co-host) via [WatchPartyMath] so a
     * member can never issue a control. On success we reflect the host-authoritative state locally
     * (optimistic) so the driver sees immediate feedback even before the SSE echo lands.
     */
    private fun control(action: String, positionSeconds: Double?) {
        val state = _uiState.value
        val party = state.party ?: return
        if (state.isControlling) return
        if (!WatchPartyMath.canControlPlayback(party, state.participants, state.currentUserSub)) {
            viewModelScope.launch {
                _effects.send(WatchPartyDetailEffect.ShowMessage(R.string.watch_parties_control_forbidden))
            }
            return
        }
        val normalized = WatchPartyMath.normalizeAction(action) ?: return
        _uiState.update { it.copy(isControlling = true) }
        viewModelScope.launch {
            when (val result = repository.controlPlayback(partyId, normalized, positionSeconds)) {
                is ApiResult.Success -> {
                    val updated = result.data
                    _uiState.update {
                        it.copy(
                            isControlling = false,
                            party = updated,
                            playbackSync = WatchPartyDetailUiState.PlaybackSyncState(
                                isPlaying = updated.status == com.testlogon.android.data.watchparties.WatchPartyStatus.PLAYING,
                                positionSeconds = updated.positionSeconds.toDouble(),
                                positionUpdatedAtEpochSeconds = updated.positionUpdatedAtSeconds,
                                controlledBy = it.currentUserSub.orEmpty(),
                                lastAction = normalized,
                                serverTimeEpochSeconds = updated.positionUpdatedAtSeconds,
                            ),
                        )
                    }
                }
                is ApiResult.Failure ->
                    failControl(if (result.error.status == HTTP_UNAUTHORIZED) HTTP_UNAUTHORIZED else 0)
                is ApiResult.NetworkError -> failControl(0)
            }
        }
    }

    fun onGrantCoHost(targetUserSub: String) {
        val state = _uiState.value
        val party = state.party ?: return
        if (state.isControlling || !WatchPartyMath.canManageParty(party, state.currentUserSub)) return
        _uiState.update { it.copy(isControlling = true) }
        viewModelScope.launch {
            when (repository.grantCoHost(partyId, targetUserSub)) {
                is ApiResult.Success -> {
                    _effects.send(WatchPartyDetailEffect.ShowMessage(R.string.watch_parties_cohost_success))
                    reload()
                }
                else -> {
                    _uiState.update { it.copy(isControlling = false) }
                    _effects.send(WatchPartyDetailEffect.ShowMessage(R.string.watch_parties_cohost_failed))
                }
            }
        }
    }

    fun onKick(targetUserSub: String) {
        val state = _uiState.value
        val party = state.party ?: return
        if (state.isControlling || !WatchPartyMath.canManageParty(party, state.currentUserSub)) return
        _uiState.update { it.copy(isControlling = true) }
        viewModelScope.launch {
            when (repository.kickParticipant(partyId, targetUserSub)) {
                is ApiResult.Success -> {
                    _effects.send(WatchPartyDetailEffect.ShowMessage(R.string.watch_parties_kick_success))
                    reload()
                }
                else -> {
                    _uiState.update { it.copy(isControlling = false) }
                    _effects.send(WatchPartyDetailEffect.ShowMessage(R.string.watch_parties_kick_failed))
                }
            }
        }
    }

    fun onEnd() {
        val state = _uiState.value
        val party = state.party ?: return
        if (state.isControlling || !WatchPartyMath.canManageParty(party, state.currentUserSub)) return
        _uiState.update { it.copy(isControlling = true) }
        viewModelScope.launch {
            when (val result = repository.endParty(partyId)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(isControlling = false, party = result.data) }
                    _effects.send(WatchPartyDetailEffect.ShowMessage(R.string.watch_parties_end_success))
                    reload()
                }
                else -> {
                    _uiState.update { it.copy(isControlling = false) }
                    _effects.send(WatchPartyDetailEffect.ShowMessage(R.string.watch_parties_end_failed))
                }
            }
        }
    }

    private suspend fun failControl(status: Int) {
        if (status == HTTP_UNAUTHORIZED) {
            _uiState.update { it.copy(phase = WatchPartyDetailUiState.Phase.SessionExpired, isControlling = false) }
            return
        }
        _uiState.update { it.copy(isControlling = false) }
        _effects.send(WatchPartyDetailEffect.ShowMessage(R.string.watch_parties_control_failed))
    }

    /** Best-known current position (live sync if present, else the party's last stored position). */
    private fun currentSyncPosition(): Double {
        val s = _uiState.value
        val sync = s.playbackSync
        val now = System.currentTimeMillis() / 1000L
        return sync?.targetPositionSeconds(now) ?: (s.party?.positionSeconds?.toDouble() ?: 0.0)
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
                        isControlling = false,
                        errorMessage = null,
                    )
                }
            }
            is ApiResult.Failure -> {
                if (partyResult.error.status == HTTP_UNAUTHORIZED) {
                    _uiState.update {
                        it.copy(
                            phase = WatchPartyDetailUiState.Phase.SessionExpired,
                            isMutating = false,
                            isControlling = false,
                        )
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
            _uiState.update { it.copy(isMutating = false, isControlling = false) }
            return
        }
        _uiState.update {
            it.copy(
                phase = if (offline) WatchPartyDetailUiState.Phase.Offline else WatchPartyDetailUiState.Phase.Error,
                isMutating = false,
                isControlling = false,
                errorMessage = message,
            )
        }
    }

    /**
     * Subscribe to the SHARED realtime event stream and reconcile host-authoritative playback for
     * THIS party. Collecting is lifecycle-bound to [viewModelScope]; the shared upstream (one SSE +
     * one events/poll worker) is torn down shortly after the last collector goes away. Only
     * PlaybackSync frames for [partyId] are applied - all other events (messages/calls/presence) are
     * ignored here. The reconciliation math (extrapolation + drift tolerance) lives in
     * [WatchPartyDetailUiState.PlaybackSyncState] so it stays JVM-unit-testable.
     */
    private fun observePlaybackSync() {
        viewModelScope.launch {
            eventStream.events().collect { emission ->
                if (emission !is MessagingStreamEvent.Event) return@collect
                val ev = emission.event
                if (ev !is MessagingEvent.PlaybackSync || ev.partyId != partyId) return@collect
                _uiState.update {
                    it.copy(
                        playbackSync = WatchPartyDetailUiState.PlaybackSyncState(
                            isPlaying = ev.status == "playing",
                            positionSeconds = ev.positionSeconds,
                            positionUpdatedAtEpochSeconds = ev.positionUpdatedAtEpochSeconds,
                            controlledBy = ev.controlledBy,
                            lastAction = ev.action,
                            serverTimeEpochSeconds = ev.serverTimeEpochSeconds,
                        ),
                    )
                }
            }
        }
    }

    companion object {
        const val ARG_PARTY_ID = "partyId"
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Could not reach the server. Retry."
    }
}
