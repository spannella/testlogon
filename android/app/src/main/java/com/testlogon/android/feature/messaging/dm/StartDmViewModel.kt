package com.testlogon.android.feature.messaging.dm

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.MessagingRepository
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

/** AND-127 — UI state for the "Message" (start-DM) affordance. */
data class StartDmUiState(
    val inFlight: Boolean = false,
    val errorMessage: String? = null,
)

/** AND-127 — one-shot effects for starting a DM (delivered exactly once; never replayed). */
sealed interface StartDmEffect {
    data class OpenThread(val conversationId: String) : StartDmEffect
}

/**
 * AND-127 — DM find-or-create presentation logic.
 *
 * Resolves a peer user id to a conversation id (existing or freshly created) and emits a one-shot
 * navigation effect into the thread route (AND-123). The self-DM guard and the network call live in
 * [MessagingRepository.findOrCreateDm]. Rapid double-taps are debounced via [StartDmUiState.inFlight]
 * so no concurrent requests or duplicate navigation occur (FR-4). The navigation effect uses a
 * Channel + receiveAsFlow so it is consumed once and does not re-fire on recomposition / config
 * change (FR-7).
 */
@HiltViewModel
class StartDmViewModel @Inject constructor(
    private val repository: MessagingRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(StartDmUiState())
    val state: StateFlow<StartDmUiState> = _state.asStateFlow()

    private val _effects = Channel<StartDmEffect>(Channel.BUFFERED)
    val effects: Flow<StartDmEffect> = _effects.receiveAsFlow()

    fun startDm(peerUserId: String) {
        if (_state.value.inFlight) return // FR-4 debounce / single-flight
        _state.update { it.copy(inFlight = true, errorMessage = null) }
        viewModelScope.launch {
            when (val result = repository.findOrCreateDm(peerUserId)) {
                is ApiResult.Success ->
                    _effects.send(StartDmEffect.OpenThread(result.data.id))
                is ApiResult.Failure ->
                    _state.update { it.copy(errorMessage = result.error.message) }
                is ApiResult.NetworkError ->
                    _state.update { it.copy(errorMessage = OFFLINE_MESSAGE) }
            }
            _state.update { it.copy(inFlight = false) }
        }
    }

    fun consumeError() = _state.update { it.copy(errorMessage = null) }

    private companion object {
        const val OFFLINE_MESSAGE = "You're offline. Try again when you're back online."
    }
}
