package com.testlogon.android.feature.signing

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.signing.data.SignatureRepository
import com.testlogon.android.feature.signing.model.PacketAction
import com.testlogon.android.feature.signing.model.PacketEvent
import com.testlogon.android.feature.signing.model.SignaturePacket
import com.testlogon.android.feature.signing.model.primaryAction
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
 * AND-340 - presentation logic for the e-signature packet DETAIL screen.
 *
 * READ + ONE WRITE: [load] / [refresh] read the packet + its events ONCE (a single, non-looping pair of
 * idempotent GETs) and the status-driven [onPrimaryAction] performs at most one write (send() for a
 * draft SENDER) or emits a one-shot nav event (Sign for an assigned SIGNER - the deep flow is
 * AND-342/343). There is NO poll loop - refresh is manual (pull-to-refresh / retry). The packetId is
 * sourced from the [SavedStateHandle] nav arg ([ARG_PACKET_ID]).
 *
 * STALE DISPLAY: on a refresh failure while a prior [PacketDetailUiState.Content] is showing, the prior
 * content is kept with isStale=true instead of being replaced by an Error (mirrors AND-329).
 */
@HiltViewModel
class PacketDetailViewModel @Inject constructor(
    private val repository: SignatureRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val packetId: String =
        savedStateHandle.get<String>(ARG_PACKET_ID)?.takeIf { it.isNotBlank() }.orEmpty()

    private val _uiState = MutableStateFlow<PacketDetailUiState>(PacketDetailUiState.Loading)
    val uiState: StateFlow<PacketDetailUiState> = _uiState.asStateFlow()

    private val _events = Channel<PacketDetailEvent>(Channel.BUFFERED)
    val events: Flow<PacketDetailEvent> = _events.receiveAsFlow()

    /** Single in-flight read guard. */
    private var loadJob: Job? = null

    /** Single in-flight write guard (the primary action). */
    private var actionJob: Job? = null

    init {
        load()
    }

    /** Initial read: flashes the spinner, then lands on Content or Error. */
    fun load() = read(showSpinner = true)

    /** Pull-to-refresh: re-reads without flashing the spinner; keeps prior content stale on failure. */
    fun refresh() = read(showSpinner = false)

    /** Re-runs the initial load after a terminal error. */
    fun retry() = load()

    /**
     * Runs the status-driven primary action for the loaded packet:
     *   - DRAFT + SENDER -> send() (then refresh + emit [PacketDetailEvent.PacketSent]),
     *   - SIGNER assigned -> emit [PacketDetailEvent.NavigateToSign] (deep flow deferred to AND-342/343),
     *   - otherwise       -> no-op.
     * A double-tap while a send is in flight is ignored (single-flight guard).
     */
    fun onPrimaryAction() {
        val content = _uiState.value as? PacketDetailUiState.Content ?: return
        when (primaryAction(content.packet)) {
            PacketAction.SEND -> sendDraft(content)
            PacketAction.SIGN -> viewModelScope.launch {
                _events.send(PacketDetailEvent.NavigateToSign(content.packet.packetId))
            }
            PacketAction.NONE -> Unit
        }
    }

    private fun sendDraft(content: PacketDetailUiState.Content) {
        if (content.actionInFlight) return
        _uiState.value = content.copy(actionInFlight = true)

        actionJob?.cancel()
        actionJob = viewModelScope.launch {
            when (val result = repository.send(content.packet.packetId)) {
                is ApiResult.Success -> {
                    _events.send(PacketDetailEvent.PacketSent)
                    // Re-read so the status chip / action reflect the now-sent packet.
                    read(showSpinner = false)
                }
                is ApiResult.Failure -> {
                    clearActionInFlight()
                    _events.send(PacketDetailEvent.ActionFailed(result.error.message))
                }
                is ApiResult.NetworkError -> {
                    clearActionInFlight()
                    _events.send(PacketDetailEvent.ActionFailed(OFFLINE))
                }
            }
        }
    }

    private fun clearActionInFlight() {
        (_uiState.value as? PacketDetailUiState.Content)?.let {
            _uiState.value = it.copy(actionInFlight = false)
        }
    }

    private fun read(showSpinner: Boolean) {
        if (packetId.isEmpty()) {
            _uiState.value = PacketDetailUiState.Error(MISSING_PACKET, retryable = false)
            return
        }

        val prior = _uiState.value as? PacketDetailUiState.Content
        if (showSpinner) {
            _uiState.value = PacketDetailUiState.Loading
        } else if (prior != null) {
            _uiState.value = prior.copy(refreshing = true)
        }

        loadJob?.cancel()
        loadJob = viewModelScope.launch {
            // Single, non-looping pair of idempotent GETs. Events are best-effort: an events failure does
            // NOT fail the screen (the packet still renders with an empty timeline).
            when (val packetResult = repository.getPacket(packetId)) {
                is ApiResult.Success -> {
                    val events = (repository.getEvents(packetId) as? ApiResult.Success)?.data ?: emptyList()
                    emitContent(packetResult.data, events)
                }
                is ApiResult.Failure -> emitFailure(prior, packetResult.error.message, retryable = true)
                is ApiResult.NetworkError -> emitFailure(prior, OFFLINE, retryable = true)
            }
        }
    }

    private fun emitContent(packet: SignaturePacket, events: List<PacketEvent>) {
        _uiState.value = PacketDetailUiState.Content(
            packet = packet,
            events = events,
            isStale = false,
            refreshing = false,
            actionInFlight = false,
        )
    }

    /** On a refresh failure with prior content, KEEP it stale; otherwise surface a terminal Error. */
    private fun emitFailure(prior: PacketDetailUiState.Content?, message: String, retryable: Boolean) {
        _uiState.value = prior?.copy(isStale = true, refreshing = false, actionInFlight = false)
            ?: PacketDetailUiState.Error(message, retryable)
    }

    companion object {
        const val ARG_PACKET_ID = "packetId"

        private const val OFFLINE = "Couldn't reach the server. Try again."
        private const val MISSING_PACKET = "Packet not found."
    }
}
