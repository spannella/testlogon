package com.testlogon.android.feature.signing.submit

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.signing.capture.model.SignedPacketDraft
import com.testlogon.android.feature.signing.capture.model.toSignatureField
import com.testlogon.android.feature.signing.data.SignatureRepository
import com.testlogon.android.feature.signing.document.data.PdfSource
import com.testlogon.android.feature.signing.model.SignaturePacket
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-343 - presentation logic for the TERMINAL e-sign step.
 *
 * FLOW: [load] reads the packet (legal notice + remaining-required check). [acknowledge] posts the
 * inline legal-notice acknowledgement (EMPTY body) then RELOADS the packet (the button hides once
 * accepted). [markDone] FLUSHES the AND-342 draft's placements via the per-field fill endpoint, then
 * posts mark-done (EMPTY body) and surfaces the [SubmitUiState.Confirmed] terminal state.
 * [downloadCompletedPdf] streams the final-pdf to cache and emits an open-file event.
 *
 * DRAFT-HANDOFF: a [SignedPacketDraft] is not a nav arg, so it is picked up from the process-scoped
 * [SignedDraftHandoff] keyed by the SavedStateHandle packet id (see that class for the rationale). The
 * draft may be null (e.g. process death mid-flow); mark-done then flushes nothing and is a pure
 * terminal acknowledgement.
 *
 * SAFETY: mark-done is NON-idempotent with NO auto-retry; duplicate taps are blocked by the
 * [SubmitUiState.Ready.submitting] flag. NO poll loop. Plain [MutableStateFlow]; one-shot events via a
 * [Channel].
 */
@HiltViewModel
class SubmitSignViewModel @Inject constructor(
    private val repository: SignatureRepository,
    private val pdfSource: PdfSource,
    private val draftHandoff: SignedDraftHandoff,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val packetId: String =
        savedStateHandle.get<String>(ARG_PACKET_ID)?.takeIf { it.isNotBlank() }.orEmpty()

    private val _uiState = MutableStateFlow<SubmitUiState>(SubmitUiState.Loading)
    val uiState: StateFlow<SubmitUiState> = _uiState.asStateFlow()

    private val _events = Channel<SubmitSignEvent>(Channel.BUFFERED)
    val events: Flow<SubmitSignEvent> = _events.receiveAsFlow()

    /** The validated draft handed from AND-342 (null when none was deposited / after process death). */
    private var draft: SignedPacketDraft? = null

    /** Guards against duplicate mark-done taps (also reflected in Ready.submitting for the UI). */
    private var submitting = false

    init {
        draft = draftHandoff.peek(packetId)
        load()
    }

    /**
     * Lets a host (or a test) inject the draft explicitly when not using the handoff (e.g. a direct
     * navigation). Additive to the SavedStateHandle pickup; the more recent call wins.
     */
    fun setDraft(value: SignedPacketDraft?) {
        draft = value
    }

    /** Loads the packet detail and projects the legal notice + remaining-required gate. */
    fun load() {
        if (packetId.isEmpty()) {
            _uiState.value = SubmitUiState.Error(MISSING_PACKET, retryable = false)
            return
        }
        _uiState.value = SubmitUiState.Loading
        viewModelScope.launch {
            when (val result = repository.getPacket(packetId)) {
                is ApiResult.Success -> emitReady(result.data)
                is ApiResult.Failure ->
                    _uiState.value = SubmitUiState.Error(result.error.message, retryable = true)
                is ApiResult.NetworkError ->
                    _uiState.value = SubmitUiState.Error(OFFLINE, retryable = true)
            }
        }
    }

    /** Re-runs [load] after a terminal error. */
    fun retry() = load()

    /** Acknowledges the inline legal notice (EMPTY body) then reloads so the button hides once accepted. */
    fun acknowledge() {
        if (submitting) return
        viewModelScope.launch {
            when (val result = repository.acknowledgeLegalNotice(packetId)) {
                is ApiResult.Success -> load() // RELOAD to observe the updated accepted flag.
                is ApiResult.Failure ->
                    _uiState.value = SubmitUiState.Error(result.error.message, retryable = true)
                is ApiResult.NetworkError ->
                    _uiState.value = SubmitUiState.Error(OFFLINE, retryable = true)
            }
        }
    }

    /**
     * The terminal action: flush every placement via the per-field fill endpoint, then mark-done. Blocks
     * duplicate taps; NO auto-retry (a failure surfaces an Error the user can retry deliberately).
     */
    fun markDone() {
        if (submitting) return
        val current = _uiState.value
        if (current is SubmitUiState.Ready && !current.canMarkDone) return
        submitting = true
        if (current is SubmitUiState.Ready) {
            _uiState.value = current.copy(submitting = true)
        }
        viewModelScope.launch {
            // 1) Flush the AND-342 deferred fills (NO bulk submit), if a draft is present.
            val currentDraft = draft
            if (currentDraft != null && currentDraft.placements.isNotEmpty()) {
                when (val flush = repository.flushDraft(currentDraft)) {
                    is ApiResult.Success -> Unit
                    is ApiResult.Failure -> return@launch failTerminal(flush.error.message)
                    is ApiResult.NetworkError -> return@launch failTerminal(OFFLINE)
                }
            }
            // 2) Terminal mark-done (EMPTY body); the repo reloads for completed_at / signer_status.
            when (val done = repository.markDone(packetId)) {
                is ApiResult.Success -> {
                    submitting = false
                    draftHandoff.take(packetId) // consume the one-shot draft.
                    val result = done.data
                    _uiState.value = SubmitUiState.Confirmed(
                        status = result.packetStatus,
                        completedAt = result.completedAt,
                        canDownloadPdf = result.isCompleted,
                    )
                }
                is ApiResult.Failure -> failTerminal(done.error.message)
                is ApiResult.NetworkError -> failTerminal(OFFLINE)
            }
        }
    }

    /** Streams the completed PDF to cache (final-pdf, valid only when completed) and emits an open event. */
    fun downloadCompletedPdf() {
        val confirmed = _uiState.value as? SubmitUiState.Confirmed ?: return
        if (!confirmed.canDownloadPdf) return
        viewModelScope.launch {
            when (val result = pdfSource.downloadPdf(packetId)) {
                is ApiResult.Success ->
                    _events.send(SubmitSignEvent.OpenCompletedPdf(packetId, result.data))
                is ApiResult.Failure -> Unit // a download failure leaves the confirmation intact.
                is ApiResult.NetworkError -> Unit
            }
        }
    }

    private fun failTerminal(message: String) {
        submitting = false
        _uiState.value = SubmitUiState.Error(message, retryable = true)
    }

    private fun emitReady(packet: SignaturePacket) {
        _uiState.value = SubmitUiState.Ready(
            legalNotice = packet.legalNotice,
            canMarkDone = computeCanMarkDone(packet),
            submitting = false,
        )
    }

    /**
     * PURE gate: every required field satisfied (from the draft, against the viewer's assigned fields)
     * AND the legal gate cleared (no notice, or not required, or already accepted). With no draft the
     * field check passes (the placements were made on a prior session / the packet has no viewer fields).
     */
    private fun computeCanMarkDone(packet: SignaturePacket): Boolean {
        val legalCleared = packet.legalNotice.let { it == null || !it.required || it.accepted }
        if (!legalCleared) return false
        val currentDraft = draft ?: return true
        val viewerFields = packet.fields
            .filter { it.isAssignedToViewer == true }
            .map { it.toSignatureField() }
        return currentDraft.isComplete(viewerFields)
    }

    companion object {
        const val ARG_PACKET_ID = "packetId"

        private const val OFFLINE = "Couldn't reach the server. Try again."
        private const val MISSING_PACKET = "Packet not found."
    }
}
