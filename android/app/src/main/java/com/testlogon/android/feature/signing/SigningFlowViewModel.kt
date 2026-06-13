package com.testlogon.android.feature.signing

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.signing.PacketRole
import com.testlogon.android.core.network.signing.PacketStatus
import com.testlogon.android.feature.signing.capture.model.SignatureAsset
import com.testlogon.android.feature.signing.data.SignatureRepository
import com.testlogon.android.feature.signing.editor.SigningEditorReducer
import com.testlogon.android.feature.signing.editor.SigningEditorState
import com.testlogon.android.feature.signing.model.PacketField
import com.testlogon.android.feature.signing.model.PlacedField
import com.testlogon.android.feature.signing.model.SignaturePacket
import com.testlogon.android.feature.signing.model.SigningEffect
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
 * AND-344 - the cross-cutting ORCHESTRATOR that sequences the e-signature journey
 * (load -> read document -> capture/place -> submit). It does NOT duplicate the per-screen ViewModels
 * (AND-340 PacketDetail, AND-341 DocumentViewer, AND-342 Signing capture, AND-343 SubmitSign); it
 * COMPOSES the journey conceptually by:
 *   - reusing the EXISTING [SignatureRepository] (getPacket - no new endpoint, no poll loop),
 *   - driving the PURE [SigningEditorReducer] / [SigningEditorState] for the capture/placement step, and
 *   - emitting one-shot [SigningEffect]s for navigation (NavigateToDocument / NavigateToSubmit).
 *
 * SINGLE StateFlow INVARIANT (FR-6): the VM exposes EXACTLY ONE [StateFlow] of [SigningFlowUiState] plus
 * a separate one-shot [SigningEffect] Channel (effects are NEVER in the StateFlow, so re-collection
 * never replays a navigation).
 *
 * canSign DERIVATION: a viewer can sign when the packet grants [CAP_CAN_FILL_FIELDS], the viewer's role
 * is [PacketRole.SIGNER], and the packet is NOT terminal (completed / cancelled / expired). See
 * [deriveCanSign].
 *
 * NOTE: the AND-344 spec refers to the error carrier generically as "AppError"; the canonical type in
 * this codebase is core-model [ApiError], reused verbatim here.
 */
@HiltViewModel
class SigningFlowViewModel @Inject constructor(
    private val repository: SignatureRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val packetId: String =
        savedStateHandle.get<String>(ARG_PACKET_ID)?.takeIf { it.isNotBlank() }.orEmpty()

    private val _uiState = MutableStateFlow(
        SigningFlowUiState(
            step = SigningStep.LOADING,
            editor = SigningEditorState.Loading,
            canSign = false,
            error = null,
        ),
    )
    val uiState: StateFlow<SigningFlowUiState> = _uiState.asStateFlow()

    private val _effects = Channel<SigningEffect>(Channel.BUFFERED)
    val effects: Flow<SigningEffect> = _effects.receiveAsFlow()

    /** The loaded packet (the source of the field manifest for the reducer's completeness checks). */
    private var packet: SignaturePacket? = null

    init {
        load()
    }

    /**
     * Loads the packet ONCE (a single idempotent GET; NO poll loop, NO new endpoint). On success the
     * journey enters the DOCUMENT step and emits [SigningEffect.NavigateToDocument]; on failure it lands
     * on a terminal editor [SigningEditorState.Error] and emits [SigningEffect.ShowError].
     */
    fun load() {
        if (packetId.isEmpty()) {
            failLoad(ApiError(ApiError.STATUS_PARSE, MISSING_PACKET))
            return
        }
        _uiState.value = _uiState.value.copy(
            step = SigningStep.LOADING,
            editor = SigningEditorState.Loading,
            error = null,
        )
        viewModelScope.launch {
            when (val result = repository.getPacket(packetId)) {
                is ApiResult.Success -> onPacketLoaded(result.data)
                is ApiResult.Failure -> failLoad(result.error)
                is ApiResult.NetworkError ->
                    failLoad(ApiError(ApiError.STATUS_NETWORK, OFFLINE))
            }
        }
    }

    private suspend fun onPacketLoaded(loaded: SignaturePacket) {
        packet = loaded
        _uiState.value = _uiState.value.copy(
            step = SigningStep.DOCUMENT,
            editor = SigningEditorState.Loading,
            canSign = deriveCanSign(loaded),
            error = null,
        )
        _effects.send(SigningEffect.NavigateToDocument(loaded.packetId))
    }

    private fun failLoad(error: ApiError) {
        _uiState.value = _uiState.value.copy(
            step = SigningStep.ERROR,
            editor = SigningEditorState.Error(error),
            canSign = false,
            error = error,
        )
        viewModelScope.launch { _effects.send(SigningEffect.ShowError(error)) }
    }

    /**
     * Advances from reading the document into the CAPTURE step, seeding the editor state machine via the
     * pure reducer (Loading --loadOk--> Capturing). [savedSignature] is an optional previously-saved
     * asset to offer for adoption. A no-op unless a packet is loaded.
     */
    fun beginEditing(savedSignature: SignatureAsset? = null) {
        if (packet == null) return
        val nextEditor = SigningEditorReducer.loadOk(SigningEditorState.Loading, savedSignature)
        _uiState.value = _uiState.value.copy(step = SigningStep.CAPTURE, editor = nextEditor)
    }

    /**
     * Drives Capturing --onSignatureCaptured--> Placing via the pure reducer. [placed] / required are
     * sourced from the loaded packet manifest. Moves the step to PLACEMENT on success.
     */
    fun onSignatureCaptured(
        signature: SignatureAsset,
        placed: List<PlacedField> = emptyList(),
    ) {
        val next = SigningEditorReducer.onSignatureCaptured(
            state = _uiState.value.editor,
            signature = signature,
            placed = placed,
            required = manifest(),
        )
        if (next is SigningEditorState.Placing) {
            _uiState.value = _uiState.value.copy(step = SigningStep.PLACEMENT, editor = next)
        }
    }

    /** Placing --onFieldPlaced--> Placing (recompute completeness) via the pure reducer. */
    fun onFieldPlaced(field: PlacedField) {
        _uiState.value = _uiState.value.copy(
            editor = SigningEditorReducer.onFieldPlaced(_uiState.value.editor, field, manifest()),
        )
    }

    /** Placing --onFieldRemoved--> Placing (recompute completeness) via the pure reducer. */
    fun onFieldRemoved(fieldId: String) {
        _uiState.value = _uiState.value.copy(
            editor = SigningEditorReducer.onFieldRemoved(_uiState.value.editor, fieldId, manifest()),
        )
    }

    /**
     * Placing --onContinue--> ReadyToSubmit (gated on isComplete) via the pure reducer. On a successful
     * transition the step moves to SUBMIT and [SigningEffect.NavigateToSubmit] is emitted. A
     * not-yet-complete editor is a no-op (no step change, no effect).
     */
    fun onContinue() {
        val before = _uiState.value.editor
        val after = SigningEditorReducer.onContinue(before)
        if (after is SigningEditorState.ReadyToSubmit && before !is SigningEditorState.ReadyToSubmit) {
            _uiState.value = _uiState.value.copy(step = SigningStep.SUBMIT, editor = after)
            viewModelScope.launch { _effects.send(SigningEffect.NavigateToSubmit) }
        }
    }

    /** ReadyToSubmit --onBack--> Placing via the pure reducer; returns the step to PLACEMENT. */
    fun onBackToPlacement() {
        val next = SigningEditorReducer.onBack(_uiState.value.editor, manifest())
        if (next is SigningEditorState.Placing) {
            _uiState.value = _uiState.value.copy(step = SigningStep.PLACEMENT, editor = next)
        }
    }

    /** Closes the flow (e.g. the packet is terminal / the user backed out). Emits [SigningEffect.Dismiss]. */
    fun dismiss() {
        viewModelScope.launch { _effects.send(SigningEffect.Dismiss) }
    }

    /** The viewer's required+assigned manifest fields drive the reducer's completeness checks. */
    private fun manifest(): List<PacketField> = packet?.fields.orEmpty()

    companion object {
        const val ARG_PACKET_ID = "packetId"

        /** Capability key (AND-344) that grants the viewer the ability to fill fields. */
        const val CAP_CAN_FILL_FIELDS = "can_fill_fields"

        private const val OFFLINE = "Couldn't reach the server. Try again."
        private const val MISSING_PACKET = "Packet not found."

        /**
         * PURE derivation of canSign: the packet grants [CAP_CAN_FILL_FIELDS], the viewer is a
         * [PacketRole.SIGNER], and the packet is NOT terminal (completed / cancelled / expired).
         */
        fun deriveCanSign(packet: SignaturePacket): Boolean {
            val canFill = packet.capabilities[CAP_CAN_FILL_FIELDS] == true
            val isSigner = packet.role == PacketRole.SIGNER
            return canFill && isSigner && !isTerminal(packet.status)
        }

        /** A packet status is terminal when it is completed, cancelled or expired. */
        private fun isTerminal(status: PacketStatus): Boolean =
            status == PacketStatus.COMPLETED ||
                status == PacketStatus.CANCELLED ||
                status == PacketStatus.EXPIRED
    }
}

/** The coarse step the orchestrated journey is on (drives top-level UI + nav). */
enum class SigningStep {
    LOADING,
    DOCUMENT,
    CAPTURE,
    PLACEMENT,
    SUBMIT,
    ERROR,
}

/**
 * The SINGLE UI state the orchestrator exposes. Wraps the current [step], the editor state machine
 * [editor], the derived [canSign] affordance and any terminal [error] (reused core-model [ApiError]).
 * One-shot navigation lives off this state, in the [SigningFlowViewModel.effects] channel.
 */
data class SigningFlowUiState(
    val step: SigningStep,
    val editor: SigningEditorState,
    val canSign: Boolean,
    val error: ApiError?,
)
