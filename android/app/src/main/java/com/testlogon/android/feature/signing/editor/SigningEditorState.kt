package com.testlogon.android.feature.signing.editor

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.feature.signing.capture.model.SignatureAsset
import com.testlogon.android.feature.signing.model.PacketField
import com.testlogon.android.feature.signing.model.PlacedField
import com.testlogon.android.feature.signing.model.isComplete

/**
 * AND-344 - the EXPLICIT, finite signing EDITOR state machine the spec's section 4 centers on.
 *
 * The journey through capture + placement is modelled as a small set of states with explicit edges, so
 * the orchestrator (SigningFlowViewModel) never reasons about loose booleans and AND-345 can assert
 * EVERY transition. The whole machine is Android-free and PURE: states are immutable data, transitions
 * are pure functions on [SigningEditorReducer], and ILLEGAL transitions are NO-OPS (they return the
 * SAME state instance) rather than throwing.
 *
 * REUSE (NO redefinition): [SignatureAsset] is AND-342's captured asset; [PlacedField] is AND-344's
 * editor read-model (mapped from AND-342 [FieldPlacement] / AND-340 [PacketField]); completeness is the
 * pure AND-344 [isComplete] over the AND-340 manifest. The error payload reuses core-model [ApiError].
 *
 * Edges (every legal transition; everything else is a no-op):
 *   Loading      --loadOk-->            Capturing
 *   Loading      --loadErr-->           Error
 *   Capturing    --onSignatureCaptured--> Placing
 *   Placing      --onFieldPlaced-->      Placing (recompute isComplete)
 *   Placing      --onFieldMoved-->       Placing (recompute isComplete)
 *   Placing      --onFieldRemoved-->     Placing (recompute isComplete)
 *   Placing      --onContinue (gated)-->  ReadyToSubmit (only when isComplete)
 *   ReadyToSubmit--onBack-->             Placing
 */
sealed interface SigningEditorState {

    /** The packet is being loaded; nothing is capturable yet. */
    data object Loading : SigningEditorState

    /**
     * The viewer is capturing a signature. [mode] is the active capture affordance; [savedSignature] is
     * a previously-saved asset offered for adoption (null when none).
     */
    data class Capturing(
        val mode: CaptureMode,
        val savedSignature: SignatureAsset? = null,
    ) : SigningEditorState

    /**
     * The viewer is placing the captured [signature] onto fields. [placed] is the editor read-model of
     * placed fields; [activeFieldId] is the field currently being manipulated (null when none);
     * [isComplete] is the recomputed completeness gate for Continue.
     */
    data class Placing(
        val signature: SignatureAsset,
        val placed: List<PlacedField>,
        val activeFieldId: String? = null,
        val isComplete: Boolean = false,
    ) : SigningEditorState

    /** Placement is complete; the viewer can proceed to the terminal submit step. */
    data class ReadyToSubmit(
        val signature: SignatureAsset,
        val placed: List<PlacedField>,
    ) : SigningEditorState

    /** A terminal editor error (e.g. the initial load failed). Reuses core-model [ApiError]. */
    data class Error(val error: ApiError) : SigningEditorState
}

/**
 * How the active signature is being captured. DRAW wires to the AND-342 "drawn" capture mode; TYPE and
 * ADOPT_SAVED both wire to the AND-342 "typed" mode (a saved asset is re-used as typed content - it is
 * never re-drawn).
 */
enum class CaptureMode(val wireMode: String) {
    DRAW("drawn"),
    ADOPT_SAVED("typed"),
    TYPE("typed"),
}

/**
 * AND-344 - the PURE reducer for [SigningEditorState]. Every public function is a pure transition:
 * given a state (+ inputs) it returns the next state, and any transition that is not legal from the
 * current state returns the SAME state unchanged (a no-op). No coroutines, no Android, no I/O.
 */
object SigningEditorReducer {

    /**
     * Loading --loadOk--> Capturing. Seeds the initial [CaptureMode] ([CaptureMode.ADOPT_SAVED] when a
     * [savedSignature] exists, else [CaptureMode.DRAW]). A no-op from any non-[Loading] state.
     */
    fun loadOk(
        state: SigningEditorState,
        savedSignature: SignatureAsset? = null,
    ): SigningEditorState = when (state) {
        is SigningEditorState.Loading -> SigningEditorState.Capturing(
            mode = if (savedSignature != null) CaptureMode.ADOPT_SAVED else CaptureMode.DRAW,
            savedSignature = savedSignature,
        )
        else -> state
    }

    /** Loading --loadErr--> Error. A no-op from any non-[Loading] state. */
    fun loadErr(
        state: SigningEditorState,
        error: ApiError,
    ): SigningEditorState = when (state) {
        is SigningEditorState.Loading -> SigningEditorState.Error(error)
        else -> state
    }

    /**
     * Capturing --onSignatureCaptured--> Placing. Carries the captured [signature] and the initial
     * [placed] read-model, recomputing [SigningEditorState.Placing.isComplete] from the [required]
     * manifest. A no-op from any non-[Capturing] state.
     */
    fun onSignatureCaptured(
        state: SigningEditorState,
        signature: SignatureAsset,
        placed: List<PlacedField> = emptyList(),
        required: List<PacketField> = emptyList(),
    ): SigningEditorState = when (state) {
        is SigningEditorState.Capturing -> SigningEditorState.Placing(
            signature = signature,
            placed = placed,
            activeFieldId = null,
            isComplete = isComplete(required, placed),
        )
        else -> state
    }

    /**
     * Placing --onFieldPlaced--> Placing. Adds (or replaces by id) [field] in the read-model, sets it as
     * the active field, and recomputes completeness from [required]. A no-op from any non-[Placing] state.
     */
    fun onFieldPlaced(
        state: SigningEditorState,
        field: PlacedField,
        required: List<PacketField>,
    ): SigningEditorState = when (state) {
        is SigningEditorState.Placing -> {
            val next = state.placed.filterNot { it.fieldId == field.fieldId } + field
            state.copy(
                placed = next,
                activeFieldId = field.fieldId,
                isComplete = isComplete(required, next),
            )
        }
        else -> state
    }

    /**
     * Placing --onFieldMoved--> Placing. Replaces the rect of [fieldId] (a move/drag) and recomputes
     * completeness. A move of an unknown field, or a move from a non-[Placing] state, is a no-op.
     */
    fun onFieldMoved(
        state: SigningEditorState,
        fieldId: String,
        rect: com.testlogon.android.feature.signing.capture.model.NormalizedRect,
        required: List<PacketField>,
    ): SigningEditorState = when (state) {
        is SigningEditorState.Placing -> {
            if (state.placed.none { it.fieldId == fieldId }) {
                state
            } else {
                val next = state.placed.map { if (it.fieldId == fieldId) it.copy(rect = rect) else it }
                state.copy(
                    placed = next,
                    activeFieldId = fieldId,
                    isComplete = isComplete(required, next),
                )
            }
        }
        else -> state
    }

    /**
     * Placing --onFieldRemoved--> Placing. Drops [fieldId] from the read-model, clears it as active if it
     * was active, and recomputes completeness. Removing an unknown field, or removing from a
     * non-[Placing] state, is a no-op.
     */
    fun onFieldRemoved(
        state: SigningEditorState,
        fieldId: String,
        required: List<PacketField>,
    ): SigningEditorState = when (state) {
        is SigningEditorState.Placing -> {
            if (state.placed.none { it.fieldId == fieldId }) {
                state
            } else {
                val next = state.placed.filterNot { it.fieldId == fieldId }
                state.copy(
                    placed = next,
                    activeFieldId = state.activeFieldId.takeIf { it != fieldId },
                    isComplete = isComplete(required, next),
                )
            }
        }
        else -> state
    }

    /**
     * Placing --onContinue--> ReadyToSubmit, GATED on [SigningEditorState.Placing.isComplete]. When the
     * editor is not yet complete (or the state is not [Placing]) this is a no-op.
     */
    fun onContinue(state: SigningEditorState): SigningEditorState = when (state) {
        is SigningEditorState.Placing ->
            if (state.isComplete) {
                SigningEditorState.ReadyToSubmit(
                    signature = state.signature,
                    placed = state.placed,
                )
            } else {
                state
            }
        else -> state
    }

    /**
     * ReadyToSubmit --onBack--> Placing. Returns to placement (recomputing completeness from [required],
     * which is true here since ReadyToSubmit was only reachable when complete). A no-op from any
     * non-[ReadyToSubmit] state.
     */
    fun onBack(
        state: SigningEditorState,
        required: List<PacketField> = emptyList(),
    ): SigningEditorState = when (state) {
        is SigningEditorState.ReadyToSubmit -> SigningEditorState.Placing(
            signature = state.signature,
            placed = state.placed,
            activeFieldId = null,
            isComplete = isComplete(required, state.placed),
        )
        else -> state
    }
}
