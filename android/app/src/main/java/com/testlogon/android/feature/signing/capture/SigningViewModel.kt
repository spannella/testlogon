package com.testlogon.android.feature.signing.capture

import androidx.compose.ui.geometry.Offset
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.signing.capture.model.FieldPlacement
import com.testlogon.android.feature.signing.capture.model.FieldType
import com.testlogon.android.feature.signing.capture.model.SignatureAsset
import com.testlogon.android.feature.signing.capture.model.SignatureField
import com.testlogon.android.feature.signing.capture.model.SignatureSource
import com.testlogon.android.feature.signing.capture.model.SignedPacketDraft
import com.testlogon.android.feature.signing.capture.model.formatSubmitDate
import com.testlogon.android.feature.signing.capture.model.toSignatureField
import com.testlogon.android.feature.signing.data.SignatureRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import java.time.LocalDate
import javax.inject.Inject

/**
 * AND-342 - presentation logic for in-app signature CAPTURE + PLACEMENT.
 *
 * LOAD: [load] reuses AND-340 [SignatureRepository.getPacket] then projects the viewer's assigned fields
 * (isAssignedToViewer == true) to [SignatureField] (AND-341 geometry is applied per-frame in the UI).
 *
 * CAPTURE: [onStrokesConfirmed] / [onTypedConfirmed] rasterize via the [SignatureRasterizer] seam (the
 * real impl is android-only; the JVM test injects a fake) and persist a saved-signature pointer via
 * [SignatureAssetStore]. [onUseSaved] adopts the previously saved asset.
 *
 * PLACEMENT: [placeField] stamps the captured asset onto a signature / initials field, or auto-fills a
 * date field with today's date as YYYY-MM-DD. [clearField] removes a placement. Progress + completeness
 * are recomputed off the PURE [SignedPacketDraft] validators.
 *
 * NO network submit (that is AND-343, fed the validated [SignedPacketDraft] via the one-shot
 * [SigningEvent.ContinueToSubmit]). NO poll loop - capture is event-driven. Plain [MutableStateFlow].
 */
@HiltViewModel
class SigningViewModel @Inject constructor(
    private val repository: SignatureRepository,
    private val assetStore: SignatureAssetStore,
    private val rasterizer: SignatureRasterizer,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val packetId: String =
        savedStateHandle.get<String>(ARG_PACKET_ID)?.takeIf { it.isNotBlank() }.orEmpty()

    private val documentId: String =
        savedStateHandle.get<String>(ARG_DOCUMENT_ID)?.takeIf { it.isNotBlank() }.orEmpty()

    private val _uiState = MutableStateFlow<SigningUiState>(SigningUiState.Loading)
    val uiState: StateFlow<SigningUiState> = _uiState.asStateFlow()

    private val _events = Channel<SigningEvent>(Channel.BUFFERED)
    val events: Flow<SigningEvent> = _events.receiveAsFlow()

    private var fields: List<SignatureField> = emptyList()
    private val placements = linkedMapOf<String, FieldPlacement>()
    private var asset: SignatureAsset? = null
    private var savedAsset: SignatureAsset? = null

    /** Override the clock in tests; production uses today. */
    var today: () -> LocalDate = { LocalDate.now() }

    init {
        load()
    }

    /** Loads the packet, projecting the viewer's assigned fields, and seeds any saved-signature pointer. */
    fun load() {
        if (packetId.isEmpty()) {
            _uiState.value = SigningUiState.Error(MISSING_PACKET, retryable = false)
            return
        }
        _uiState.value = SigningUiState.Loading
        viewModelScope.launch {
            savedAsset = assetStore.load()
            when (val result = repository.getPacket(packetId)) {
                is ApiResult.Success -> {
                    fields = result.data.fields
                        .filter { it.isAssignedToViewer == true }
                        .map { it.toSignatureField() }
                    emitEditing()
                }
                is ApiResult.Failure ->
                    _uiState.value = SigningUiState.Error(result.error.message, retryable = true)
                is ApiResult.NetworkError ->
                    _uiState.value = SigningUiState.Error(OFFLINE, retryable = true)
            }
        }
    }

    /** Re-runs [load] after a terminal error. */
    fun retry() = load()

    /** Rasterizes a DRAWN signature (strokes), sets it as the active asset + persists the pointer. */
    fun onStrokesConfirmed(strokes: List<List<Offset>>) {
        viewModelScope.launch {
            val signature = rasterizer.rasterizeStrokes(strokes, SIG_WIDTH_PX, SIG_HEIGHT_PX)
            val initials = rasterizer.rasterizeStrokes(strokes, INITIALS_WIDTH_PX, INITIALS_HEIGHT_PX)
            adoptAsset(
                SignatureAsset(
                    signaturePngPath = signature.absolutePath,
                    initialsPngPath = initials.absolutePath,
                    source = SignatureSource.DRAWN,
                    widthPx = SIG_WIDTH_PX,
                    heightPx = SIG_HEIGHT_PX,
                ),
            )
        }
    }

    /** Rasterizes a TYPED signature in [fontStyleIndex], sets it as the active asset + persists. */
    fun onTypedConfirmed(text: String, fontStyleIndex: Int) {
        viewModelScope.launch {
            val signature = rasterizer.rasterizeTyped(text, fontStyleIndex, SIG_WIDTH_PX, SIG_HEIGHT_PX)
            val initials = rasterizer.rasterizeTyped(
                text = initialsOf(text),
                fontStyleIndex = fontStyleIndex,
                widthPx = INITIALS_WIDTH_PX,
                heightPx = INITIALS_HEIGHT_PX,
            )
            adoptAsset(
                SignatureAsset(
                    signaturePngPath = signature.absolutePath,
                    initialsPngPath = initials.absolutePath,
                    source = SignatureSource.TYPED,
                    widthPx = SIG_WIDTH_PX,
                    heightPx = SIG_HEIGHT_PX,
                ),
            )
        }
    }

    /** Adopts the previously SAVED asset (offered on re-entry) without re-rasterizing. */
    fun onUseSaved() {
        val saved = savedAsset ?: return
        asset = saved.copy(source = SignatureSource.SAVED)
        emitEditing()
    }

    private suspend fun adoptAsset(captured: SignatureAsset) {
        asset = captured
        savedAsset = captured
        assetStore.save(captured)
        emitEditing()
    }

    /**
     * Places (satisfies) [fieldId]. Signature / initials stamp the captured asset's PNG; date auto-fills
     * today as YYYY-MM-DD. A signature/initials field with no captured asset yet is a no-op (the UI opens
     * the pad instead). Text / notary_stamp are out of scope in v1 (no-op).
     */
    fun placeField(fieldId: String) {
        val field = fields.firstOrNull { it.id == fieldId } ?: return
        val placement = when (field.type) {
            FieldType.SIGNATURE -> {
                val a = asset ?: return
                FieldPlacement(
                    fieldId = field.id,
                    page = field.page,
                    rect = field.rect,
                    assetPath = a.signaturePngPath,
                    satisfied = true,
                )
            }
            FieldType.INITIALS -> {
                val a = asset ?: return
                FieldPlacement(
                    fieldId = field.id,
                    page = field.page,
                    rect = field.rect,
                    assetPath = a.initialsPngPath,
                    satisfied = true,
                )
            }
            FieldType.DATE -> FieldPlacement(
                fieldId = field.id,
                page = field.page,
                rect = field.rect,
                textValue = formatSubmitDate(today()),
                satisfied = true,
            )
            FieldType.TEXT, FieldType.NOTARY_STAMP -> return
        }
        placements[fieldId] = placement
        emitEditing()
    }

    /** Removes the placement for [fieldId] (unsatisfies it) and recomputes progress. */
    fun clearField(fieldId: String) {
        if (placements.remove(fieldId) != null) {
            emitEditing()
        }
    }

    /** Builds the validated in-memory draft for AND-343. */
    fun buildDraft(): SignedPacketDraft = SignedPacketDraft(
        packetId = packetId,
        documentId = documentId,
        asset = asset,
        placements = placements.values.toList(),
    )

    /** Emits the one-shot Continue event with the draft when every required field is satisfied. */
    fun onContinue() {
        val draft = buildDraft()
        if (draft.isComplete(fields)) {
            viewModelScope.launch { _events.send(SigningEvent.ContinueToSubmit(draft)) }
        }
    }

    private fun emitEditing() {
        val draft = buildDraft()
        val requiredTotal = fields.count { it.required }
        val requiredDone = requiredTotal - draft.unsatisfiedRequired(fields).size
        _uiState.value = SigningUiState.Editing(
            fields = fields,
            placements = placements.toMap(),
            asset = asset,
            savedAsset = savedAsset,
            requiredTotal = requiredTotal,
            requiredDone = requiredDone,
            isComplete = draft.isComplete(fields),
        )
    }

    private fun initialsOf(name: String): String =
        name.trim().split(Regex("\\s+"))
            .filter { it.isNotEmpty() }
            .joinToString("") { it.first().uppercase() }
            .ifEmpty { name.take(2).uppercase() }

    companion object {
        const val ARG_PACKET_ID = "packetId"
        const val ARG_DOCUMENT_ID = "documentId"

        private const val SIG_WIDTH_PX = 600
        private const val SIG_HEIGHT_PX = 200
        private const val INITIALS_WIDTH_PX = 240
        private const val INITIALS_HEIGHT_PX = 200

        private const val OFFLINE = "Couldn't reach the server. Try again."
        private const val MISSING_PACKET = "Packet not found."
    }
}
