package com.testlogon.android.feature.kyc.idscanner

import com.testlogon.android.feature.kyc.idscanner.model.IdDocumentType
import com.testlogon.android.feature.kyc.idscanner.model.IdSide
import com.testlogon.android.feature.kyc.idscanner.model.ScanResult
import com.testlogon.android.feature.kyc.idscanner.model.ValidationInfo
import java.io.File

// AND-322 - UI state + supporting types for the KYC ID-scanner screen.

/** The high-level step the flow is on; the screen renders one surface per step. */
enum class IdScannerStep {
    TYPE_SELECT,
    CAPTURE,
    REVIEW,
    UPLOADING,
    SCANNING,
    RESULT,
}

/** A captured side awaiting upload/scan. [documentId] is set once the side has been uploaded (AND-321). */
data class CapturedSide(
    val side: IdSide,
    val file: File,
    val documentId: String? = null,
)

/** A user-facing error surfaced inline by the ViewModel (no exception leaks to the UI). */
data class UiError(
    val message: String,
    val retryable: Boolean,
)

/**
 * The single immutable UI state for the ID-scanner flow (a plain MutableStateFlow drives it, NO poll loop).
 *
 * [mediaUnavailable] is set when the FLAGGED auto-capture / MRZ analyzer path is requested but not configured;
 * it drives the "identity verification (auto-capture / MRZ) not configured" note while leaving the manual
 * capture+upload+scan path fully usable.
 */
data class IdScannerUiState(
    val step: IdScannerStep = IdScannerStep.TYPE_SELECT,
    val selectedType: IdDocumentType? = null,
    val validation: ValidationInfo? = null,
    val currentSide: IdSide = IdSide.FRONT,
    val captured: Map<IdSide, CapturedSide> = emptyMap(),
    val results: List<ScanResult> = emptyList(),
    val mediaUnavailable: Boolean = false,
    val error: UiError? = null,
    val isOffline: Boolean = false,
) {
    /** The ordered sides this flow requires (server-driven when available, else the client default). */
    val requiredSides: List<IdSide> get() = sidesFor(selectedType, validation)

    /** True once every required side has a captured image. */
    val allSidesCaptured: Boolean get() = requiredSides.all { captured.containsKey(it) }
}

/**
 * The required sides for a document type. PREFERS the server's sides_required from validate-document; falls
 * back to the client rule (passport = front only; everything else = front + back).
 */
fun sidesFor(type: IdDocumentType?, validation: ValidationInfo?): List<IdSide> {
    val fromServer = validation?.sidesRequired
        ?.mapNotNull { token -> IdSide.entries.firstOrNull { it.fileType == token } }
        ?.distinct()
    if (!fromServer.isNullOrEmpty()) return fromServer
    return when (type) {
        IdDocumentType.PASSPORT -> listOf(IdSide.FRONT)
        else -> listOf(IdSide.FRONT, IdSide.BACK)
    }
}
