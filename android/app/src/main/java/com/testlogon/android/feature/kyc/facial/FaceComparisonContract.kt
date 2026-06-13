package com.testlogon.android.feature.kyc.facial

import com.testlogon.android.feature.kyc.facial.model.FaceComparison
import com.testlogon.android.feature.kyc.facial.model.FaceResult
import java.io.File

// AND-323 - UI state + supporting types for the KYC facial-comparison screen.

/** The high-level phase the flow is on; the screen renders one surface per phase. */
enum class FacePhase {
    CAPTURE,
    REVIEW,
    SUBMITTING,
    RESULT,
}

/** A user-facing error surfaced inline by the ViewModel (no exception leaks to the UI). */
data class UiError(
    val message: String,
    val retryable: Boolean,
)

/**
 * The single immutable UI state for the facial-comparison flow (a plain MutableStateFlow drives it, NO
 * poll loop).
 *
 * [autoCaptureUnavailable] is ALWAYS true this wave: the embedded CameraX front-camera live preview +
 * oval face-guide + on-device liveness auto-capture are DEFERRED (STOP-AND-FLAG), so the screen shows
 * the "auto face-capture not configured" note while the system-intent selfie capture + server-side
 * comparison path remains fully usable.
 */
data class FaceComparisonUiState(
    val phase: FacePhase = FacePhase.CAPTURE,
    val capturedFile: File? = null,
    val submitting: Boolean = false,
    val result: FaceComparison? = null,
    val history: List<FaceComparison> = emptyList(),
    val error: UiError? = null,
    val autoCaptureUnavailable: Boolean = true,
) {
    /**
     * True only when the last verdict was a FAIL with attempts remaining — the single condition under
     * which the user may retry the comparison (PASS is done, REVIEW is neutral, FAIL with no attempts
     * left routes to contact-support).
     */
    val canRetry: Boolean
        get() = result?.let { it.result == FaceResult.FAIL && it.remainingAttempts > 0 } ?: false
}
