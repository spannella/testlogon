package com.testlogon.android.feature.kyc.idscanner

import java.io.File
import javax.inject.Inject

/**
 * AND-322 - FLAGGED on-device seam for the live auto-capture quality gates + MRZ OCR.
 *
 * STOP-AND-FLAG (HUMAN DECISION REQUIRED): a REAL implementation needs
 *   - CameraX `ImageAnalysis` to stream frames for live auto-capture, and
 *   - on-device quality gates (Laplacian-variance sharpness, glare/exposure, document-edge detection), and
 *   - ML Kit (or an equivalent) text recognition to OCR the MRZ lines,
 * all of which require a NEW CameraX / ML Kit / vendor dependency that is explicitly OUT OF SCOPE for AND-322
 * (NO CameraX, NO ML Kit, NO new Gradle dependency). The vendor / model choice is a HUMAN DECISION.
 *
 * Until that is built, the manual control-plane path is REAL and fully functional: the user captures each
 * side via AND-321's system-intent camera / photo picker, the image is uploaded (base64) and scanned
 * server-side. This seam exists so that path does not depend on the deferred ML work — the stub reports a
 * passing quality verdict (so MANUAL capture proceeds) and returns NO MRZ lines (so the server scans without
 * client-supplied MRZ).
 */
interface IdFrameAnalyzer {

    /**
     * Whether a live auto-capture analyzer is actually configured. The stub returns false so the ViewModel
     * surfaces the "auto-capture / MRZ not configured" note and keeps the user on the manual capture path.
     */
    val isAutoCaptureAvailable: Boolean

    /** On-device quality verdict for an acquired still. The stub passes so manual capture is never blocked. */
    fun analyze(image: File): QualityReport

    /** On-device MRZ OCR. The stub returns an empty list (the server scans without client MRZ lines). */
    suspend fun readMrz(image: File): List<String>
}

/**
 * AND-322 - per-frame quality verdict. With a real analyzer these gates drive auto-capture; with the stub
 * they are all reported as passing / not-evaluated so MANUAL capture is never blocked.
 */
data class QualityReport(
    val sharpnessOk: Boolean,
    val glareOk: Boolean,
    val edgesOk: Boolean,
    val mrzLineCount: Int,
    val passed: Boolean,
)

/**
 * AND-322 - the FLAGGED stub. Bound via Hilt @Binds in [com.testlogon.android.feature.kyc.idscanner.data.
 * IdScannerModule]. Reports a passing verdict with all gates "not evaluated" (reported as true) and zero MRZ
 * lines so the manual capture+upload+scan path works end to end; [readMrz] returns an empty list. Replace
 * with a real CameraX + ML Kit implementation when that dependency decision is made (STOP-AND-FLAG).
 */
class StubIdFrameAnalyzer @Inject constructor() : IdFrameAnalyzer {

    override val isAutoCaptureAvailable: Boolean = false

    override fun analyze(image: File): QualityReport = QualityReport(
        sharpnessOk = true,
        glareOk = true,
        edgesOk = true,
        mrzLineCount = 0,
        passed = true,
    )

    override suspend fun readMrz(image: File): List<String> = emptyList()
}
