package com.testlogon.android.data.vod.download

/**
 * AND-195 — pure, JVM-unit-testable watermark-download domain + the fail-closed render-status resolver.
 *
 * Framework-free: the [resolveRender] truth table decides ready/poll/fail purely from the begin/poll
 * status string, so the "never promote an un-watermarked file" guarantee (FR-3) is JVM-tested. The
 * download artifact is server-burned-in (the only backend strategy); the forensic token is recorded.
 */

/** Observable per-VOD download state surfaced to the detail screen (FR-4). */
sealed interface DownloadUiState {
    data object Idle : DownloadUiState
    data object Queued : DownloadUiState
    data class Downloading(val percent: Int) : DownloadUiState   // 0..100
    data object Watermarking : DownloadUiState
    data class Completed(val item: DownloadedItem) : DownloadUiState
    data class Failed(val reason: DownloadError) : DownloadUiState
    data object Cancelled : DownloadUiState
}

enum class DownloadError {
    NETWORK, NOT_ENTITLED, IDENTITY_UNRESOLVED, WATERMARK_FAILED,
    STORAGE_FULL, TOKEN_EXPIRED, UNKNOWN,
}

/** The backend supports server-side burn-in only; the sidecar branch is a dead-code fail-safe (§16). */
enum class WatermarkStrategy { SERVER_BURNED_IN, CLIENT_SIDECAR }

/** Persisted metadata for a completed (or in-flight) download. */
data class DownloadedItem(
    val videoId: String,
    val localUri: String,
    val sizeBytes: Long,
    val watermarked: Boolean,          // MUST be true for protected content
    val strategy: WatermarkStrategy,
    val identityId: String,            // user id captured at request time
    val watermarkPayload: String?,     // forensic per-viewer token (server burn-in)
    val completedAtEpochMs: Long,
)

/** The next step the worker pipeline should take, decided purely from a render-status string. */
sealed interface RenderResolution {
    /** Ready to stream the artifact from [downloadUrl]. */
    data class Stream(val downloadUrl: String, val watermarkPayload: String?) : RenderResolution
    /** Still rendering; poll status. */
    data object Poll : RenderResolution
    /** Render not found (reaped); restart from begin once. */
    data object Restart : RenderResolution
    /** Terminal failure; fail closed with no artifact. */
    data object Fail : RenderResolution
}

object WatermarkDownloadLogic {

    /**
     * Fail-closed resolution of a begin/poll response. Unknown statuses are treated as [Poll] (keep
     * polling up to the worker's deadline, then the caller fails closed) — NEVER promoted to a stream.
     * A `ready` status without a usable [downloadUrl] is a failure (no un-watermarked save).
     */
    fun resolveRender(
        status: String,
        downloadUrl: String?,
        watermarkPayload: String?,
    ): RenderResolution = when (status) {
        VodWatermarkDownloadApi.STATUS_READY ->
            if (!downloadUrl.isNullOrBlank()) RenderResolution.Stream(downloadUrl, watermarkPayload)
            else RenderResolution.Fail
        VodWatermarkDownloadApi.STATUS_PROCESSING -> RenderResolution.Poll
        VodWatermarkDownloadApi.STATUS_FAILED -> RenderResolution.Fail
        VodWatermarkDownloadApi.STATUS_NOT_FOUND -> RenderResolution.Restart
        else -> RenderResolution.Poll // unknown -> keep polling, fail closed at deadline
    }

    /** Whole-number download percent (0..100), clamped. Pure. */
    fun percent(bytesRead: Long, totalBytes: Long): Int {
        if (totalBytes <= 0L) return 0
        val pct = (bytesRead * 100L / totalBytes).toInt()
        return pct.coerceIn(0, 100)
    }
}
