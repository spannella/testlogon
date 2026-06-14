package com.testlogon.android.data.vod.download

import androidx.work.ListenableWorker
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-195 — pure render-resolution (fail-closed) + worker result-mapping logic
 * (TC-AND-195-05/06). JVM, no Android Context.
 */
class WatermarkDownloadLogicTest {

    @Test
    fun resolve_ready_withUrl_streams() {
        val r = WatermarkDownloadLogic.resolveRender("ready", "http://x/wm.mp4", "wmp_1")
        assertTrue(r is RenderResolution.Stream)
        assertEquals("http://x/wm.mp4", (r as RenderResolution.Stream).downloadUrl)
        assertEquals("wmp_1", r.watermarkPayload)
    }

    @Test
    fun resolve_ready_withoutUrl_failsClosed() {
        // Never promote an un-watermarked file: ready with no url is a failure.
        assertTrue(WatermarkDownloadLogic.resolveRender("ready", null, "wmp") is RenderResolution.Fail)
    }

    @Test
    fun resolve_processing_polls() {
        assertTrue(WatermarkDownloadLogic.resolveRender("processing", null, null) is RenderResolution.Poll)
    }

    @Test
    fun resolve_failed_failsClosed() {
        assertTrue(WatermarkDownloadLogic.resolveRender("failed", null, null) is RenderResolution.Fail)
    }

    @Test
    fun resolve_notFound_restarts() {
        assertTrue(WatermarkDownloadLogic.resolveRender("not_found", null, null) is RenderResolution.Restart)
    }

    @Test
    fun resolve_unknownStatus_pollsNotStream() {
        // Unknown -> keep polling (caller fails closed at deadline); NEVER stream.
        assertTrue(WatermarkDownloadLogic.resolveRender("weird", "http://x", "p") is RenderResolution.Poll)
    }

    @Test
    fun percent_clampsAndComputes() {
        assertEquals(0, WatermarkDownloadLogic.percent(0L, 0L))
        assertEquals(50, WatermarkDownloadLogic.percent(50L, 100L))
        assertEquals(100, WatermarkDownloadLogic.percent(200L, 100L))
    }

    @Test
    fun worker_resultMapping() {
        val item = DownloadedItem("v1", "file://x", 10L, true, WatermarkStrategy.SERVER_BURNED_IN, "u", "p", 0L)
        assertTrue(WatermarkDownloadWorker.resultFor(ApiResult.Success(item)) is ListenableWorker.Result.Success)
        assertTrue(
            WatermarkDownloadWorker.resultFor(ApiResult.NetworkError(RuntimeException())) is ListenableWorker.Result.Retry,
        )
        // NETWORK/TOKEN_EXPIRED Failure -> retry; permanent (WATERMARK_FAILED) -> failure.
        assertTrue(
            WatermarkDownloadWorker.resultFor(
                ApiResult.Failure(ApiError(0, "x", code = DownloadError.NETWORK.name)),
            ) is ListenableWorker.Result.Retry,
        )
        assertTrue(
            WatermarkDownloadWorker.resultFor(
                ApiResult.Failure(ApiError(0, "x", code = DownloadError.WATERMARK_FAILED.name)),
            ) is ListenableWorker.Result.Failure,
        )
    }
}
