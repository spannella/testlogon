package com.testlogon.android.feature.signing.document

import android.graphics.Bitmap
import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.signing.document.data.PdfSource
import com.testlogon.android.feature.signing.document.model.DocumentUiState
import com.testlogon.android.feature.signing.document.model.PageLayout
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.mockito.Mockito
import java.io.File

/**
 * AND-341 - unit tests for [DocumentViewerViewModel].
 *
 * ANTI-HANG DISCIPLINE: the VM has NO poll loop. Tests use runCurrent() and NEVER advanceUntilIdle.
 * packetId is sourced from the SavedStateHandle nav arg. The real [PdfRendererImpl] depends on
 * android.graphics.pdf.PdfRenderer / ParcelFileDescriptor (android-only, NOT on the JVM unit classpath),
 * so the test drives a FAKE [PdfPageRenderer]/[PdfPageRendererFactory] returning canned [PageLayout]s and
 * a Mockito-mocked [Bitmap] (mirrors how existing tests mock Uri / Context / RequestBody). Fake helper
 * names are distinct from the production seams. No nested runTest.
 */
class DocumentViewerViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class StubPdfSource(
        var result: ApiResult<File>,
    ) : PdfSource {
        override suspend fun downloadPdf(packetId: String): ApiResult<File> = result
    }

    private class FakeRenderer(
        private val layouts: List<PageLayout>,
        private val bitmap: Bitmap,
    ) : PdfPageRenderer {
        var renderCalls = 0
        var closed = false

        override val pageCount: Int = layouts.size
        override fun pageLayout(index: Int): PageLayout = layouts[index]
        override suspend fun renderPage(index: Int, targetWidthPx: Int): Bitmap {
            renderCalls++
            return bitmap
        }

        override fun close() {
            closed = true
        }
    }

    private class FakeRendererFactory(private val renderer: FakeRenderer) : PdfPageRendererFactory {
        var created = 0
        override fun create(file: File): PdfPageRenderer {
            created++
            return renderer
        }
    }

    private fun savedState(packetId: String? = "pkt_1") = SavedStateHandle().apply {
        if (packetId != null) set(DocumentViewerViewModel.ARG_PACKET_ID, packetId)
    }

    private fun stubFile() = File("build/tmp/doc-test.pdf")

    private fun fakeBitmap(): Bitmap = Mockito.mock(Bitmap::class.java)

    @Test
    fun load_success_landsOnReady_withPageCountAndPages() = runTest {
        val source = StubPdfSource(ApiResult.Success(stubFile()))
        val renderer = FakeRenderer(
            layouts = listOf(
                PageLayout(index = 0, widthPts = 612f, heightPts = 792f),
                PageLayout(index = 1, widthPts = 612f, heightPts = 792f),
            ),
            bitmap = fakeBitmap(),
        )
        val viewModel = DocumentViewerViewModel(source, FakeRendererFactory(renderer), savedState())
        runCurrent()

        val state = viewModel.uiState.value as DocumentUiState.Ready
        assertEquals(2, state.pageCount)
        assertEquals(2, state.pages.size)
        assertEquals(0, state.pages[0].index)
        assertEquals(792f, state.pages[1].heightPts)
        assertFalse(state.isStale)
    }

    @Test
    fun load_downloadFailure_landsOnRetryableError() = runTest {
        val source = StubPdfSource(ApiResult.Failure(ApiError(500, "boom")))
        val viewModel = DocumentViewerViewModel(
            source,
            FakeRendererFactory(FakeRenderer(emptyList(), fakeBitmap())),
            savedState(),
        )
        runCurrent()

        val state = viewModel.uiState.value as DocumentUiState.Error
        assertTrue(state.retryable)
    }

    @Test
    fun load_networkError_landsOnRetryableError() = runTest {
        val source = StubPdfSource(ApiResult.NetworkError(java.io.IOException("offline")))
        val viewModel = DocumentViewerViewModel(
            source,
            FakeRendererFactory(FakeRenderer(emptyList(), fakeBitmap())),
            savedState(),
        )
        runCurrent()

        val state = viewModel.uiState.value as DocumentUiState.Error
        assertTrue(state.retryable)
    }

    @Test
    fun blankPacketId_landsOnNonRetryableError() = runTest {
        val source = StubPdfSource(ApiResult.Success(stubFile()))
        val viewModel = DocumentViewerViewModel(
            source,
            FakeRendererFactory(FakeRenderer(emptyList(), fakeBitmap())),
            savedState(packetId = null),
        )
        runCurrent()

        val state = viewModel.uiState.value as DocumentUiState.Error
        assertFalse(state.retryable)
    }

    @Test
    fun requestPage_returnsRendererBitmap_andCaches_secondCallDoesNotReRender() = runTest {
        val bitmap = fakeBitmap()
        val source = StubPdfSource(ApiResult.Success(stubFile()))
        val renderer = FakeRenderer(
            layouts = listOf(PageLayout(index = 0, widthPts = 612f, heightPts = 792f)),
            bitmap = bitmap,
        )
        val viewModel = DocumentViewerViewModel(source, FakeRendererFactory(renderer), savedState())
        runCurrent()

        val first = viewModel.requestPage(index = 0, targetWidthPx = 1000)
        runCurrent()
        assertSame(bitmap, first)
        assertEquals(1, renderer.renderCalls)

        // Second request for the same (index, width) is served from the cache -> no extra render.
        val second = viewModel.requestPage(index = 0, targetWidthPx = 1000)
        runCurrent()
        assertSame(bitmap, second)
        assertEquals(1, renderer.renderCalls)
    }
}
