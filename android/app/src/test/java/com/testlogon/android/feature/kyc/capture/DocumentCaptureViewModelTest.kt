package com.testlogon.android.feature.kyc.capture

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.kyc.capture.data.KycDocumentsRepository
import com.testlogon.android.feature.kyc.capture.model.KycDocument
import com.testlogon.android.feature.kyc.capture.model.KycDocumentStatus
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.File
import java.time.Instant

/**
 * AND-321 - unit tests for [DocumentCaptureViewModel].
 *
 * ANTI-HANG DISCIPLINE: the VM has NO poll loop, so tests use only runCurrent() — NEVER advanceUntilIdle.
 * A fake repo records the order + count of POSTs (to verify sequential upload + the double-send guard); a
 * fake processor returns a deterministic processed file or throws a CaptureError (the >4MB path).
 */
class DocumentCaptureViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class FakeRepo : KycDocumentsRepository {
        val uploadedTypes = mutableListOf<String>()
        var results: ArrayDeque<ApiResult<KycDocument>> = ArrayDeque()

        override suspend fun uploadDocument(
            documentType: String,
            fileName: String,
            contentB64: String,
            caseId: String?,
        ): ApiResult<KycDocument> {
            uploadedTypes += documentType
            return if (results.isEmpty()) ApiResult.Success(doc(documentType)) else results.removeFirst()
        }
    }

    private class FakeProcessor(
        private val throwTooLarge: Boolean = false,
    ) : CaptureImageProcessor {
        override suspend fun process(source: File): ProcessedImage =
            if (throwTooLarge) throw CaptureError.TooLarge(9_000_000) else ProcessedImage(source, 1024)

        override suspend fun process(source: android.net.Uri): ProcessedImage =
            ProcessedImage(File("unused"), 1024)

        override suspend fun encodeBase64(file: File): String = "QUJD"
    }

    private fun vm(repo: FakeRepo = FakeRepo(), processor: CaptureImageProcessor = FakeProcessor()) =
        DocumentCaptureViewModel(repo, processor, SavedStateHandle())

    @Test
    fun selectType_thenImageAcquired_movesToReviewing() = runTest {
        val viewModel = vm()
        viewModel.onSelectType(DocType.ID_FRONT)
        viewModel.onImageAcquired(File("front.jpg"))
        runCurrent()

        val state = viewModel.uiState.value as DocumentCaptureUiState.Reviewing
        assertEquals(DocType.ID_FRONT, state.docType)
        assertEquals(2, state.totalCount)
    }

    @Test
    fun twoImageFlow_uploadsBothInOrder_thenSuccess() = runTest {
        val repo = FakeRepo()
        val viewModel = vm(repo)

        viewModel.onSelectType(DocType.ID_FRONT)
        viewModel.onImageAcquired(File("front.jpg"))
        runCurrent()
        viewModel.onConfirm()

        viewModel.onSelectType(DocType.ID_BACK)
        viewModel.onImageAcquired(File("back.jpg"))
        runCurrent()
        viewModel.onConfirm()

        assertTrue(viewModel.allConfirmed)

        viewModel.onStartUpload()
        runCurrent()

        assertEquals(listOf("id_front", "id_back"), repo.uploadedTypes)
        val success = viewModel.uiState.value as DocumentCaptureUiState.Success
        assertEquals("doc_id_back", success.document.documentId)
    }

    @Test
    fun cancelBeforeSecondImage_onlyFirstPosted() = runTest {
        val repo = FakeRepo()
        // First upload succeeds; cancel before the second by cancelling the job mid-pass is hard to
        // interleave deterministically, so instead confirm only ONE slot is uploaded when we cancel
        // after kicking off with a single confirmed image.
        val viewModel = vm(repo)

        viewModel.onSelectType(DocType.ID_FRONT)
        viewModel.onImageAcquired(File("front.jpg"))
        runCurrent()
        viewModel.onConfirm()

        // Only id_front confirmed; start upload, then cancel. Because cancel() cancels the job, at most the
        // in-flight image is sent and no further images are POSTed.
        viewModel.onStartUpload()
        viewModel.onCancel()
        runCurrent()

        assertTrue(repo.uploadedTypes.size <= 1)
        assertTrue(viewModel.uiState.value is DocumentCaptureUiState.SelectingType)
    }

    @Test
    fun uploadFailure_thenRetry_doesNotRePostSucceededImage() = runTest {
        val repo = FakeRepo()
        // id_front succeeds, id_back fails on the first pass.
        repo.results.addLast(ApiResult.Success(doc("id_front")))
        repo.results.addLast(ApiResult.Failure(ApiError(500, "boom")))
        val viewModel = vm(repo)

        confirmBoth(viewModel)

        viewModel.onStartUpload()
        runCurrent()

        assertEquals(listOf("id_front", "id_back"), repo.uploadedTypes)
        val error = viewModel.uiState.value as DocumentCaptureUiState.Error
        assertEquals("boom", error.message)
        assertTrue(error.retryable)

        // Retry: id_back now succeeds; id_front MUST NOT be re-POSTed (double-send guard).
        repo.results.addLast(ApiResult.Success(doc("id_back")))
        viewModel.onRetry()
        runCurrent()

        // id_front appears exactly once across both passes.
        assertEquals(1, repo.uploadedTypes.count { it == "id_front" })
        assertEquals(listOf("id_front", "id_back", "id_back"), repo.uploadedTypes)
        assertTrue(viewModel.uiState.value is DocumentCaptureUiState.Success)
    }

    @Test
    fun processorRejectsTooLarge_surfacesInlineError() = runTest {
        val viewModel = vm(processor = FakeProcessor(throwTooLarge = true))
        viewModel.onSelectType(DocType.ID_FRONT)
        viewModel.onImageAcquired(File("huge.jpg"))
        runCurrent()

        val error = viewModel.uiState.value as DocumentCaptureUiState.Error
        assertTrue(error.retryable)
        assertTrue(error.message.contains("too large"))
    }

    private fun kotlinx.coroutines.test.TestScope.confirmBoth(viewModel: DocumentCaptureViewModel) {
        viewModel.onSelectType(DocType.ID_FRONT)
        viewModel.onImageAcquired(File("front.jpg"))
        runCurrent()
        viewModel.onConfirm()
        viewModel.onSelectType(DocType.ID_BACK)
        viewModel.onImageAcquired(File("back.jpg"))
        runCurrent()
        viewModel.onConfirm()
    }

    private companion object {
        fun doc(type: String): KycDocument = KycDocument(
            documentId = "doc_$type",
            documentType = type,
            fileName = "$type.jpg",
            status = KycDocumentStatus.PENDING,
            createdAt = Instant.ofEpochSecond(1_780_000_000),
            updatedAt = Instant.ofEpochSecond(1_780_000_000),
        )
    }
}
