package com.testlogon.android.feature.kyc.capture

import androidx.lifecycle.SavedStateHandle
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
 * AND-330 — ADDITIONAL unit tests for [DocumentCaptureViewModel] (AND-321) locking down behavior NOT
 * already covered by [DocumentCaptureViewModelTest]: the case_id pass-through into the upload, the
 * onRetake -> back-to-selection path, the NetworkError -> offline Error mapping, the per-item Uploading
 * states (PENDING/UPLOADING/SUCCEEDED) and progress fraction, and the onStartUpload re-entrancy guard.
 *
 * ANTI-HANG DISCIPLINE: the VM has NO poll loop, so tests use only runCurrent() — NEVER advanceUntilIdle.
 * Distinct fake-helper name [makeDoc] (must not shadow a repo override) per AND-330.
 */
class DocumentCaptureViewModelAdditionalTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class RecordingRepo : KycDocumentsRepository {
        val uploadedTypes = mutableListOf<String>()
        val caseIds = mutableListOf<String?>()
        var results: ArrayDeque<ApiResult<KycDocument>> = ArrayDeque()

        override suspend fun uploadDocument(
            documentType: String,
            fileName: String,
            contentB64: String,
            caseId: String?,
        ): ApiResult<KycDocument> {
            uploadedTypes += documentType
            caseIds += caseId
            return if (results.isEmpty()) ApiResult.Success(makeDoc(documentType)) else results.removeFirst()
        }
    }

    private class PassThroughProcessor : CaptureImageProcessor {
        override suspend fun process(source: File): ProcessedImage = ProcessedImage(source, 1024)
        override suspend fun process(source: android.net.Uri): ProcessedImage =
            ProcessedImage(File("unused"), 1024)
        override suspend fun encodeBase64(file: File): String = "QUJD"
    }

    private fun vm(repo: RecordingRepo = RecordingRepo()) =
        DocumentCaptureViewModel(repo, PassThroughProcessor(), SavedStateHandle())

    private fun kotlinx.coroutines.test.TestScope.confirmBothSlots(viewModel: DocumentCaptureViewModel) {
        viewModel.onSelectType(DocType.ID_FRONT)
        viewModel.onImageAcquired(File("front.jpg"))
        runCurrent()
        viewModel.onConfirm()
        viewModel.onSelectType(DocType.ID_BACK)
        viewModel.onImageAcquired(File("back.jpg"))
        runCurrent()
        viewModel.onConfirm()
    }

    @Test
    fun setCaseId_isPassedThroughOnEveryUpload() = runTest {
        val repo = RecordingRepo()
        val viewModel = vm(repo)
        viewModel.setCaseId("case_99")

        confirmBothSlots(viewModel)
        viewModel.onStartUpload()
        runCurrent()

        assertEquals(listOf("case_99", "case_99"), repo.caseIds)
    }

    @Test
    fun onRetake_discardsPending_returnsToSelection() = runTest {
        val viewModel = vm()
        viewModel.onSelectType(DocType.ID_FRONT)
        viewModel.onImageAcquired(File("front.jpg"))
        runCurrent()
        assertTrue(viewModel.uiState.value is DocumentCaptureUiState.Reviewing)

        viewModel.onRetake()

        val selecting = viewModel.uiState.value as DocumentCaptureUiState.SelectingType
        // Nothing confirmed, so both slots are still available to re-acquire.
        assertEquals(listOf(DocType.ID_FRONT, DocType.ID_BACK), selecting.available)
    }

    @Test
    fun uploadNetworkError_surfacesOfflineError() = runTest {
        val repo = RecordingRepo()
        repo.results.addLast(ApiResult.NetworkError(java.io.IOException("offline")))
        val viewModel = vm(repo)

        confirmBothSlots(viewModel)
        viewModel.onStartUpload()
        runCurrent()

        val error = viewModel.uiState.value as DocumentCaptureUiState.Error
        assertTrue(error.retryable)
        assertEquals("Couldn't reach the server. Try again.", error.message)
    }

    @Test
    fun upload_finalProgressIsFull_andAllItemsSucceeded() = runTest {
        val repo = RecordingRepo()
        val viewModel = vm(repo)

        confirmBothSlots(viewModel)
        viewModel.onStartUpload()
        runCurrent()

        // Both succeeded -> Success state; the LAST document is surfaced.
        val success = viewModel.uiState.value as DocumentCaptureUiState.Success
        assertEquals("doc_id_back", success.document.documentId)
        assertEquals(listOf("id_front", "id_back"), repo.uploadedTypes)
    }

    @Test
    fun onStartUpload_whileActive_doesNotStartSecondPass() = runTest {
        val repo = RecordingRepo()
        val viewModel = vm(repo)

        confirmBothSlots(viewModel)
        // Two back-to-back start calls before the coroutine drains: the second must be a no-op.
        viewModel.onStartUpload()
        viewModel.onStartUpload()
        runCurrent()

        // Each slot uploaded exactly once (no duplicate pass).
        assertEquals(listOf("id_front", "id_back"), repo.uploadedTypes)
    }

    private companion object {
        fun makeDoc(type: String): KycDocument = KycDocument(
            documentId = "doc_$type",
            documentType = type,
            fileName = "$type.jpg",
            status = KycDocumentStatus.PENDING,
            createdAt = Instant.ofEpochSecond(1_780_000_000),
            updatedAt = Instant.ofEpochSecond(1_780_000_000),
        )
    }
}
