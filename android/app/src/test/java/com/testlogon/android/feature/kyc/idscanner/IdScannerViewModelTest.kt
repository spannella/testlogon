package com.testlogon.android.feature.kyc.idscanner

import android.net.Uri
import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.kyc.capture.CaptureImageProcessor
import com.testlogon.android.feature.kyc.capture.ProcessedImage
import com.testlogon.android.feature.kyc.idscanner.data.IdScannerRepository
import com.testlogon.android.feature.kyc.idscanner.model.ExtractionSummary
import com.testlogon.android.feature.kyc.idscanner.model.IdDocumentType
import com.testlogon.android.feature.kyc.idscanner.model.IdSide
import com.testlogon.android.feature.kyc.idscanner.model.ScanResult
import com.testlogon.android.feature.kyc.idscanner.model.ScanStatus
import com.testlogon.android.feature.kyc.idscanner.model.ValidationInfo
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.File

/**
 * AND-322 - unit tests for [IdScannerViewModel].
 *
 * ANTI-HANG DISCIPLINE: the VM has NO poll loop, so tests use only runCurrent() — NEVER advanceUntilIdle.
 * Helper funcs that call runCurrent are [TestScope] extensions; no nested runTest. A fake repo records the
 * order + count of validate/upload/scan calls (to verify sequential upload+scan + the double-send guard); a
 * stub analyzer reports auto-capture unavailable + empty MRZ; a fake processor returns the source file.
 */
class IdScannerViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class FakeRepo : IdScannerRepository {
        var validation: ValidationInfo? = null
        val uploadedSides = mutableListOf<String>()
        val scannedSides = mutableListOf<String>()
        var uploadResults: ArrayDeque<ApiResult<String>> = ArrayDeque()
        var scanResults: ArrayDeque<ApiResult<ScanResult>> = ArrayDeque()
        var validateResult: ApiResult<ValidationInfo>? = null

        override suspend fun validate(caseId: String, docType: IdDocumentType): ApiResult<ValidationInfo> {
            validateResult?.let { return it }
            val info = validation ?: defaultValidation(docType)
            return ApiResult.Success(info)
        }

        override suspend fun uploadSide(
            caseId: String,
            fileType: String,
            fileName: String,
            contentB64: String,
        ): ApiResult<String> {
            uploadedSides += fileType
            return if (uploadResults.isEmpty()) ApiResult.Success("doc_$fileType") else uploadResults.removeFirst()
        }

        override suspend fun scanSide(
            caseId: String,
            docType: IdDocumentType,
            side: IdSide,
            imageRef: String?,
            mrzLines: List<String>?,
        ): ApiResult<ScanResult> {
            scannedSides += side.fileType
            return if (scanResults.isEmpty()) {
                ApiResult.Success(scanResult(side, ScanStatus.MATCHED))
            } else {
                scanResults.removeFirst()
            }
        }
    }

    private class StubAnalyzer : IdFrameAnalyzer {
        override val isAutoCaptureAvailable: Boolean = false
        override fun analyze(image: File): QualityReport =
            QualityReport(true, true, true, 0, true)

        override suspend fun readMrz(image: File): List<String> = emptyList()
    }

    private class FakeProcessor : CaptureImageProcessor {
        override suspend fun process(source: File): ProcessedImage = ProcessedImage(source, 1024)
        override suspend fun process(source: Uri): ProcessedImage = ProcessedImage(File("unused"), 1024)
        override suspend fun encodeBase64(file: File): String = "QUJD"
    }

    private fun vm(
        repo: FakeRepo = FakeRepo(),
        caseId: String? = "kyc_1",
    ): IdScannerViewModel {
        val saved = SavedStateHandle().apply { if (caseId != null) set(IdScannerViewModel.ARG_CASE_ID, caseId) }
        return IdScannerViewModel(repo, StubAnalyzer(), FakeProcessor(), saved)
    }

    @Test
    fun selectPassport_validates_thenCapture_frontOnly() = runTest {
        val repo = FakeRepo().apply { validation = info(listOf("id_front")) }
        val viewModel = vm(repo)

        viewModel.selectType(IdDocumentType.PASSPORT)
        runCurrent()

        val state = viewModel.uiState.value
        assertEquals(IdScannerStep.CAPTURE, state.step)
        assertEquals(listOf(IdSide.FRONT), state.requiredSides)
        assertTrue(state.mediaUnavailable)
    }

    @Test
    fun selectNationalId_requiresFrontAndBack() = runTest {
        val repo = FakeRepo().apply { validation = info(listOf("id_front", "id_back")) }
        val viewModel = vm(repo)

        viewModel.selectType(IdDocumentType.NATIONAL_ID_CARD)
        runCurrent()

        assertEquals(listOf(IdSide.FRONT, IdSide.BACK), viewModel.uiState.value.requiredSides)
    }

    @Test
    fun captureBothSides_movesToReview() = runTest {
        val repo = FakeRepo().apply { validation = info(listOf("id_front", "id_back")) }
        val viewModel = vm(repo)
        captureAll(viewModel, IdDocumentType.NATIONAL_ID_CARD)

        val state = viewModel.uiState.value
        assertEquals(IdScannerStep.REVIEW, state.step)
        assertTrue(state.allSidesCaptured)
    }

    @Test
    fun confirmAndUpload_uploadsThenScansEachInOrder_thenResult() = runTest {
        val repo = FakeRepo().apply { validation = info(listOf("id_front", "id_back")) }
        val viewModel = vm(repo)
        captureAll(viewModel, IdDocumentType.NATIONAL_ID_CARD)

        viewModel.confirmAndUpload()
        runCurrent()

        // All uploads happen before any scan, each in side order.
        assertEquals(listOf("id_front", "id_back"), repo.uploadedSides)
        assertEquals(listOf("id_front", "id_back"), repo.scannedSides)
        val state = viewModel.uiState.value
        assertEquals(IdScannerStep.RESULT, state.step)
        assertEquals(2, state.results.size)
        assertTrue(state.results.all { it.status == ScanStatus.MATCHED })
    }

    @Test
    fun rejectedScan_thenRestart_returnsToCapture() = runTest {
        val repo = FakeRepo().apply {
            validation = info(listOf("id_front"))
            scanResults.addLast(ApiResult.Success(scanResult(IdSide.FRONT, ScanStatus.REJECTED)))
        }
        val viewModel = vm(repo)
        captureAll(viewModel, IdDocumentType.PASSPORT)

        viewModel.confirmAndUpload()
        runCurrent()
        assertEquals(ScanStatus.REJECTED, viewModel.uiState.value.results.single().status)

        viewModel.retryAfterReject()
        runCurrent()
        val state = viewModel.uiState.value
        assertEquals(IdScannerStep.CAPTURE, state.step)
        assertTrue(state.captured.isEmpty())
        assertTrue(state.results.isEmpty())
    }

    @Test
    fun uploadFailureThenRetry_doesNotReUploadSucceededSide() = runTest {
        val repo = FakeRepo().apply {
            validation = info(listOf("id_front", "id_back"))
            // front upload OK, back upload fails on the first pass.
            uploadResults.addLast(ApiResult.Success("doc_id_front"))
            uploadResults.addLast(ApiResult.Failure(ApiError(500, "boom")))
        }
        val viewModel = vm(repo)
        captureAll(viewModel, IdDocumentType.NATIONAL_ID_CARD)

        viewModel.confirmAndUpload()
        runCurrent()
        // Mid-upload failure lands back on REVIEW with a retryable error; nothing scanned yet.
        assertEquals(IdScannerStep.REVIEW, viewModel.uiState.value.step)
        assertEquals("boom", viewModel.uiState.value.error?.message)
        assertTrue(repo.scannedSides.isEmpty())

        // Retry: back now uploads; front MUST NOT be re-uploaded (double-send guard).
        viewModel.confirmAndUpload()
        runCurrent()

        assertEquals(1, repo.uploadedSides.count { it == "id_front" })
        assertEquals(listOf("id_front", "id_back", "id_back"), repo.uploadedSides)
        assertEquals(IdScannerStep.RESULT, viewModel.uiState.value.step)
    }

    @Test
    fun blankCaseId_isErrorState() = runTest {
        val viewModel = vm(caseId = null)
        val state = viewModel.uiState.value
        assertEquals(false, state.error?.retryable)
        assertTrue(state.error != null)
    }

    // ---- TestScope-extension helpers (call runCurrent; never nested runTest) ----

    private fun TestScope.captureAll(viewModel: IdScannerViewModel, type: IdDocumentType) {
        viewModel.selectType(type)
        runCurrent()
        val sides = viewModel.uiState.value.requiredSides
        for (side in sides) {
            viewModel.onImageAcquired(side, File("${side.fileType}.jpg"))
            runCurrent()
        }
    }

    private companion object {
        fun info(sidesRequired: List<String>) = ValidationInfo(
            documentType = "x",
            sidesRequired = sidesRequired,
            sidesPresent = emptyList(),
            hasMrz = true,
            mrzFormat = "TD3",
            allSidesPresent = false,
        )

        fun defaultValidation(docType: IdDocumentType) = info(
            if (docType == IdDocumentType.PASSPORT) listOf("id_front") else listOf("id_front", "id_back"),
        )

        fun scanResult(side: IdSide, status: ScanStatus) = ScanResult(
            scanId = "scan_${side.fileType}",
            side = side,
            status = status,
            mrzValid = true,
            reason = if (status == ScanStatus.REJECTED) "Document expired" else null,
            extraction = ExtractionSummary(null, null, null, null, null),
            imageUrl = null,
        )
    }
}
