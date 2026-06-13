package com.testlogon.android.feature.kyc.residency

import android.net.Uri
import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.kyc.capture.CaptureImageProcessor
import com.testlogon.android.feature.kyc.capture.ProcessedImage
import com.testlogon.android.feature.kyc.residency.data.ResidencyRepository
import com.testlogon.android.feature.kyc.residency.model.AddressForm
import com.testlogon.android.feature.kyc.residency.model.AddrDecision
import com.testlogon.android.feature.kyc.residency.model.AddrStatus
import com.testlogon.android.feature.kyc.residency.model.AddressVerification
import com.testlogon.android.feature.kyc.residency.model.ResidencyDocType
import com.testlogon.android.feature.kyc.residency.model.ResidencyDocument
import com.testlogon.android.feature.kyc.residency.model.ResidencyStatus
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.File
import java.time.Instant

/**
 * AND-326 - unit tests for [ResidencyViewModel].
 *
 * ANTI-HANG DISCIPLINE: the VM has NO poll loop, so tests use only runCurrent() — NEVER advanceUntilIdle.
 * Helper funcs that call runCurrent are [TestScope] extensions; no nested runTest. A fake repo records the
 * upload + verify call counts and serves queued results; a fake processor returns a fixed base64 string.
 */
class ResidencyViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class FakeRepo : ResidencyRepository {
        var documentsResult: ApiResult<List<ResidencyDocument>> = ApiResult.Success(emptyList())
        var addressStatusResult: ApiResult<AddressVerification> =
            ApiResult.Failure(ApiError(404, "no address yet"))

        var uploadCalls = 0
        val uploadResults: ArrayDeque<ApiResult<ResidencyDocument>> = ArrayDeque()

        var verifyCalls = 0
        val verifyResults: ArrayDeque<ApiResult<AddressVerification>> = ArrayDeque()

        override suspend fun residencyDocuments(): ApiResult<List<ResidencyDocument>> = documentsResult

        override suspend fun uploadResidency(
            docType: ResidencyDocType,
            issuingEntity: String,
            documentDate: String,
            fileName: String,
            contentB64: String,
            caseId: String?,
        ): ApiResult<ResidencyDocument> {
            uploadCalls++
            return if (uploadResults.isEmpty()) {
                ApiResult.Success(document(ResidencyStatus.PENDING))
            } else {
                uploadResults.removeFirst()
            }
        }

        override suspend fun extractResidency(documentId: String): ApiResult<ResidencyDocument> =
            ApiResult.Success(document(ResidencyStatus.PENDING))

        override suspend fun verifyAddress(
            caseId: String,
            form: AddressForm,
        ): ApiResult<AddressVerification> {
            verifyCalls++
            return if (verifyResults.isEmpty()) {
                ApiResult.Success(verification(AddrDecision.VERIFIED))
            } else {
                verifyResults.removeFirst()
            }
        }

        override suspend fun getAddressVerification(caseId: String): ApiResult<AddressVerification> =
            addressStatusResult

        override suspend fun validatePostalCode(postal: String, country: String): ApiResult<Boolean> =
            ApiResult.Success(true)
    }

    private class FakeProcessor : CaptureImageProcessor {
        override suspend fun process(source: File): ProcessedImage = ProcessedImage(source, 1024)
        override suspend fun process(source: Uri): ProcessedImage = ProcessedImage(File("unused"), 1024)
        override suspend fun encodeBase64(file: File): String = "QUJD"
    }

    private fun vm(
        repo: FakeRepo = FakeRepo(),
        caseId: String? = "kyc_1",
    ): ResidencyViewModel {
        val saved = SavedStateHandle().apply {
            if (caseId != null) set(ResidencyViewModel.ARG_CASE_ID, caseId)
        }
        return ResidencyViewModel(repo, FakeProcessor(), saved)
    }

    @Test
    fun onScreenEntered_loadsEditing_withLatestDocument() = runTest {
        val repo = FakeRepo().apply {
            documentsResult = ApiResult.Success(
                listOf(
                    document(ResidencyStatus.PENDING, createdEpoch = 1_000),
                    document(ResidencyStatus.VERIFIED, createdEpoch = 2_000, id = "doc_2"),
                ),
            )
        }
        val viewModel = vm(repo)

        enter(viewModel)

        val state = viewModel.uiState.value as ResidencyUiState.Editing
        // The latest (max createdAt) document is surfaced.
        assertEquals("doc_2", state.latestDocument?.documentId)
    }

    @Test
    fun submitResidency_missingIssuerOrDate_blocksUpload() = runTest {
        val repo = FakeRepo()
        val viewModel = vm(repo)
        enter(viewModel)

        // Type + proof present, but issuer + date blank.
        viewModel.onProofTypeSelected(ResidencyDocType.UTILITY_BILL)
        viewModel.onProofCaptured(File("bill.jpg"))
        runCurrent()

        viewModel.submitResidency()
        runCurrent()

        // No upload fired; still Editing with validation flags set.
        assertEquals(0, repo.uploadCalls)
        val state = viewModel.uiState.value as ResidencyUiState.Editing
        assertTrue(state.validation.issuerMissing)
        assertTrue(state.validation.dateMissing)
        assertFalse(state.submitEnabled)
    }

    @Test
    fun submitResidency_pending_success_landsOnPending() = runTest {
        val repo = FakeRepo().apply {
            uploadResults.addLast(ApiResult.Success(document(ResidencyStatus.PENDING)))
        }
        val viewModel = vm(repo)
        completeProofForm(viewModel)

        viewModel.submitResidency()
        runCurrent()

        assertEquals(1, repo.uploadCalls)
        assertTrue(viewModel.uiState.value is ResidencyUiState.Pending)
    }

    @Test
    fun submitResidency_verifiedStatus_landsOnVerified() = runTest {
        val repo = FakeRepo().apply {
            uploadResults.addLast(ApiResult.Success(document(ResidencyStatus.VERIFIED)))
        }
        val viewModel = vm(repo)
        completeProofForm(viewModel)

        viewModel.submitResidency()
        runCurrent()

        assertTrue(viewModel.uiState.value is ResidencyUiState.Verified)
    }

    @Test
    fun submitResidency_rejectedStatus_landsOnRejected_withReason() = runTest {
        val repo = FakeRepo().apply {
            uploadResults.addLast(
                ApiResult.Success(document(ResidencyStatus.REJECTED, reviewNote = "blurry")),
            )
        }
        val viewModel = vm(repo)
        completeProofForm(viewModel)

        viewModel.submitResidency()
        runCurrent()

        val state = viewModel.uiState.value as ResidencyUiState.Rejected
        assertEquals("blurry", state.reason)
    }

    @Test
    fun submitAddress_success_landsOnAddressResult_withDecision() = runTest {
        val repo = FakeRepo().apply {
            verifyResults.addLast(ApiResult.Success(verification(AddrDecision.NEEDS_REVIEW)))
        }
        val viewModel = vm(repo)
        enter(viewModel)
        fillAddress(viewModel)

        viewModel.submitAddress()
        runCurrent()

        assertEquals(1, repo.verifyCalls)
        val state = viewModel.uiState.value as ResidencyUiState.AddressResult
        assertEquals(AddrDecision.NEEDS_REVIEW, state.verification.decision)
    }

    @Test
    fun submitAddress_withoutCaseId_isNoOp() = runTest {
        val repo = FakeRepo()
        val viewModel = vm(repo, caseId = null)
        enter(viewModel)
        fillAddress(viewModel)

        viewModel.submitAddress()
        runCurrent()

        assertEquals(0, repo.verifyCalls)
        assertFalse(viewModel.canVerifyAddress)
    }

    @Test
    fun submitResidency_oversizedProof_blocksWithInlineError() = runTest {
        val repo = FakeRepo()
        val viewModel = vm(repo)
        enter(viewModel)

        viewModel.onProofTypeSelected(ResidencyDocType.UTILITY_BILL)
        viewModel.onIssuingEntityChanged("Acme")
        viewModel.onDocumentDateChanged("2026-05-01")
        viewModel.onProofCaptured(OversizedFile())
        runCurrent()

        viewModel.submitResidency()
        runCurrent()

        // The >4MB proof was rejected before encode -> no upload, proofTooLarge flagged.
        assertEquals(0, repo.uploadCalls)
        val state = viewModel.uiState.value as ResidencyUiState.Editing
        assertTrue(state.validation.proofTooLarge)
        assertFalse(state.submitEnabled)
    }

    @Test
    fun submitResidency_doubleSend_firesOnce() = runTest {
        val repo = FakeRepo().apply {
            uploadResults.addLast(ApiResult.Success(document(ResidencyStatus.PENDING)))
        }
        val viewModel = vm(repo)
        completeProofForm(viewModel)

        // Two rapid taps before runCurrent drains the first job.
        viewModel.submitResidency()
        viewModel.submitResidency()
        runCurrent()

        assertEquals(1, repo.uploadCalls)
    }

    // ---- TestScope-extension helpers (call runCurrent; never nested runTest) ----

    /** Drives the one-shot initial load and drains it. */
    private fun TestScope.enter(viewModel: ResidencyViewModel) {
        viewModel.onScreenEntered()
        runCurrent()
    }

    private fun TestScope.completeProofForm(viewModel: ResidencyViewModel) {
        viewModel.onScreenEntered()
        runCurrent()
        viewModel.onProofTypeSelected(ResidencyDocType.UTILITY_BILL)
        viewModel.onIssuingEntityChanged("Acme Power")
        viewModel.onDocumentDateChanged("2026-05-01")
        viewModel.onProofCaptured(File("bill.jpg"))
        runCurrent()
    }

    private fun TestScope.fillAddress(viewModel: ResidencyViewModel) {
        viewModel.onAddressFieldChanged { it.copy(line1 = "Main St 1") }
        viewModel.onAddressFieldChanged { it.copy(city = "Springfield") }
        viewModel.onAddressFieldChanged { it.copy(state = "IL") }
        viewModel.onAddressFieldChanged { it.copy(postalCode = "62704") }
        viewModel.onAddressFieldChanged { it.copy(country = "US") }
        runCurrent()
    }

    /** A File reporting a length over the 4 MB cap without touching the filesystem. */
    private class OversizedFile : File("oversized.jpg") {
        override fun length(): Long = ResidencyViewModel.MAX_PROOF_BYTES + 1
    }

    private companion object {
        fun document(
            status: ResidencyStatus,
            id: String = "doc_1",
            reviewNote: String? = null,
            createdEpoch: Long = 1_780_000_000L,
        ) = ResidencyDocument(
            documentId = id,
            docType = ResidencyDocType.UTILITY_BILL,
            status = status,
            fileName = "bill.jpg",
            issuingEntity = "Acme Power",
            documentDate = "2026-05-01",
            reviewNote = reviewNote,
            createdAt = Instant.ofEpochSecond(createdEpoch),
        )

        fun verification(decision: AddrDecision) = AddressVerification(
            status = AddrStatus.PARTIAL_MATCH,
            decision = decision,
            discrepancies = listOf("postal_code"),
            confidenceScore = 72,
            standardizedAddress = mapOf("line_1" to "MAIN ST 1"),
        )
    }
}
