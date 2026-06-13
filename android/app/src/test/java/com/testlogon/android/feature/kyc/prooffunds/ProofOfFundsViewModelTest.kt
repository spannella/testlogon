package com.testlogon.android.feature.kyc.prooffunds

import android.net.Uri
import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.kyc.capture.CaptureImageProcessor
import com.testlogon.android.feature.kyc.capture.ProcessedImage
import com.testlogon.android.feature.kyc.prooffunds.data.ProofOfFundsRepository
import com.testlogon.android.feature.kyc.prooffunds.model.PoFSource
import com.testlogon.android.feature.kyc.prooffunds.model.PoFStatus
import com.testlogon.android.feature.kyc.prooffunds.model.PoFSummary
import com.testlogon.android.feature.kyc.prooffunds.model.ProofOfFunds
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.File
import java.time.Instant

/**
 * AND-327 - unit tests for [ProofOfFundsViewModel].
 *
 * ANTI-HANG DISCIPLINE: the VM has NO poll loop, so tests use only runCurrent() — NEVER advanceUntilIdle.
 * Helper funcs that call runCurrent are [TestScope] extensions; no nested runTest. A fake repo records the
 * upload + submit call counts and serves queued results; a fake processor returns a fixed processed file.
 */
class ProofOfFundsViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class FakeRepo : ProofOfFundsRepository {
        var summaryResult: ApiResult<PoFSummary> = ApiResult.Success(sampleSummary())
        var submissionsResult: ApiResult<List<ProofOfFunds>> = ApiResult.Success(emptyList())

        var uploadCalls = 0
        val uploadResults: ArrayDeque<ApiResult<String>> = ArrayDeque()

        var submitCalls = 0
        var lastSubmitDocKey: String? = null
        val submitResults: ArrayDeque<ApiResult<ProofOfFunds>> = ArrayDeque()

        override suspend fun summary(): ApiResult<PoFSummary> = summaryResult

        override suspend fun submissions(): ApiResult<List<ProofOfFunds>> = submissionsResult

        override suspend fun getSubmission(submissionId: String): ApiResult<ProofOfFunds> =
            ApiResult.Success(submission(PoFStatus.PENDING))

        override suspend fun uploadDocument(jpegFile: File): ApiResult<String> {
            uploadCalls++
            return if (uploadResults.isEmpty()) ApiResult.Success("kyc/pof/x.jpg") else uploadResults.removeFirst()
        }

        override suspend fun submit(
            sourceCategory: String?,
            declaredAmountCents: Long?,
            currency: String?,
            documentS3Key: String?,
            note: String?,
        ): ApiResult<ProofOfFunds> {
            submitCalls++
            lastSubmitDocKey = documentS3Key
            return if (submitResults.isEmpty()) {
                ApiResult.Success(submission(PoFStatus.PENDING))
            } else {
                submitResults.removeFirst()
            }
        }
    }

    private class FakeProcessor : CaptureImageProcessor {
        override suspend fun process(source: File): ProcessedImage = ProcessedImage(source, 1024)
        override suspend fun process(source: Uri): ProcessedImage = ProcessedImage(File("unused"), 1024)
        override suspend fun encodeBase64(file: File): String = "QUJD"
    }

    private fun vm(repo: FakeRepo = FakeRepo()): ProofOfFundsViewModel =
        ProofOfFundsViewModel(repo, FakeProcessor(), SavedStateHandle())

    @Test
    fun load_noSubmissions_landsOnForm() = runTest {
        val viewModel = vm(FakeRepo())
        runCurrent()
        assertTrue(viewModel.uiState.value is ProofOfFundsUiState.Form)
    }

    @Test
    fun load_existingSubmission_landsOnStatus_withLatest() = runTest {
        val repo = FakeRepo().apply {
            submissionsResult = ApiResult.Success(
                listOf(
                    submission(PoFStatus.PENDING, id = "old", createdEpoch = 1_000),
                    submission(PoFStatus.VERIFIED, id = "new", createdEpoch = 2_000),
                ),
            )
        }
        val viewModel = vm(repo)
        runCurrent()

        val state = viewModel.uiState.value as ProofOfFundsUiState.Status
        assertEquals("new", state.latest.submissionId)
        assertFalse(state.canResubmit) // VERIFIED does not invite resubmit.
    }

    @Test
    fun onDocumentAcquired_uploads_setsDocumentKey() = runTest {
        val repo = FakeRepo()
        val viewModel = vm(repo)
        runCurrent()

        viewModel.onDocumentAcquired(File("doc.jpg"))
        runCurrent()

        assertEquals(1, repo.uploadCalls)
        val state = viewModel.uiState.value as ProofOfFundsUiState.Form
        assertEquals("kyc/pof/x.jpg", state.documentKey)
    }

    @Test
    fun submit_missingDocOrSourceOrAmount_blocksSubmit() = runTest {
        val repo = FakeRepo()
        val viewModel = vm(repo)
        runCurrent()

        // Source + amount only, no document.
        viewModel.onSourceChanged(PoFSource.SAVINGS)
        viewModel.onAmountChanged("100")
        runCurrent()
        viewModel.submit()
        runCurrent()

        assertEquals(0, repo.submitCalls)
        val state = viewModel.uiState.value as ProofOfFundsUiState.Form
        assertTrue(state.fieldErrors.documentMissing)
        assertFalse(state.submitEnabled)
    }

    @Test
    fun submit_completeForm_success_landsOnStatus() = runTest {
        val repo = FakeRepo()
        val viewModel = vm(repo)
        completeForm(viewModel)

        viewModel.submit()
        runCurrent()

        assertEquals(1, repo.submitCalls)
        assertEquals("kyc/pof/x.jpg", repo.lastSubmitDocKey)
        assertTrue(viewModel.uiState.value is ProofOfFundsUiState.Status)
    }

    @Test
    fun submit_enabledOnlyWhenComplete() = runTest {
        val repo = FakeRepo()
        val viewModel = vm(repo)
        completeForm(viewModel)

        val state = viewModel.uiState.value as ProofOfFundsUiState.Form
        assertTrue(state.submitEnabled)
    }

    @Test
    fun resubmit_fromStatus_prefillsForm() = runTest {
        val repo = FakeRepo().apply {
            submissionsResult = ApiResult.Success(
                listOf(
                    submission(
                        PoFStatus.NEEDS_MORE_INFO,
                        id = "s1",
                        source = PoFSource.INVESTMENT,
                        amountCents = 250_00L,
                        currency = "EUR",
                        note = "see attachment",
                    ),
                ),
            )
        }
        val viewModel = vm(repo)
        runCurrent()

        val status = viewModel.uiState.value as ProofOfFundsUiState.Status
        assertTrue(status.canResubmit)

        viewModel.onResubmit()
        runCurrent()

        val form = viewModel.uiState.value as ProofOfFundsUiState.Form
        assertEquals(PoFSource.INVESTMENT, form.source)
        assertEquals("250.00", form.amountRaw)
        assertEquals("EUR", form.currency)
        assertEquals("see attachment", form.note)
    }

    @Test
    fun submit_doubleSend_firesOnce() = runTest {
        val repo = FakeRepo()
        val viewModel = vm(repo)
        completeForm(viewModel)

        // Two rapid taps before runCurrent drains the first job.
        viewModel.submit()
        viewModel.submit()
        runCurrent()

        assertEquals(1, repo.submitCalls)
    }

    @Test
    fun onDocumentAcquired_doubleSend_uploadsOnce() = runTest {
        val repo = FakeRepo()
        val viewModel = vm(repo)
        runCurrent()

        viewModel.onDocumentAcquired(File("doc.jpg"))
        viewModel.onDocumentAcquired(File("doc.jpg"))
        runCurrent()

        assertEquals(1, repo.uploadCalls)
    }

    @Test
    fun load_summaryFailure_landsOnError() = runTest {
        val repo = FakeRepo().apply { summaryResult = ApiResult.Failure(ApiError(422, "bad")) }
        val viewModel = vm(repo)
        runCurrent()

        val state = viewModel.uiState.value as ProofOfFundsUiState.Error
        assertTrue(state.retryable)
    }

    // ---- TestScope-extension helpers (call runCurrent; never nested runTest) ----

    private fun TestScope.completeForm(viewModel: ProofOfFundsViewModel) {
        runCurrent()
        viewModel.onSourceChanged(PoFSource.BANK_STATEMENT)
        viewModel.onAmountChanged("1234.50")
        viewModel.onDocumentAcquired(File("doc.jpg"))
        runCurrent()
    }

    @Test
    fun parseAmountToCents_handlesGroupingAndDecimal() {
        assertEquals(123450L, parseAmountToCents("1,234.50"))
        assertEquals(123450L, parseAmountToCents("1234.5"))
        // No '.' present, so the lone comma is treated as the decimal separator.
        assertEquals(150L, parseAmountToCents("1,5"))
        // Whole number with no separators -> exact cents.
        assertEquals(50000L, parseAmountToCents("500"))
        assertNull(parseAmountToCents(""))
        assertNull(parseAmountToCents("abc"))
    }

    private companion object {
        fun sampleSummary() = PoFSummary(
            count = 0,
            verifiedCount = 0,
            activeRiskContribution = null,
            verifiedAmountCents = null,
            verifiedCategories = emptyList(),
            userSub = null,
        )

        fun submission(
            status: PoFStatus,
            id: String = "sub_1",
            source: PoFSource? = PoFSource.BANK_STATEMENT,
            amountCents: Long? = 100_00L,
            currency: String? = "USD",
            note: String? = null,
            createdEpoch: Long = 1_780_000_000L,
        ) = ProofOfFunds(
            submissionId = id,
            status = status,
            source = source,
            declaredAmountCents = amountCents,
            currency = currency,
            documentS3Key = "kyc/pof/x.jpg",
            note = note,
            reviewerNote = if (status.invitesResubmit) "needs work" else null,
            createdAt = Instant.ofEpochSecond(createdEpoch),
        )
    }
}
