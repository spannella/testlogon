package com.testlogon.android.feature.kyc.facial

import android.net.Uri
import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.kyc.capture.CaptureImageProcessor
import com.testlogon.android.feature.kyc.capture.ProcessedImage
import com.testlogon.android.feature.kyc.facial.data.FaceComparisonRepository
import com.testlogon.android.feature.kyc.facial.model.FaceComparison
import com.testlogon.android.feature.kyc.facial.model.FaceResult
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
 * AND-323 - unit tests for [FaceComparisonViewModel].
 *
 * ANTI-HANG DISCIPLINE: the VM has NO poll loop, so tests use only runCurrent() — NEVER advanceUntilIdle.
 * Helper funcs that call runCurrent are [TestScope] extensions; no nested runTest. A fake repo records the
 * submit call count + serves queued results (to exercise the version-conflict + double-send paths); a fake
 * processor returns the source file.
 */
class FaceComparisonViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class FakeRepo : FaceComparisonRepository {
        var submitCalls = 0
        val submitFiles = mutableListOf<File>()
        val submitResults: ArrayDeque<ApiResult<FaceComparison>> = ArrayDeque()
        var historyResult: ApiResult<List<FaceComparison>> = ApiResult.Success(emptyList())

        override suspend fun submitSelfie(caseId: String, jpegFile: File): ApiResult<FaceComparison> {
            submitCalls++
            submitFiles += jpegFile
            return if (submitResults.isEmpty()) {
                ApiResult.Success(comparison(FaceResult.PASS, remaining = 2))
            } else {
                submitResults.removeFirst()
            }
        }

        override suspend fun listHistory(caseId: String): ApiResult<List<FaceComparison>> = historyResult
    }

    private class FakeProcessor : CaptureImageProcessor {
        override suspend fun process(source: File): ProcessedImage = ProcessedImage(source, 1024)
        override suspend fun process(source: Uri): ProcessedImage = ProcessedImage(File("unused"), 1024)
        override suspend fun encodeBase64(file: File): String = "QUJD"
    }

    private fun vm(
        repo: FakeRepo = FakeRepo(),
        caseId: String? = "kyc_1",
    ): FaceComparisonViewModel {
        val saved = SavedStateHandle().apply { if (caseId != null) set(FaceComparisonViewModel.ARG_CASE_ID, caseId) }
        return FaceComparisonViewModel(repo, FakeProcessor(), saved)
    }

    @Test
    fun acquireSelfie_movesToReview() = runTest {
        val viewModel = vm()
        viewModel.onSelfieAcquired(File("selfie.jpg"))
        runCurrent()

        val state = viewModel.uiState.value
        assertEquals(FacePhase.REVIEW, state.phase)
        assertEquals("selfie.jpg", state.capturedFile?.name)
        assertTrue(state.autoCaptureUnavailable)
    }

    @Test
    fun submit_pass_goesSubmittingThenResult() = runTest {
        val repo = FakeRepo().apply { submitResults.addLast(ApiResult.Success(comparison(FaceResult.PASS, remaining = 2))) }
        val viewModel = vm(repo)
        acquire(viewModel)

        viewModel.submit()
        runCurrent()

        val state = viewModel.uiState.value
        assertEquals(FacePhase.RESULT, state.phase)
        assertFalse(state.submitting)
        assertEquals(FaceResult.PASS, state.result?.result)
        assertFalse(state.canRetry)
        assertEquals(1, repo.submitCalls)
    }

    @Test
    fun fail_withRemaining_canRetry_thenRetryReturnsToCapture() = runTest {
        val repo = FakeRepo().apply { submitResults.addLast(ApiResult.Success(comparison(FaceResult.FAIL, remaining = 1))) }
        val viewModel = vm(repo)
        acquire(viewModel)

        viewModel.submit()
        runCurrent()
        assertEquals(FaceResult.FAIL, viewModel.uiState.value.result?.result)
        assertTrue(viewModel.uiState.value.canRetry)

        viewModel.retryAfterFail()
        runCurrent()
        val state = viewModel.uiState.value
        assertEquals(FacePhase.CAPTURE, state.phase)
        assertNull(state.capturedFile)
        assertNull(state.result)
    }

    @Test
    fun fail_withNoRemaining_retryDisabled() = runTest {
        val repo = FakeRepo().apply { submitResults.addLast(ApiResult.Success(comparison(FaceResult.FAIL, remaining = 0))) }
        val viewModel = vm(repo)
        acquire(viewModel)

        viewModel.submit()
        runCurrent()
        assertFalse(viewModel.uiState.value.canRetry)

        // retryAfterFail is a no-op when canRetry is false (stays on RESULT).
        viewModel.retryAfterFail()
        runCurrent()
        assertEquals(FacePhase.RESULT, viewModel.uiState.value.phase)
    }

    @Test
    fun submit_versionConflict_returnsToReview_withRetryablePrompt() = runTest {
        val repo = FakeRepo().apply {
            // First submit: 409 conflict. Second submit (re-submit): success (repo re-reads version).
            submitResults.addLast(ApiResult.Failure(ApiError(409, "conflict")))
            submitResults.addLast(ApiResult.Success(comparison(FaceResult.PASS, remaining = 2)))
        }
        val viewModel = vm(repo)
        acquire(viewModel)

        viewModel.submit()
        runCurrent()
        val afterConflict = viewModel.uiState.value
        assertEquals(FacePhase.REVIEW, afterConflict.phase)
        assertEquals(true, afterConflict.error?.retryable)
        assertFalse(afterConflict.submitting)

        // Re-submit succeeds.
        viewModel.submit()
        runCurrent()
        assertEquals(FacePhase.RESULT, viewModel.uiState.value.phase)
        assertEquals(2, repo.submitCalls)
    }

    @Test
    fun submit_networkError_returnsToReview() = runTest {
        val repo = FakeRepo().apply { submitResults.addLast(ApiResult.NetworkError(java.io.IOException("offline"))) }
        val viewModel = vm(repo)
        acquire(viewModel)

        viewModel.submit()
        runCurrent()
        assertEquals(FacePhase.REVIEW, viewModel.uiState.value.phase)
        assertEquals(true, viewModel.uiState.value.error?.retryable)
    }

    @Test
    fun loadHistory_populatesHistory() = runTest {
        val repo = FakeRepo().apply {
            historyResult = ApiResult.Success(
                listOf(comparison(FaceResult.FAIL, remaining = 1), comparison(FaceResult.PASS, remaining = 0)),
            )
        }
        val viewModel = vm(repo)

        viewModel.loadHistory()
        runCurrent()
        assertEquals(2, viewModel.uiState.value.history.size)
    }

    @Test
    fun blankCaseId_isNonRetryableErrorState() = runTest {
        val viewModel = vm(caseId = null)
        val state = viewModel.uiState.value
        assertEquals(false, state.error?.retryable)
        assertTrue(state.error != null)
    }

    // ---- TestScope-extension helpers (call runCurrent; never nested runTest) ----

    private fun TestScope.acquire(viewModel: FaceComparisonViewModel, file: File = File("selfie.jpg")) {
        viewModel.onSelfieAcquired(file)
        runCurrent()
    }

    private companion object {
        fun comparison(result: FaceResult, remaining: Int) = FaceComparison(
            comparisonId = "cmp_1",
            confidenceScore = if (result == FaceResult.PASS) 92 else 40,
            result = result,
            antiSpoofPassed = result == FaceResult.PASS,
            antiSpoofPassedChecks = if (result == FaceResult.PASS) 3 else 1,
            antiSpoofTotalChecks = 3,
            attemptNumber = 3 - remaining,
            maxAttempts = 3,
            remainingAttempts = remaining,
            createdAt = Instant.ofEpochSecond(1_780_000_000L),
        )
    }
}
