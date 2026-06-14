package com.testlogon.android.feature.report

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.report.ReportReason
import com.testlogon.android.data.report.ReportFlowRepository
import com.testlogon.android.data.report.ReportKind
import com.testlogon.android.data.report.ReportOutcome
import com.testlogon.android.data.report.ReportResult
import com.testlogon.android.data.report.ReportTarget
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-383 — ReportViewModel unit tests (TC-AND-383-01..06). Uses a fake [ReportFlowRepository]; no nested
 * runTest. State is read synchronously off the StateFlow value; the single in-flight coroutine is driven
 * with runCurrent / advanceUntilIdle on the StandardTestDispatcher from [MainDispatcherRule].
 */
class ReportViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeReportFlowRepository()

    private fun vm(target: ReportTarget = contentTarget()) =
        ReportViewModel(repo, SavedStateHandle()).apply { start(target) }

    private fun contentTarget() = ReportTarget.Content(id = "post_1", contentType = "feed_post")

    // TC-AND-383-01
    @Test
    fun canSubmit_requiresTopicAndReasonLengthInRange() {
        val viewModel = vm()
        assertEquals(ReportKind.CONTENT, viewModel.state.value.kind)
        assertFalse(viewModel.state.value.canSubmit) // nothing selected

        viewModel.onTopicToggled(ReportReason.SPAM, true)
        viewModel.onReasonTextChanged("0123456789") // 10 chars
        assertTrue(viewModel.state.value.canSubmit)

        viewModel.onTopicToggled(ReportReason.SPAM, false) // clear topics
        assertFalse(viewModel.state.value.canSubmit)

        viewModel.onTopicToggled(ReportReason.SPAM, true)
        viewModel.onReasonTextChanged("abcd") // 4 < 5
        assertFalse(viewModel.state.value.canSubmit)

        viewModel.onReasonTextChanged("x".repeat(2001)) // capped to 2000 -> trimmed length 2000 (in range)
        assertEquals(2000, viewModel.state.value.reasonText.length)
        assertTrue(viewModel.state.value.canSubmit)
    }

    // TC-AND-383-02
    @Test
    fun submit_transitions_editing_submitting_success() = runTest {
        repo.result = ApiResult.Success(ReportResult("rpt_1", alreadyReported = false))
        val viewModel = vm()
        viewModel.onTopicToggled(ReportReason.SPAM, true)
        viewModel.onReasonTextChanged("repeated spam")

        viewModel.submit()
        assertEquals(ReportUiState.Phase.Submitting, viewModel.state.value.phase)
        advanceUntilIdle()

        assertEquals(ReportUiState.Phase.Success(alreadyReported = false), viewModel.state.value.phase)
        assertEquals(ReportOutcome.SUBMITTED, viewModel.outcome())
        assertEquals(1, repo.calls.size)
    }

    // TC-AND-383-03
    @Test
    fun submit_deduplicated_mapsToAlreadyReported() = runTest {
        repo.result = ApiResult.Success(ReportResult("rpt_2", alreadyReported = true))
        val viewModel = vm()
        viewModel.onTopicToggled(ReportReason.CRIMINAL, true)
        viewModel.onReasonTextChanged("already flagged this")
        viewModel.submit()
        advanceUntilIdle()

        assertEquals(ReportUiState.Phase.Success(alreadyReported = true), viewModel.state.value.phase)
        assertEquals(ReportOutcome.ALREADY_REPORTED, viewModel.outcome())
    }

    // TC-AND-383-04
    @Test
    fun retryableError_preservesForm_andRetryRecovers() = runTest {
        repo.result = ApiResult.Failure(ApiError(500, "server boom"))
        val viewModel = vm()
        viewModel.onTopicToggled(ReportReason.SPAM, true)
        viewModel.onReasonTextChanged("spam links everywhere")
        viewModel.submit()
        advanceUntilIdle()

        val errored = viewModel.state.value
        assertTrue(errored.phase is ReportUiState.Phase.Error)
        assertTrue((errored.phase as ReportUiState.Phase.Error).retryable)
        // Form preserved.
        assertEquals(setOf(ReportReason.SPAM), errored.selectedTopics)
        assertEquals("spam links everywhere", errored.reasonText)

        repo.result = ApiResult.Success(ReportResult("rpt_3", alreadyReported = false))
        viewModel.retry()
        advanceUntilIdle()
        assertEquals(ReportUiState.Phase.Success(alreadyReported = false), viewModel.state.value.phase)
        assertEquals(2, repo.calls.size)
    }

    // TC-AND-383-05
    @Test
    fun terminal401_isNonRetryableSignIn_andCallsRepoOnce() = runTest {
        repo.result = ApiResult.Failure(ApiError(401, "unauthorized"))
        val viewModel = vm()
        viewModel.onTopicToggled(ReportReason.RACIST, true)
        viewModel.onReasonTextChanged("hate speech here")
        viewModel.submit()
        advanceUntilIdle()

        val phase = viewModel.state.value.phase
        assertTrue(phase is ReportUiState.Phase.Error)
        phase as ReportUiState.Phase.Error
        assertEquals(ReportViewModel.SIGN_IN_MESSAGE, phase.message)
        assertFalse(phase.retryable)
        assertEquals(1, repo.calls.size)
    }

    // TC-AND-383-06
    @Test
    fun reEntrantSubmit_whileSubmitting_isNoOp() = runTest {
        val gate = CompletableDeferred<ApiResult<ReportResult>>()
        repo.deferred = gate
        val viewModel = vm()
        viewModel.onTopicToggled(ReportReason.SPAM, true)
        viewModel.onReasonTextChanged("spammy content")

        viewModel.submit()
        runCurrent()
        assertEquals(ReportUiState.Phase.Submitting, viewModel.state.value.phase)
        viewModel.submit() // second call while in flight -> ignored
        runCurrent()

        gate.complete(ApiResult.Success(ReportResult("rpt_4", alreadyReported = false)))
        advanceUntilIdle()
        assertEquals(1, repo.calls.size)
    }

    @Test
    fun networkError_isRetryable_offlineMessage() = runTest {
        repo.result = ApiResult.NetworkError(java.io.IOException("down"))
        val viewModel = vm()
        viewModel.onTopicToggled(ReportReason.SPAM, true)
        viewModel.onReasonTextChanged("offline attempt")
        viewModel.submit()
        advanceUntilIdle()

        val phase = viewModel.state.value.phase as ReportUiState.Phase.Error
        assertEquals(ReportViewModel.OFFLINE_MESSAGE, phase.message)
        assertTrue(phase.retryable)
    }

    @Test
    fun messageTarget_kindIsMessage() {
        val viewModel = vm(ReportTarget.Message(id = "m1", conversationId = "c1"))
        assertEquals(ReportKind.MESSAGE, viewModel.state.value.kind)
    }

    // ---- fake ----

    private class FakeReportFlowRepository : ReportFlowRepository {
        data class Call(
            val target: ReportTarget,
            val topics: Set<ReportReason>,
            val reasonText: String,
        )

        val calls = mutableListOf<Call>()
        var result: ApiResult<ReportResult> = ApiResult.NetworkError(java.io.IOException("default"))
        var deferred: CompletableDeferred<ApiResult<ReportResult>>? = null

        override suspend fun submit(
            target: ReportTarget,
            topics: Set<ReportReason>,
            reasonText: String,
        ): ApiResult<ReportResult> {
            calls += Call(target, topics, reasonText)
            return deferred?.await() ?: result
        }
    }
}
