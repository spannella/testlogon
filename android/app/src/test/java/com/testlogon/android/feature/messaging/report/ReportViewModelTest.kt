package com.testlogon.android.feature.messaging.report

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.report.Report
import com.testlogon.android.data.messaging.report.ReportReason
import com.testlogon.android.data.messaging.report.ReportRepository
import com.testlogon.android.data.messaging.report.ReportStatus
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class ReportViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeReportRepository()

    private fun vm() = ReportViewModel(repo).apply { open("c1", "m1") }

    @Test
    fun submitDisabled_untilReasonAndStatementMin() {
        val viewModel = vm()
        assertFalse(viewModel.uiState.value.canSubmit) // nothing selected, empty statement

        viewModel.onReasonSelected(ReportReason.SEXUAL)
        assertFalse(viewModel.uiState.value.canSubmit) // reason but no statement

        viewModel.onStatementChanged("abcd") // 4 chars < 5
        assertFalse(viewModel.uiState.value.canSubmit)

        viewModel.onStatementChanged("abcde") // exactly 5
        assertTrue(viewModel.uiState.value.canSubmit)
    }

    @Test
    fun statement_cappedAt2000() {
        val viewModel = vm()
        viewModel.onStatementChanged("x".repeat(2500))
        assertEquals(2000, viewModel.uiState.value.statementLength)
    }

    @Test
    fun submit_success_callsRepoWithChosenReasonAndText_dismissesAndEmitsEvent() = runTest {
        repo.result = ApiResult.Success(
            Report("rpt", "c1", "m1", "sexual", ReportStatus.SUBMITTED, 1),
        )
        val viewModel = vm()
        viewModel.onReasonSelected(ReportReason.SEXUAL)
        viewModel.onStatementChanged("ten chars+")

        viewModel.submit()
        advanceUntilIdle()

        val call = repo.calls.single()
        assertEquals("c1", call.conversationId)
        assertEquals("m1", call.messageId)
        assertEquals(ReportReason.SEXUAL, call.reason)
        assertEquals("ten chars+", call.statement)
        // Sheet dismissed on success.
        assertFalse(viewModel.uiState.value.visible)
        // One-shot confirmation event emitted.
        assertEquals(ReportEvent.Submitted, viewModel.events.first())
    }

    @Test
    fun submit_isSubmittingFlipsTrueThenClears() = runTest {
        repo.result = ApiResult.Success(Report("rpt", "c1", "m1", "spam", ReportStatus.SUBMITTED, 1))
        val viewModel = vm()
        viewModel.onReasonSelected(ReportReason.SPAM)
        viewModel.onStatementChanged("spammy text")
        viewModel.submit() // dispatched but not yet run (StandardTestDispatcher)
        assertTrue(viewModel.uiState.value.isSubmitting)
        advanceUntilIdle()
        assertFalse(viewModel.uiState.value.isSubmitting) // reset (sheet closed)
    }

    @Test
    fun submit_failure_surfacesErrorMessage_keepsSheetOpen() = runTest {
        repo.result = ApiResult.Failure(ApiError(429, "rate limited", code = "rate_limited"))
        val viewModel = vm()
        viewModel.onReasonSelected(ReportReason.SPAM)
        viewModel.onStatementChanged("spammy text")
        viewModel.submit()
        advanceUntilIdle()

        val s = viewModel.uiState.value
        assertTrue(s.visible)
        assertFalse(s.isSubmitting)
        assertEquals("rate limited", s.error)
    }

    @Test
    fun submit_networkError_showsOfflineMessage() = runTest {
        repo.result = ApiResult.NetworkError(java.io.IOException("down"))
        val viewModel = vm()
        viewModel.onReasonSelected(ReportReason.CRIMINAL)
        viewModel.onStatementChanged("illegal stuff")
        viewModel.submit()
        advanceUntilIdle()
        assertEquals(ReportViewModel.OFFLINE_MESSAGE, viewModel.uiState.value.error)
    }

    @Test
    fun dismiss_discardsDraft() {
        val viewModel = vm()
        viewModel.onReasonSelected(ReportReason.SPAM)
        viewModel.onStatementChanged("draft text")
        viewModel.dismiss()
        val s = viewModel.uiState.value
        assertFalse(s.visible)
        assertNull(s.selectedReason)
        assertEquals("", s.statement)
    }

    // ---- fake ----

    private class FakeReportRepository : ReportRepository {
        data class Call(
            val conversationId: String,
            val messageId: String,
            val reason: ReportReason,
            val statement: String,
        )

        val calls = mutableListOf<Call>()
        var result: ApiResult<Report> = ApiResult.NetworkError(java.io.IOException("default"))
        private val statuses = MutableStateFlow<Map<String, ReportStatus>>(emptyMap())

        override suspend fun reportMessage(
            conversationId: String,
            messageId: String,
            reason: ReportReason,
            statement: String,
        ): ApiResult<Report> {
            calls += Call(conversationId, messageId, reason, statement)
            return result
        }

        override fun observeStatus(messageId: String): Flow<ReportStatus> =
            statuses.map { it[messageId] ?: ReportStatus.NONE }
    }
}
