package com.testlogon.android.feature.kyc.cases

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.kyc.KycCaseStatus
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.kyc.cases.data.KycCaseRepository
import com.testlogon.android.feature.kyc.cases.model.KycCaseDetail
import com.testlogon.android.feature.kyc.cases.model.KycCaseSummary
import com.testlogon.android.feature.kyc.cases.model.MonitoringState
import com.testlogon.android.feature.kyc.cases.model.TimelineEvent
import com.testlogon.android.feature.kyc.cases.model.TimelineKind
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.time.Instant

/**
 * AND-329 - unit tests for [KycCaseDetailViewModel].
 *
 * ANTI-HANG DISCIPLINE: the VM has NO poll loop (manual refresh only). Tests use runCurrent() and NEVER
 * advanceUntilIdle. caseId is sourced from the SavedStateHandle nav arg. The fake repo's test-data builder
 * ([detail]) does NOT share a name with the repo overrides (no shadowing). No nested runTest.
 */
class KycCaseDetailViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class FakeRepo(
        var detailResult: ApiResult<KycCaseDetail>,
    ) : KycCaseRepository {
        override suspend fun cases(): ApiResult<List<KycCaseSummary>> =
            throw UnsupportedOperationException("not used in detail tests")

        override suspend fun caseDetail(caseId: String): ApiResult<KycCaseDetail> = detailResult

        override suspend fun monitoring(): ApiResult<MonitoringState> =
            throw UnsupportedOperationException("not used in detail tests")
    }

    private fun vm(repo: FakeRepo, caseId: String? = "case_1"): KycCaseDetailViewModel {
        val handle = SavedStateHandle().apply {
            if (caseId != null) set(KycCaseDetailViewModel.ARG_CASE_ID, caseId)
        }
        return KycCaseDetailViewModel(repo, handle)
    }

    @Test
    fun load_landsOnContent_withTimelineAndReasonCodes() = runTest {
        val repo = FakeRepo(detailResult = ApiResult.Success(detail()))
        val viewModel = vm(repo)
        runCurrent()

        val state = viewModel.uiState.value as KycCaseDetailUiState.Content
        assertEquals("case_1", state.case.caseId)
        assertEquals(2, state.timeline.size)
        assertEquals(listOf("doc_unreadable"), state.reasonCodes)
        assertFalse(state.isStale)
    }

    @Test
    fun blankCaseId_landsOnNonRetryableError() = runTest {
        val repo = FakeRepo(detailResult = ApiResult.Success(detail()))
        val viewModel = vm(repo, caseId = null)
        runCurrent()

        val state = viewModel.uiState.value as KycCaseDetailUiState.Error
        assertFalse(state.retryable)
    }

    @Test
    fun loadFailure_withNoPriorContent_landsOnError() = runTest {
        val repo = FakeRepo(detailResult = ApiResult.Failure(ApiError(404, "missing")))
        val viewModel = vm(repo)
        runCurrent()

        assertTrue(viewModel.uiState.value is KycCaseDetailUiState.Error)
    }

    @Test
    fun refreshFailure_withPriorContent_keepsContentStale() = runTest {
        val repo = FakeRepo(detailResult = ApiResult.Success(detail()))
        val viewModel = vm(repo)
        runCurrent()
        assertTrue(viewModel.uiState.value is KycCaseDetailUiState.Content)

        repo.detailResult = ApiResult.Failure(ApiError(422, "bad"))
        viewModel.refresh()
        runCurrent()

        val state = viewModel.uiState.value as KycCaseDetailUiState.Content
        assertTrue(state.isStale)
        assertEquals(2, state.timeline.size)
    }

    // ---- fake test-data builder (distinct name; never shadows a repo override) ----

    private companion object {
        fun detail() = KycCaseDetail(
            case = KycCaseSummary(
                caseId = "case_1",
                status = KycCaseStatus.REJECTED,
                createdAt = Instant.ofEpochSecond(1_000L),
                updatedAt = Instant.ofEpochSecond(2_000L),
            ),
            timeline = listOf(
                TimelineEvent(at = Instant.ofEpochSecond(1_000L), kind = TimelineKind.CREATED, label = "created"),
                TimelineEvent(at = Instant.ofEpochSecond(2_000L), kind = TimelineKind.CURRENT, label = "current"),
            ),
            reasonCodes = listOf("doc_unreadable"),
        )
    }
}
