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
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.time.Instant

/**
 * AND-329 - unit tests for [KycCaseListViewModel].
 *
 * ANTI-HANG DISCIPLINE: the VM has NO poll loop (manual refresh only). Tests use runCurrent() and NEVER
 * advanceUntilIdle. The fake repo's test-data builders ([summary]) do NOT share a name with the repo overrides
 * (no shadowing). No nested runTest.
 */
class KycCaseListViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class FakeRepo(
        var casesResult: ApiResult<List<KycCaseSummary>>,
        var monitoringResult: ApiResult<MonitoringState> = ApiResult.Success(MonitoringState.INACTIVE),
    ) : KycCaseRepository {
        override suspend fun cases(): ApiResult<List<KycCaseSummary>> = casesResult

        override suspend fun caseDetail(caseId: String): ApiResult<KycCaseDetail> =
            throw UnsupportedOperationException("not used in list tests")

        override suspend fun monitoring(): ApiResult<MonitoringState> = monitoringResult
    }

    private fun vm(repo: FakeRepo) = KycCaseListViewModel(repo, SavedStateHandle())

    @Test
    fun load_landsOnContent_sortedNewestFirst_withMonitoring() = runTest {
        val repo = FakeRepo(
            casesResult = ApiResult.Success(
                listOf(
                    summary("old", createdEpoch = 1_000L),
                    summary("new", createdEpoch = 3_000L),
                    summary("mid", createdEpoch = 2_000L),
                ),
            ),
            monitoringResult = ApiResult.Success(
                MonitoringState(
                    active = true,
                    status = "needs_review",
                    nextReviewDate = null,
                    graceDeadline = null,
                    caseId = "new",
                    message = "schedule:needs_review",
                ),
            ),
        )
        val viewModel = vm(repo)
        runCurrent()

        val state = viewModel.uiState.value as KycCaseListUiState.Content
        assertEquals(listOf("new", "mid", "old"), state.cases.map { it.caseId })
        assertTrue(state.monitoring.active)
        assertFalse(state.isStale)
    }

    @Test
    fun load_noCases_landsOnEmpty_withMonitoring() = runTest {
        val repo = FakeRepo(casesResult = ApiResult.Success(emptyList()))
        val viewModel = vm(repo)
        runCurrent()

        val state = viewModel.uiState.value as KycCaseListUiState.Empty
        assertFalse(state.monitoring.active)
    }

    @Test
    fun monitoringFailure_doesNotFailScreen_listStillRenders() = runTest {
        val repo = FakeRepo(
            casesResult = ApiResult.Success(listOf(summary("c1", createdEpoch = 1_000L))),
            monitoringResult = ApiResult.Failure(ApiError(422, "bad")),
        )
        val viewModel = vm(repo)
        runCurrent()

        val state = viewModel.uiState.value as KycCaseListUiState.Content
        assertFalse(state.monitoring.active)
        assertEquals(1, state.cases.size)
    }

    @Test
    fun loadFailure_withNoPriorContent_landsOnError() = runTest {
        val repo = FakeRepo(casesResult = ApiResult.Failure(ApiError(500, "boom")))
        val viewModel = vm(repo)
        runCurrent()

        val state = viewModel.uiState.value as KycCaseListUiState.Error
        assertTrue(state.retryable)
    }

    @Test
    fun refreshFailure_withPriorContent_keepsContentStale() = runTest {
        val repo = FakeRepo(casesResult = ApiResult.Success(listOf(summary("c1", createdEpoch = 1_000L))))
        val viewModel = vm(repo)
        runCurrent()
        assertTrue(viewModel.uiState.value is KycCaseListUiState.Content)

        repo.casesResult = ApiResult.Failure(ApiError(422, "bad"))
        viewModel.refresh()
        runCurrent()

        val state = viewModel.uiState.value as KycCaseListUiState.Content
        assertTrue(state.isStale)
        assertEquals(1, state.cases.size)
    }

    // ---- fake test-data builders (distinct names; never shadow a repo override) ----

    private companion object {
        fun summary(id: String, createdEpoch: Long) = KycCaseSummary(
            caseId = id,
            status = KycCaseStatus.SUBMITTED,
            createdAt = Instant.ofEpochSecond(createdEpoch),
            updatedAt = Instant.ofEpochSecond(createdEpoch + 100L),
        )
    }
}
