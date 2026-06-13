package com.testlogon.android.feature.kyc.screening

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.kyc.screening.data.ScreeningRepository
import com.testlogon.android.feature.kyc.screening.model.KycScreenResult
import com.testlogon.android.feature.kyc.screening.model.KycScreenType
import com.testlogon.android.feature.kyc.screening.model.KycScreeningResult
import com.testlogon.android.feature.kyc.screening.model.ScreeningStatus
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.time.Instant

/**
 * AND-328 - unit tests for [ScreeningViewModel].
 *
 * ANTI-HANG DISCIPLINE: the VM has NO poll loop — only a SINGLE bounded one-shot re-poll. Tests use
 * runCurrent() plus, for the one-shot, a tiny bounded advanceTimeBy then assert — NEVER advanceUntilIdle.
 * Helper funcs that call runCurrent are [TestScope] extensions; no nested runTest. The fake repo serves a
 * queue of results and counts calls; its test-data builders ([result] / [resultList]) do NOT share a name
 * with the repo override [ScreeningRepository.screening] (no shadowing).
 */
class ScreeningViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class FakeRepo : ScreeningRepository {
        val results: ArrayDeque<ApiResult<List<KycScreeningResult>>> = ArrayDeque()
        var calls = 0
        private var cached: List<KycScreeningResult>? = null

        override suspend fun screening(caseId: String?): ApiResult<List<KycScreeningResult>> {
            calls++
            val next = if (results.isEmpty()) ApiResult.Success(emptyList()) else results.removeFirst()
            if (next is ApiResult.Success) cached = next.data
            return next
        }

        override fun lastKnown(): List<KycScreeningResult>? = cached
    }

    private fun vm(repo: FakeRepo, caseId: String? = "case_1"): ScreeningViewModel {
        val handle = SavedStateHandle().apply {
            if (caseId != null) set(ScreeningViewModel.ARG_CASE_ID, caseId)
        }
        return ScreeningViewModel(repo, handle).apply { rePollDelayMs = 10L }
    }

    @Test
    fun load_aggregatesToContent_withStatus() = runTest {
        val repo = FakeRepo().apply {
            results.add(
                ApiResult.Success(
                    listOf(
                        result(KycScreenResult.CLEAR, KycScreenType.SANCTIONS_OFAC),
                        result(KycScreenResult.CONFIRMED_MATCH, KycScreenType.PEP_CHECK),
                    ),
                ),
            )
        }
        val viewModel = vm(repo)
        runCurrent()

        val state = viewModel.uiState.value as ScreeningUiState.Content
        assertEquals(ScreeningStatus.HIT, state.status)
        assertEquals(2, state.results.size)
        assertFalse(state.isStale)
    }

    @Test
    fun noCase_emptyResults_landsOnNotStarted() = runTest {
        val repo = FakeRepo().apply { results.add(ApiResult.Success(emptyList())) }
        // No case id -> repository returns Success(emptyList) -> NOT_STARTED.
        val viewModel = vm(repo, caseId = null)
        runCurrent()

        val state = viewModel.uiState.value as ScreeningUiState.Content
        assertEquals(ScreeningStatus.NOT_STARTED, state.status)
    }

    @Test
    fun refreshFailure_withPriorContent_keepsContentStale() = runTest {
        val repo = FakeRepo().apply {
            results.add(ApiResult.Success(resultList(KycScreenResult.CLEAR)))
            results.add(ApiResult.Failure(ApiError(422, "bad")))
        }
        val viewModel = vm(repo)
        runCurrent()
        assertTrue(viewModel.uiState.value is ScreeningUiState.Content)

        viewModel.refresh()
        runCurrent()

        val state = viewModel.uiState.value as ScreeningUiState.Content
        assertTrue(state.isStale)
        assertEquals(ScreeningStatus.CLEAR, state.status)
    }

    @Test
    fun loadFailure_withNoPriorContent_landsOnError() = runTest {
        val repo = FakeRepo().apply { results.add(ApiResult.Failure(ApiError(422, "bad"))) }
        val viewModel = vm(repo)
        runCurrent()

        val state = viewModel.uiState.value as ScreeningUiState.Error
        assertTrue(state.retryable)
    }

    @Test
    fun reviewStatus_firesSingleBoundedRepoll_thenStops() = runTest {
        val repo = FakeRepo().apply {
            results.add(ApiResult.Success(resultList(KycScreenResult.POTENTIAL_MATCH)))
            results.add(ApiResult.Success(resultList(KycScreenResult.CLEAR)))
        }
        val viewModel = vm(repo)
        runCurrent()
        assertEquals(1, repo.calls) // initial load only.

        // Bounded advance past the one-shot delay (10ms): exactly ONE extra re-poll, never a loop.
        advanceTimeBy(50L)
        runCurrent()

        assertEquals(2, repo.calls)
        val state = viewModel.uiState.value as ScreeningUiState.Content
        assertEquals(ScreeningStatus.CLEAR, state.status)

        // No further re-poll is ever scheduled (the second result was CLEAR, and the guard blocks re-arming).
        advanceTimeBy(50L)
        runCurrent()
        assertEquals(2, repo.calls)
    }

    @Test
    fun clearStatus_doesNotRepoll() = runTest {
        val repo = FakeRepo().apply {
            results.add(ApiResult.Success(resultList(KycScreenResult.CLEAR)))
        }
        val viewModel = vm(repo)
        runCurrent()

        advanceTimeBy(50L)
        runCurrent()
        assertEquals(1, repo.calls) // CLEAR is terminal -> no re-poll.
    }

    // ---- fake test-data builders (distinct names; never shadow the repo override) ----

    private companion object {
        fun result(
            res: KycScreenResult,
            type: KycScreenType,
            screenedEpoch: Long = 1_780_000_000L,
        ) = KycScreeningResult(
            result = res,
            screenType = type,
            screenedAt = Instant.ofEpochSecond(screenedEpoch),
            matchCount = null,
        )

        fun resultList(res: KycScreenResult) =
            listOf(result(res, KycScreenType.SANCTIONS_OFAC))
    }
}
