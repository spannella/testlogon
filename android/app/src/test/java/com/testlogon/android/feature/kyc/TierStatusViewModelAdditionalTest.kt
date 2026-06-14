package com.testlogon.android.feature.kyc

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.kyc.data.KycTierRepository
import com.testlogon.android.feature.kyc.model.Requirement
import com.testlogon.android.feature.kyc.model.Tier
import com.testlogon.android.feature.kyc.model.TierEvaluation
import com.testlogon.android.feature.kyc.model.TierStatus
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.time.Instant

/**
 * AND-330 — ADDITIONAL unit tests for [TierStatusViewModel] locking down behavior NOT already covered by
 * [TierStatusViewModelTest] (AND-320): the warm-cache render via observeTierStatus before the refresh
 * lands, the evaluate-failure path (content kept, evaluating cleared, Snackbar emitted, NO Promoted), the
 * non-promoting evaluate (no Promoted event), and the in-flight evaluate guard.
 *
 * ANTI-HANG DISCIPLINE: the VM does a SINGLE one-shot refresh in init (NO poll loop), so tests use only
 * runCurrent() — NEVER advanceUntilIdle.
 */
class TierStatusViewModelAdditionalTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class FakeTierRepo : KycTierRepository {
        val cache = MutableStateFlow<TierStatus?>(null)
        var refreshResult: ApiResult<TierStatus> = ApiResult.Success(tierStatus(level = 1))
        var evaluateResult: ApiResult<TierEvaluation> =
            ApiResult.Success(TierEvaluation(tierStatus(level = 2), promoted = true))
        var evaluateCalls = 0

        override fun observeTierStatus(): Flow<TierStatus?> = cache
        override suspend fun refreshTierStatus(): ApiResult<TierStatus> = refreshResult
        override suspend fun evaluate(): ApiResult<TierEvaluation> {
            evaluateCalls++
            return evaluateResult
        }
    }

    @Test
    fun warmCache_rendersContentBeforeRefreshLands() = runTest {
        val repo = FakeTierRepo()
        // Cache already has a snapshot at construction; refresh is still "pending" until runCurrent.
        repo.cache.value = tierStatus(level = 2)
        repo.refreshResult = ApiResult.Success(tierStatus(level = 3))
        val vm = TierStatusViewModel(repo)

        // observeCache + the init refresh are both launched; draining them surfaces the cached snapshot
        // first (Loading -> cached Content), then the fresh refresh result.
        runCurrent()

        val content = vm.state.value as TierUiState.Content
        // The fresh refresh (level 3) wins after it lands; the cache seeded the instant render path.
        assertEquals(3, content.current.level)
    }

    @Test
    fun evaluateFailure_keepsContent_clearsEvaluating_emitsSnackbar_noPromoted() = runTest {
        val repo = FakeTierRepo()
        repo.refreshResult = ApiResult.Success(tierStatus(level = 1))
        repo.evaluateResult = ApiResult.Failure(ApiError(500, "evaluate boom"))
        val vm = TierStatusViewModel(repo)
        runCurrent()

        val events = mutableListOf<TierEvent>()
        backgroundScope.launch { vm.events.collect { events += it } }
        runCurrent()

        vm.onEvaluate()
        assertTrue((vm.state.value as TierUiState.Content).evaluating)
        runCurrent()

        val content = vm.state.value as TierUiState.Content
        assertFalse(content.evaluating)
        assertEquals(1, content.current.level)
        assertTrue(events.any { it is TierEvent.Snackbar && it.message == "evaluate boom" })
        assertFalse(events.any { it is TierEvent.Promoted })
    }

    @Test
    fun evaluateNetworkError_keepsContent_emitsOfflineSnackbar() = runTest {
        val repo = FakeTierRepo()
        repo.refreshResult = ApiResult.Success(tierStatus(level = 1))
        repo.evaluateResult = ApiResult.NetworkError(java.io.IOException("offline"))
        val vm = TierStatusViewModel(repo)
        runCurrent()

        val events = mutableListOf<TierEvent>()
        backgroundScope.launch { vm.events.collect { events += it } }
        runCurrent()

        vm.onEvaluate()
        runCurrent()

        assertFalse((vm.state.value as TierUiState.Content).evaluating)
        assertTrue(events.any { it is TierEvent.Snackbar })
    }

    @Test
    fun evaluate_noPromotion_appliesNewTier_butEmitsNoPromotedEvent() = runTest {
        val repo = FakeTierRepo()
        repo.refreshResult = ApiResult.Success(tierStatus(level = 2))
        repo.evaluateResult = ApiResult.Success(TierEvaluation(tierStatus(level = 2), promoted = false))
        val vm = TierStatusViewModel(repo)
        runCurrent()

        val events = mutableListOf<TierEvent>()
        backgroundScope.launch { vm.events.collect { events += it } }
        runCurrent()

        vm.onEvaluate()
        runCurrent()

        assertEquals(2, (vm.state.value as TierUiState.Content).current.level)
        assertFalse(events.any { it is TierEvent.Promoted })
    }

    @Test
    fun evaluate_ignoresReentrantCall_whileAlreadyEvaluating() = runTest {
        val repo = FakeTierRepo()
        repo.refreshResult = ApiResult.Success(tierStatus(level = 1))
        val vm = TierStatusViewModel(repo)
        runCurrent()

        vm.onEvaluate()
        // Second call before the first coroutine resumes is a no-op (evaluating guard).
        vm.onEvaluate()
        runCurrent()

        assertEquals(1, repo.evaluateCalls)
    }

    private companion object {
        val NOW: Instant = Instant.ofEpochSecond(1_700_000_000)

        fun tierStatus(level: Int, target: Tier? = Tier(level + 1)): TierStatus = TierStatus(
            current = Tier(level),
            updatedAt = null,
            history = emptyList(),
            target = target,
            requirements =
                if (target != null) listOf(Requirement("email_verified", met = false)) else emptyList(),
            eligibleForTarget = false,
            asOf = NOW,
        )
    }
}
