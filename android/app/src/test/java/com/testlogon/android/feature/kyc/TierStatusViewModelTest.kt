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
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.time.Instant

/**
 * AND-320 — unit tests for [TierStatusViewModel].
 *
 * ANTI-HANG DISCIPLINE: the VM does a SINGLE one-shot refresh in init (NO poll loop), so tests use only
 * runCurrent() — NEVER advanceUntilIdle.
 */
class TierStatusViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class FakeRepo : KycTierRepository {
        val cache = MutableStateFlow<TierStatus?>(null)
        var refreshResult: ApiResult<TierStatus> = ApiResult.Success(status(level = 1))
        var evaluateResult: ApiResult<TierEvaluation> =
            ApiResult.Success(TierEvaluation(status(level = 2), promoted = true))
        var refreshCalls = 0
        var evaluateCalls = 0

        override fun observeTierStatus(): Flow<TierStatus?> = cache
        override suspend fun refreshTierStatus(): ApiResult<TierStatus> {
            refreshCalls++
            return refreshResult
        }
        override suspend fun evaluate(): ApiResult<TierEvaluation> {
            evaluateCalls++
            return evaluateResult
        }
    }

    @Test
    fun init_loadingThenContent() = runTest {
        val repo = FakeRepo()
        repo.refreshResult = ApiResult.Success(status(level = 1))
        val vm = TierStatusViewModel(repo)

        // Before the launched refresh runs.
        assertTrue(vm.state.value is TierUiState.Loading)

        runCurrent()

        val content = vm.state.value as TierUiState.Content
        assertEquals(1, content.current.level)
        assertEquals(2, content.target?.level)
        assertFalse(content.refreshing)
    }

    @Test
    fun evaluate_setsEvaluating_thenAppliesNewTier_andEmitsPromoted() = runTest {
        val repo = FakeRepo()
        repo.refreshResult = ApiResult.Success(status(level = 1))
        repo.evaluateResult = ApiResult.Success(TierEvaluation(status(level = 2), promoted = true))
        val vm = TierStatusViewModel(repo)
        runCurrent()

        val emitted = mutableListOf<TierEvent>()
        backgroundScope.launch { vm.events.collect { emitted += it } }
        runCurrent()

        vm.onEvaluate()
        // Synchronously flips evaluating=true before the coroutine resumes.
        assertTrue((vm.state.value as TierUiState.Content).evaluating)

        runCurrent()

        val content = vm.state.value as TierUiState.Content
        assertEquals(2, content.current.level)
        assertFalse(content.evaluating)
        assertEquals(1, repo.evaluateCalls)
        assertTrue(emitted.any { it is TierEvent.Promoted && it.toTierLevel == 2 })
    }

    @Test
    fun refreshFailure_withWarmCache_keepsStaleContent_notError() = runTest {
        val repo = FakeRepo()
        repo.refreshResult = ApiResult.Success(status(level = 1))
        val vm = TierStatusViewModel(repo)
        runCurrent()
        assertTrue(vm.state.value is TierUiState.Content)

        // A subsequent refresh fails; warm content must survive as stale.
        repo.refreshResult = ApiResult.Failure(ApiError(500, "boom"))
        vm.refresh()
        runCurrent()

        val content = vm.state.value as TierUiState.Content
        assertTrue(content.stale)
        assertEquals("boom", content.inlineError)
        assertEquals(1, content.current.level)
    }

    @Test
    fun refreshFailure_cold_dropsToError() = runTest {
        val repo = FakeRepo()
        repo.refreshResult = ApiResult.Failure(ApiError(500, "cold boom"))
        val vm = TierStatusViewModel(repo)
        runCurrent()

        val error = vm.state.value as TierUiState.Error
        assertEquals("cold boom", error.message)
        assertTrue(error.canRetry)
    }

    @Test
    fun maxTier_contentHasNoTarget() = runTest {
        val repo = FakeRepo()
        repo.refreshResult = ApiResult.Success(status(level = 4, target = null))
        val vm = TierStatusViewModel(repo)
        runCurrent()

        val content = vm.state.value as TierUiState.Content
        assertTrue(content.isMaxTier)
        assertNull(content.target)
    }

    private companion object {
        val NOW: Instant = Instant.ofEpochSecond(1_700_000_000)

        fun status(level: Int, target: Tier? = Tier(level + 1)): TierStatus = TierStatus(
            current = Tier(level),
            updatedAt = null,
            history = emptyList(),
            target = target,
            requirements = if (target != null) listOf(Requirement("email_verified", met = false)) else emptyList(),
            eligibleForTarget = false,
            asOf = NOW,
        )
    }
}
