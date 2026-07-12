package com.testlogon.android.feature.boost

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.BoostCancelResult
import com.testlogon.android.core.model.ads.BoostSpend
import com.testlogon.android.core.model.ads.BoostStatus
import com.testlogon.android.core.model.ads.ContentBoost
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.boost.data.BoostRepository
import com.testlogon.android.feature.boost.data.BoostStatusCache
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-364 - unit tests for [BoostViewModel]. Uses MainDispatcherRule + runCurrent (NEVER advanceUntilIdle).
 * The fake repository returns canned outcomes + records calls; the fake cache is an in-memory map. The
 * BOUNDED status poll is exercised with advanceTimeBy and ALWAYS reaches a non-active status (cancelling
 * the poll) before the test finishes, so runTest's end-of-test drain never spins the parked delay loop.
 */
class BoostViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    /** Fake repository: canned outcomes + a record of create args + the get/cancel call counts. */
    private class FakeBoostRepo : BoostRepository {
        var createOutcome: ApiResult<ContentBoost> = ApiResult.Success(activeBoost())
        var getOutcomes: ArrayDeque<ApiResult<ContentBoost>> = ArrayDeque()
        var cancelOutcome: ApiResult<BoostCancelResult> =
            ApiResult.Success(BoostCancelResult(boostId = BOOST_ID, status = "cancelled", refundedCents = 250L))

        var createBudgetCents: Long? = null
        var createDurationSeconds: Long? = null
        var createContentType: String? = null
        var createContentId: String? = null
        var getCount = 0
        var cancelCount = 0

        override suspend fun createBoost(
            contentType: String,
            contentId: String,
            budgetCents: Long,
            durationSeconds: Long,
        ): ApiResult<ContentBoost> {
            createContentType = contentType
            createContentId = contentId
            createBudgetCents = budgetCents
            createDurationSeconds = durationSeconds
            return createOutcome
        }

        override suspend fun getBoost(boostId: String): ApiResult<ContentBoost> {
            getCount++
            return if (getOutcomes.isNotEmpty()) getOutcomes.removeFirst() else ApiResult.Success(completedBoost())
        }

        override suspend fun getSpend(boostId: String): ApiResult<BoostSpend> =
            ApiResult.Success(BoostSpend(spentCents = 100L, remainingCents = 400L))

        override suspend fun listBoosts(): ApiResult<List<ContentBoost>> =
            ApiResult.Success(emptyList())

        override suspend fun cancelBoost(boostId: String): ApiResult<BoostCancelResult> {
            cancelCount++
            return cancelOutcome
        }
    }

    /** In-memory fake cache. */
    private class FakeCache(private val seed: ContentBoost? = null) : BoostStatusCache {
        val stored = linkedMapOf<String, ContentBoost>()
        override suspend fun put(postId: String, boost: ContentBoost) {
            stored[postId] = boost
        }
        override suspend fun get(postId: String): ContentBoost? = stored[postId] ?: seed
    }

    private fun vm(
        repo: BoostRepository = FakeBoostRepo(),
        cache: BoostStatusCache = FakeCache(),
        postId: String? = POST_ID,
    ): BoostViewModel {
        val saved = SavedStateHandle(
            if (postId != null) mapOf(BoostViewModel.ARG_POST_ID to postId) else emptyMap(),
        )
        return BoostViewModel(repo, cache, saved).also {
            it.pollIntervalMillis = 1_000L
            it.maxPollTicks = 3
        }
    }

    // ---- load ----

    @Test
    fun load_withoutCache_showsFormWithDefaults() = runTest {
        val vm = vm()
        runCurrent()
        val state = vm.uiState.value
        assertTrue(state is BoostUiState.Form)
        state as BoostUiState.Form
        assertEquals(BoostViewModel.DEFAULT_BUDGET_TEXT, state.budgetText)
        assertEquals(500L, state.budgetCents) // $5.00
        assertEquals(3600L, state.durationSeconds) // 60 min
        assertTrue(state.canSubmit)
    }

    @Test
    fun load_withCache_showsStatus() = runTest {
        // Cache returns a non-active boost so no poll is armed.
        val vm = vm(cache = FakeCache(seed = completedBoost()))
        runCurrent()
        val state = vm.uiState.value
        assertTrue(state is BoostUiState.Status)
        assertEquals(BoostStatus.COMPLETED, (state as BoostUiState.Status).boost.statusEnum)
        assertFalse(state.canCancel)
    }

    // ---- canSubmit gating ----

    @Test
    fun canSubmit_disabledForBudgetBelowOne() = runTest {
        val vm = vm()
        runCurrent()
        vm.onBudgetChanged("0")
        runCurrent()
        val state = vm.uiState.value as BoostUiState.Form
        assertEquals(0L, state.budgetCents)
        assertFalse(state.canSubmit)
    }

    @Test
    fun canSubmit_disabledForDurationBelowOne() = runTest {
        val vm = vm()
        runCurrent()
        vm.onDurationChanged("0")
        runCurrent()
        val state = vm.uiState.value as BoostUiState.Form
        assertEquals(0L, state.durationSeconds)
        assertFalse(state.canSubmit)
    }

    @Test
    fun canSubmit_disabledForEmptyContent() = runTest {
        val vm = vm(postId = null)
        runCurrent()
        // No post id -> Error, never a submittable form.
        assertTrue(vm.uiState.value is BoostUiState.Error)
    }

    // ---- submit ----

    @Test
    fun submit_createsBoost_movesToStatus_andCaches() = runTest {
        val repo = FakeBoostRepo().apply {
            // create returns a completed boost so no poll is armed after submit.
            createOutcome = ApiResult.Success(completedBoost())
        }
        val cache = FakeCache()
        val vm = vm(repo = repo, cache = cache)
        runCurrent()

        vm.onBudgetChanged("10.00")
        vm.onDurationChanged("30")
        runCurrent()
        vm.submit()
        runCurrent()

        assertEquals("post", repo.createContentType)
        assertEquals(POST_ID, repo.createContentId)
        assertEquals(1000L, repo.createBudgetCents)
        assertEquals(1800L, repo.createDurationSeconds)
        assertTrue(vm.uiState.value is BoostUiState.Status)
        assertEquals(completedBoost().boostId, cache.stored[POST_ID]?.boostId)
    }

    @Test
    fun submit_failure_staysOnForm_withError() = runTest {
        val repo = FakeBoostRepo().apply { createOutcome = ApiResult.Failure(ApiError(402, "insufficient funds")) }
        val vm = vm(repo = repo)
        runCurrent()
        vm.submit()
        runCurrent()
        val state = vm.uiState.value
        assertTrue(state is BoostUiState.Form)
        assertEquals("insufficient funds", (state as BoostUiState.Form).error)
        assertFalse(state.submitting)
    }

    // ---- cancel (active only) ----

    @Test
    fun cancel_active_reloadsToCancelledStatus() = runTest {
        val repo = FakeBoostRepo().apply {
            // After cancel the VM re-reads; return a cancelled boost (non-active -> poll stops).
            getOutcomes.addLast(ApiResult.Success(cancelledBoost()))
        }
        // Seed cache with an active boost; the immediate poll tick (if any) will be drained below.
        val vm = vm(repo = repo, cache = FakeCache(seed = activeBoost()))
        runCurrent()
        assertTrue((vm.uiState.value as BoostUiState.Status).canCancel)

        vm.cancel()
        runCurrent()

        assertEquals(1, repo.cancelCount)
        val state = vm.uiState.value as BoostUiState.Status
        assertEquals(BoostStatus.CANCELLED, state.boost.statusEnum)
        assertFalse(state.canCancel)
    }

    // ---- bounded poll ----

    @Test
    fun poll_stopsWhenStatusLeavesActive_callCountBounded() = runTest {
        val repo = FakeBoostRepo().apply {
            // First poll tick: still active. Second tick: completed -> poll must stop.
            getOutcomes.addLast(ApiResult.Success(activeBoost()))
            getOutcomes.addLast(ApiResult.Success(completedBoost()))
        }
        val vm = vm(repo = repo, cache = FakeCache(seed = activeBoost()))
        runCurrent()
        assertTrue((vm.uiState.value as BoostUiState.Status).boost.statusEnum.isActive)

        // Drive a few intervals; once completed is read the poll returns and never spins again.
        advanceTimeBy(1_000)
        runCurrent()
        advanceTimeBy(1_000)
        runCurrent()
        // Extra time must NOT keep calling get (poll already stopped at completed).
        advanceTimeBy(5_000)
        runCurrent()

        assertFalse((vm.uiState.value as BoostUiState.Status).boost.statusEnum.isActive)
        // 2 ticks read (active then completed); the guard prevents further reads.
        assertEquals(2, repo.getCount)
    }

    private companion object {
        const val POST_ID = "post_9"
        const val BOOST_ID = "bst_1"

        fun activeBoost() = ContentBoost(
            boostId = BOOST_ID,
            status = "active",
            statusEnum = BoostStatus.ACTIVE,
            budgetCents = 500L,
            spentCents = 0L,
            remainingCents = 500L,
            durationSeconds = 3600L,
            endsAt = 1700003600L,
        )

        fun completedBoost() = activeBoost().copy(status = "completed", statusEnum = BoostStatus.COMPLETED)

        fun cancelledBoost() = activeBoost().copy(status = "cancelled", statusEnum = BoostStatus.CANCELLED)
    }
}
