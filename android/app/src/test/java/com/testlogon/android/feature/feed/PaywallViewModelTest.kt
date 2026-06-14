package com.testlogon.android.feature.feed

import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.paywall.PaywallRepository
import com.testlogon.android.data.paywall.UnlockOutcome
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

private class FakePaywallRepository(
    var outcome: UnlockOutcome = UnlockOutcome.Success("post_1"),
) : PaywallRepository {
    var unlockCalls = 0
    var gate: CompletableDeferred<Unit>? = null
    override fun isEntitled(postId: String): Flow<Boolean> = flowOf(false)
    override val entitledPostIds: Flow<Set<String>> = flowOf(emptySet())
    override suspend fun unlock(postId: String): UnlockOutcome {
        unlockCalls++
        gate?.await()
        return outcome
    }
    override suspend fun clearEntitlementsForCurrentUser() = Unit
}

/** AND-177 — [PaywallViewModel] state-machine tests. */
class PaywallViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    @Test
    fun unlock_success_transitionsToUnlocked() = runTest {
        val repo = FakePaywallRepository(UnlockOutcome.Success("post_1"))
        val vm = PaywallViewModel(repo)
        vm.unlock("post_1")
        advanceUntilIdle()
        assertEquals(UnlockState.Unlocked, vm.states.value["post_1"])
    }

    @Test
    fun unlock_paymentsUnavailable_surfacesStopAndFlagState() = runTest {
        val repo = FakePaywallRepository(UnlockOutcome.PaymentsUnavailable)
        val vm = PaywallViewModel(repo)
        vm.unlock("post_1")
        advanceUntilIdle()
        assertEquals(UnlockState.PaymentsUnavailable, vm.states.value["post_1"])
    }

    @Test
    fun unlock_alreadyEntitled_revealsAsUnlocked() = runTest {
        val vm = PaywallViewModel(FakePaywallRepository(UnlockOutcome.AlreadyEntitled))
        vm.unlock("post_1")
        advanceUntilIdle()
        assertEquals(UnlockState.Unlocked, vm.states.value["post_1"])
    }

    @Test
    fun unlock_failure_isRetryableFailedState() = runTest {
        val vm = PaywallViewModel(FakePaywallRepository(UnlockOutcome.Failure("declined", retryable = true)))
        vm.unlock("post_1")
        advanceUntilIdle()
        val s = vm.states.value["post_1"]
        assertTrue(s is UnlockState.Failed && s.retryable)
    }

    @Test
    fun unlock_doubleTapWhileInProgress_isNoOp() = runTest {
        val repo = FakePaywallRepository().apply { gate = CompletableDeferred() }
        val vm = PaywallViewModel(repo)
        vm.unlock("post_1")
        advanceUntilIdle()
        assertEquals(UnlockState.InProgress, vm.states.value["post_1"])
        vm.unlock("post_1") // ignored while InProgress
        repo.gate!!.complete(Unit)
        advanceUntilIdle()
        assertEquals(1, repo.unlockCalls)
        assertEquals(UnlockState.Unlocked, vm.states.value["post_1"])
    }
}
