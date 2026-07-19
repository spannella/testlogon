package com.testlogon.android.feature.feed

import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.tip.TipConfig
import com.testlogon.android.data.tip.TipOutcome
import com.testlogon.android.data.tip.TipReceipt
import com.testlogon.android.data.tip.TipRepository
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

private class FakeTipRepository(
    var outcome: TipOutcome = TipOutcome.Success(TipReceipt("post_1", 1000, 1000)),
) : TipRepository {
    val calls = mutableListOf<Pair<String, Int>>()
    var gate: CompletableDeferred<Unit>? = null
    var reactOutcome: com.testlogon.android.data.tip.TipReactOutcome =
        com.testlogon.android.data.tip.TipReactOutcome.Failure("not exercised")
    val reactCalls = mutableListOf<Triple<String, Int, String>>()
    override suspend fun tip(postId: String, amountCents: Int): TipOutcome {
        calls += postId to amountCents
        gate?.await()
        return outcome
    }
    override suspend fun tipReact(
        postId: String,
        amountCents: Int,
        emoji: String,
    ): com.testlogon.android.data.tip.TipReactOutcome {
        reactCalls += Triple(postId, amountCents, emoji)
        gate?.await()
        return reactOutcome
    }
    override fun config(): TipConfig = TipConfig()
}

/** AND-178 — [TipViewModel] state machine + submit-lock tests. */
class TipViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    @Test
    fun open_selectPreset_enablesSend() = runTest {
        val vm = TipViewModel(FakeTipRepository())
        vm.open("post_1")
        vm.selectPreset(500)
        val s = vm.state.value as TipSheetState.Entry
        assertEquals(500, s.effectiveCents)
        assertTrue(s.canSend)
    }

    @Test
    fun customAmount_parsesDollarsToCents() = runTest {
        val vm = TipViewModel(FakeTipRepository())
        vm.open("post_1")
        vm.setCustomAmount("5.50")
        assertEquals(550, (vm.state.value as TipSheetState.Entry).effectiveCents)
    }

    @Test
    fun emptyCustomAmount_disablesSend() = runTest {
        val vm = TipViewModel(FakeTipRepository())
        vm.open("post_1")
        vm.setCustomAmount("")
        assertFalse((vm.state.value as TipSheetState.Entry).canSend)
    }

    @Test
    fun send_success_confirmsAndEmitsSnackbar() = runTest {
        val vm = TipViewModel(FakeTipRepository(TipOutcome.Success(TipReceipt("post_1", 1000, 5000))))
        val effects = mutableListOf<TipEffect>()
        val collector = launch(UnconfinedTestDispatcher(testScheduler)) { vm.effects.collect { effects += it } }

        vm.open("post_1")
        vm.selectPreset(1000)
        vm.send()
        advanceUntilIdle()

        assertTrue(vm.state.value is TipSheetState.Confirmed)
        assertTrue(effects.any { it is TipEffect.ShowSnackbar })
        collector.cancel()
    }

    @Test
    fun send_doubleTapWhileSubmitting_issuesOneCall() = runTest {
        val repo = FakeTipRepository().apply { gate = CompletableDeferred() }
        val vm = TipViewModel(repo)
        vm.open("post_1")
        vm.selectPreset(1000)
        vm.send()
        advanceUntilIdle()
        assertTrue(vm.state.value is TipSheetState.Submitting)
        vm.send() // ignored while Submitting
        repo.gate!!.complete(Unit)
        advanceUntilIdle()
        assertEquals(1, repo.calls.size)
    }

    @Test
    fun send_paymentsUnavailable_returnsToEntryWithError() = runTest {
        val vm = TipViewModel(FakeTipRepository(TipOutcome.PaymentsUnavailable))
        vm.open("post_1")
        vm.selectPreset(1000)
        vm.send()
        advanceUntilIdle()
        val s = vm.state.value as TipSheetState.Entry
        assertTrue(s.error != null)
    }

    @Test
    fun dismissDuringSubmitting_isIgnored() = runTest {
        val repo = FakeTipRepository().apply { gate = CompletableDeferred() }
        val vm = TipViewModel(repo)
        vm.open("post_1")
        vm.selectPreset(1000)
        vm.send()
        advanceUntilIdle()
        vm.dismiss() // blocked during Submitting
        assertTrue(vm.state.value is TipSheetState.Submitting)
        repo.gate!!.complete(Unit)
        advanceUntilIdle()
    }
}
