package com.testlogon.android.feature.health

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.BackendStatus
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class HealthBannerViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private class FakeMonitor(initial: BackendStatus) : BackendStatusMonitor {
        val flow = MutableStateFlow(initial)
        override val status get() = flow
    }

    @Test
    fun down_showsImmediately() = runTest(mainRule.dispatcher) {
        val monitor = FakeMonitor(BackendStatus.Unknown)
        val vm = HealthBannerViewModel(monitor)
        val job = launch { vm.uiState.collect {} }

        monitor.flow.value = BackendStatus.Down
        advanceUntilIdle()
        assertTrue(vm.uiState.value.visible)
        job.cancel()
    }

    @Test
    fun unknownAndUp_hidden() = runTest(mainRule.dispatcher) {
        val monitor = FakeMonitor(BackendStatus.Unknown)
        val vm = HealthBannerViewModel(monitor)
        val job = launch { vm.uiState.collect {} }

        advanceUntilIdle()
        assertFalse(vm.uiState.value.visible)

        monitor.flow.value = BackendStatus.Up
        advanceUntilIdle()
        assertFalse(vm.uiState.value.visible)
        job.cancel()
    }

    @Test
    fun recovery_hidesAfterSettleWindow() = runTest(mainRule.dispatcher) {
        val monitor = FakeMonitor(BackendStatus.Down)
        val vm = HealthBannerViewModel(monitor)
        val job = launch { vm.uiState.collect {} }
        advanceUntilIdle()
        assertTrue(vm.uiState.value.visible)

        monitor.flow.value = BackendStatus.Up
        advanceTimeBy(1_499)
        assertTrue("still visible before settle window elapses", vm.uiState.value.visible)
        advanceTimeBy(2)
        advanceUntilIdle()
        assertFalse(vm.uiState.value.visible)
        job.cancel()
    }

    @Test
    fun antiFlap_recoveryThenDownWithinWindow_staysVisible() = runTest(mainRule.dispatcher) {
        val monitor = FakeMonitor(BackendStatus.Down)
        val vm = HealthBannerViewModel(monitor)
        val job = launch { vm.uiState.collect {} }
        advanceUntilIdle()

        monitor.flow.value = BackendStatus.Up
        advanceTimeBy(800)
        monitor.flow.value = BackendStatus.Down
        advanceTimeBy(2_000)
        advanceUntilIdle()
        assertTrue(vm.uiState.value.visible)
        job.cancel()
    }
}
