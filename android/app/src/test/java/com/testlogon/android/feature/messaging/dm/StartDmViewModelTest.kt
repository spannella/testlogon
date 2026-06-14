package com.testlogon.android.feature.messaging.dm

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.Conversation
import com.testlogon.android.feature.messaging.FakeMessagingRepository
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import java.io.IOException

@OptIn(ExperimentalCoroutinesApi::class)
class StartDmViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeMessagingRepository()

    private fun vm() = StartDmViewModel(repo)

    private fun conv(id: String) = Conversation(
        id = id, title = "Ada", iconUrl = null, lastMessagePreview = null,
        lastActivityEpochSeconds = 1, unreadCount = 0,
    )

    @Test
    fun success_emitsOpenThreadEffect_once() = runTest {
        repo.findOrCreateDmResult = ApiResult.Success(conv("conv_1"))
        val vm = vm()
        val effects = mutableListOf<StartDmEffect>()
        val job = launch { vm.effects.collect { effects += it } }

        vm.startDm("usr_peer")
        advanceUntilIdle()

        assertEquals(listOf("usr_peer"), repo.findOrCreateDmCalls)
        assertEquals(1, effects.size)
        assertEquals(StartDmEffect.OpenThread("conv_1"), effects.single())
        assertNull(vm.state.value.errorMessage)
        assertEquals(false, vm.state.value.inFlight)
        job.cancel()
    }

    @Test
    fun failure_setsError_emitsNoEffect() = runTest {
        repo.findOrCreateDmResult = FakeMessagingRepository.failure(404, "not found")
        val vm = vm()
        val effects = mutableListOf<StartDmEffect>()
        val job = launch { vm.effects.collect { effects += it } }

        vm.startDm("usr_peer")
        advanceUntilIdle()

        assertEquals(0, effects.size)
        assertNotNull(vm.state.value.errorMessage)
        assertEquals(false, vm.state.value.inFlight)
        // consumeError clears it.
        vm.consumeError()
        assertNull(vm.state.value.errorMessage)
        job.cancel()
    }

    @Test
    fun networkError_setsOfflineError() = runTest {
        repo.findOrCreateDmResult = ApiResult.NetworkError(IOException("x"), isTimeout = true)
        val vm = vm()
        vm.startDm("usr_peer")
        advanceUntilIdle()
        assertNotNull(vm.state.value.errorMessage)
    }

    @Test
    fun rapidDoubleTap_isDebounced_singleRequest() = runTest {
        // Suspend the result so the first call is still in flight during the second tap.
        repo.findOrCreateDmResult = ApiResult.Success(conv("conv_1"))
        val vm = vm()
        val effects = mutableListOf<StartDmEffect>()
        val job = launch { vm.effects.collect { effects += it } }

        vm.startDm("usr_peer")
        vm.startDm("usr_peer") // ignored while inFlight (FR-4)
        advanceUntilIdle()

        assertEquals(1, repo.findOrCreateDmCalls.size)
        assertEquals(1, effects.size)
        job.cancel()
    }
}
