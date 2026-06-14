package com.testlogon.android.feature.fanclub

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.testing.MainDispatcherRule
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** AND-238 — [ChannelsViewModel] state transitions + one-shot effects. */
class ChannelsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun handle() = SavedStateHandle(mapOf(ChannelsViewModel.ARG_CREATOR_ID to "creator_1"))

    @Test
    fun success_emitsContent() = runTest {
        val repo = FakeFanClubRepository(
            channelsResult = FakeFanClubRepository.success(
                listOf(FakeFanClubRepository.section(0, true, listOf(FakeFanClubRepository.channel("c1")))),
            ),
        )
        val vm = ChannelsViewModel(handle(), repo)
        advanceUntilIdle()
        assertTrue(vm.uiState.value is ChannelsUiState.Content)
    }

    @Test
    fun emptySections_emitEmpty_notError() = runTest {
        val repo = FakeFanClubRepository(channelsResult = FakeFanClubRepository.success(emptyList()))
        val vm = ChannelsViewModel(handle(), repo)
        advanceUntilIdle()
        assertEquals(ChannelsUiState.Empty, vm.uiState.value)
    }

    @Test
    fun failureOnEmpty_emitsRetryableError() = runTest {
        val repo = FakeFanClubRepository(channelsResult = FakeFanClubRepository.failure(status = 500))
        val vm = ChannelsViewModel(handle(), repo)
        advanceUntilIdle()
        val state = vm.uiState.value
        assertTrue(state is ChannelsUiState.Error)
        assertTrue((state as ChannelsUiState.Error).retryable)
    }

    @Test
    fun refreshFailureWithContent_keepsContent_andMarksStale() = runTest {
        val repo = FakeFanClubRepository(
            channelsResult = FakeFanClubRepository.success(
                listOf(FakeFanClubRepository.section(0, true, listOf(FakeFanClubRepository.channel("c1")))),
            ),
        )
        val vm = ChannelsViewModel(handle(), repo)
        advanceUntilIdle()
        assertTrue(vm.uiState.value is ChannelsUiState.Content)

        repo.channelsResult = FakeFanClubRepository.failure(status = 503)
        vm.refresh()
        advanceUntilIdle()

        val state = vm.uiState.value
        assertTrue(state is ChannelsUiState.Content)
        assertTrue((state as ChannelsUiState.Content).isStale)
    }

    @Test
    fun accessibleChannelTap_emitsNavigate_lockedTap_emitsUpgrade() = runTest {
        val tier = FakeFanClubRepository.tier("t_gold", level = 3, name = "Gold")
        val accessible = FakeFanClubRepository.section(0, true, listOf(FakeFanClubRepository.channel("c_free", "general")))
        val locked = FakeFanClubRepository.section(
            3, false, listOf(FakeFanClubRepository.channel("c_gold", "gold")), tier = tier,
        )
        val repo = FakeFanClubRepository(
            channelsResult = FakeFanClubRepository.success(listOf(accessible, locked)),
        )
        val vm = ChannelsViewModel(handle(), repo)

        val events = mutableListOf<ChannelsEvent>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.events.toList(events)
        }
        advanceUntilIdle()

        vm.onChannelClick(accessible.channels.single())
        vm.onChannelClick(locked.channels.single())
        advanceUntilIdle()

        assertTrue(events.any { it is ChannelsEvent.NavigateToMessages && it.channelId == "c_free" })
        assertTrue(events.any { it is ChannelsEvent.ShowUpgrade && it.tierId == "t_gold" })
        job.cancel()
    }
}
