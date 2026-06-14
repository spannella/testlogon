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

/**
 * AND-242 — gap-fill for [ChannelsViewModel] paths not covered by AND-238's unit test:
 *  - onMembersClick emits NavigateToMembers (with the tier id/name),
 *  - onMembersClick on a tier-less (free/level-0) section is a no-op (no event).
 */
class ChannelsViewModelGapTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun handle() = SavedStateHandle(mapOf(ChannelsViewModel.ARG_CREATOR_ID to "creator_1"))

    @Test
    fun onMembersClick_withTier_emitsNavigateToMembers() = runTest {
        val tier = FakeFanClubRepository.tier("t_gold", level = 3, name = "Gold")
        val section = FakeFanClubRepository.section(
            3, false, listOf(FakeFanClubRepository.channel("c_gold", "gold")), tier = tier,
        )
        val repo = FakeFanClubRepository(channelsResult = FakeFanClubRepository.success(listOf(section)))
        val vm = ChannelsViewModel(handle(), repo)
        val events = mutableListOf<ChannelsEvent>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch { vm.events.toList(events) }
        advanceUntilIdle()

        vm.onMembersClick(section)
        advanceUntilIdle()

        val nav = events.single() as ChannelsEvent.NavigateToMembers
        assertEquals("t_gold", nav.tierId)
        assertEquals("Gold", nav.tierName)
        job.cancel()
    }

    @Test
    fun onMembersClick_tierlessSection_isNoop() = runTest {
        val section = FakeFanClubRepository.section(
            0, true, listOf(FakeFanClubRepository.channel("c_free", "general")), tier = null,
        )
        val repo = FakeFanClubRepository(channelsResult = FakeFanClubRepository.success(listOf(section)))
        val vm = ChannelsViewModel(handle(), repo)
        val events = mutableListOf<ChannelsEvent>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch { vm.events.toList(events) }
        advanceUntilIdle()

        vm.onMembersClick(section)
        advanceUntilIdle()

        assertTrue(events.isEmpty())
        job.cancel()
    }
}
