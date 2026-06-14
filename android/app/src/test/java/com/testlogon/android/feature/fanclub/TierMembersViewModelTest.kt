package com.testlogon.android.feature.fanclub

import androidx.lifecycle.SavedStateHandle
import androidx.paging.testing.asSnapshot
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.fanclub.FanClubMemberPage
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** AND-240 — [TierMembersViewModel] paging + header state + refresh. */
class TierMembersViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun handle() = SavedStateHandle(
        mapOf(
            TierMembersViewModel.ARG_TIER_ID to "tier_gold",
            TierMembersViewModel.ARG_TIER_NAME to "Gold",
            TierMembersViewModel.ARG_MEMBER_COUNT to 2,
        ),
    )

    @Test
    fun members_emitFirstPage() = runTest {
        val repo = FakeFanClubRepository(
            memberPages = mapOf(
                null to FanClubMemberPage(
                    listOf(FakeFanClubRepository.member("u1"), FakeFanClubRepository.member("u2")),
                    nextCursor = null,
                    total = 2,
                ),
            ),
        )
        val vm = TierMembersViewModel(handle(), repo)
        advanceUntilIdle()

        val snapshot = vm.members.asSnapshot()
        assertEquals(listOf("u1", "u2"), snapshot.map { it.userId })
    }

    @Test
    fun header_carriesTierNameAndCount() = runTest {
        val vm = TierMembersViewModel(handle(), FakeFanClubRepository())
        advanceUntilIdle()
        assertEquals("Gold", vm.header.value.tierName)
        assertEquals(2, vm.header.value.totalCount)
    }

    @Test
    fun refresh_reTriggersPager() = runTest {
        val repo = FakeFanClubRepository(
            memberPages = mapOf(null to FanClubMemberPage(listOf(FakeFanClubRepository.member("u1")), null, 1)),
        )
        val vm = TierMembersViewModel(handle(), repo)
        advanceUntilIdle()
        vm.members.asSnapshot()

        vm.refresh()
        val snapshot = vm.members.asSnapshot()
        advanceUntilIdle()
        assertTrue(snapshot.isNotEmpty())
    }
}
