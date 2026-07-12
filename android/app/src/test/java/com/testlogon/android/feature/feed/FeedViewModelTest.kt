package com.testlogon.android.feature.feed

import androidx.paging.testing.asSnapshot
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.feed.FeedPage
import com.testlogon.android.data.feed.LockType
import com.testlogon.android.data.feed.Paywall
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** AND-102 / AND-104 — [FeedViewModel] paging + refresh + event tests. */
class FeedViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    @Test
    fun pagingFlow_mapsTwoPages_inOrder() = runTest {
        val repo = FakeFeedRepository(
            pagesByCursor = mapOf(
                null to FeedPage(
                    (1..20).map { FakeFeedRepository.post("p$it") },
                    nextCursor = "c2",
                ),
                "c2" to FeedPage(
                    (21..25).map { FakeFeedRepository.post("p$it") },
                    nextCursor = null,
                ),
            ),
        )
        val vm = FeedViewModel(repo, FakeEngagementRepository(), FakePostActionsRepository(), FakeFeedBookmarkRepository(), FakePollRepository(), fakeDisplayNameResolver())
        val items = vm.items.asSnapshot { scrollTo(24) }
        assertEquals(25, items.size)
        assertEquals("p1", items.first().id)
        assertEquals("p25", items.last().id)
    }

    @Test
    fun pagingFlow_preservesLockFlags() = runTest {
        val locked = FakeFeedRepository.post(
            "locked1",
            paywall = Paywall.Locked(
                lockType = LockType.FIXED_PRICE, priceCents = 499, unlockCount = null,
                unlockLimit = null, unlockLimitReached = false, lockExpired = false,
            ),
        )
        val repo = FakeFeedRepository(pagesByCursor = mapOf(null to FeedPage(listOf(locked), null)))
        val vm = FeedViewModel(repo, FakeEngagementRepository(), FakePostActionsRepository(), FakeFeedBookmarkRepository(), FakePollRepository(), fakeDisplayNameResolver())
        val items = vm.items.asSnapshot()
        assertEquals(1, items.size)
        assertTrue(items[0].isLocked)
    }

    @Test
    fun refresh_reAnchorsAndReloads() = runTest {
        val repo = FakeFeedRepository(
            pagesByCursor = mapOf(null to FeedPage(listOf(FakeFeedRepository.post("p1")), null)),
        )
        val vm = FeedViewModel(repo, FakeEngagementRepository(), FakePostActionsRepository(), FakeFeedBookmarkRepository(), FakePollRepository(), fakeDisplayNameResolver())
        vm.items.asSnapshot()
        val callsBefore = repo.feedCalls
        vm.refresh()
        vm.items.asSnapshot()
        assertTrue(repo.feedCalls > callsBefore)
    }

    @Test
    fun onUnlockClick_emitsUnlockRequestedEvent_once() = runTest {
        val vm = FeedViewModel(FakeFeedRepository(), FakeEngagementRepository(), FakePostActionsRepository(), FakeFeedBookmarkRepository(), FakePollRepository(), fakeDisplayNameResolver())
        vm.onUnlockClick("post_42")
        val event = vm.events.first()
        assertTrue(event is FeedEvent.UnlockRequested)
        assertEquals("post_42", (event as FeedEvent.UnlockRequested).postId)
    }
}
