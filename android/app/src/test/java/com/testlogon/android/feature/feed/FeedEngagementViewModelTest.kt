package com.testlogon.android.feature.feed

import androidx.paging.testing.asSnapshot
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.feed.FeedPage
import com.testlogon.android.data.feed.FeedPost
import com.testlogon.android.data.feed.LikeState
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** AND-173 / AND-175 — [FeedViewModel] like-toggle + hide/not-interested tests. */
class FeedEngagementViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun post(id: String, liked: Boolean = false, likeCount: Int = 10) =
        FakeFeedRepository.post(id).copy(likedByMe = liked, likeCount = likeCount)

    private fun feedRepo(vararg posts: FeedPost) =
        FakeFeedRepository(pagesByCursor = mapOf(null to FeedPage(posts.toList(), nextCursor = null)))

    @Test
    fun onLikeToggle_appliesOptimistically_thenReconcilesServerCount() = runTest {
        val engagement = FakeEngagementRepository(result = { _, liked, _ -> ApiResult.Success(LikeState(liked, 99)) })
        val vm = FeedViewModel(feedRepo(post("p1")), engagement, FakePostActionsRepository())

        vm.onLikeToggle(post("p1"))
        advanceUntilIdle()

        val items = vm.items.asSnapshot()
        val p1 = items.first { it.id == "p1" }
        assertTrue(p1.likedByMe)
        assertEquals(99, p1.likeCount) // server count from reconcile, not optimistic 11
        assertEquals(Triple("p1", true, 11), engagement.calls.single()) // optimistic count carried in
    }

    @Test
    fun onLikeToggle_failure_rollsBack_andEmitsError() = runTest {
        val engagement = FakeEngagementRepository(result = { _, _, _ -> FakeFeedRepository.failure(500) })
        val vm = FeedViewModel(feedRepo(post("p1", liked = false, likeCount = 10)), engagement, FakePostActionsRepository())

        vm.onLikeToggle(post("p1", liked = false, likeCount = 10))
        advanceUntilIdle()

        val p1 = vm.items.asSnapshot().first { it.id == "p1" }
        assertFalse(p1.likedByMe)
        assertEquals(10, p1.likeCount) // rolled back to pre-tap
    }

    @Test
    fun onLikeToggle_unlikeAtZero_neverNegative() = runTest {
        val engagement = FakeEngagementRepository()
        val vm = FeedViewModel(feedRepo(post("p1", liked = true, likeCount = 0)), engagement, FakePostActionsRepository())

        vm.onLikeToggle(post("p1", liked = true, likeCount = 0))
        advanceUntilIdle()

        val p1 = vm.items.asSnapshot().first { it.id == "p1" }
        assertFalse(p1.likedByMe)
        assertEquals(0, p1.likeCount) // coerced at 0
    }

    @Test
    fun onLikeToggle_rapidTaps_supersede_onlyLatestApplied_noErrorOnCancel() = runTest {
        val gate = CompletableDeferred<Unit>()
        val engagement = FakeEngagementRepository(result = { _, liked, count -> ApiResult.Success(LikeState(liked, count)) })
        engagement.gate = gate
        val vm = FeedViewModel(feedRepo(post("p1")), engagement, FakePostActionsRepository())

        // Three rapid taps before any request completes.
        vm.onLikeToggle(post("p1", liked = false, likeCount = 10))
        vm.onLikeToggle(post("p1", liked = true, likeCount = 11))
        vm.onLikeToggle(post("p1", liked = false, likeCount = 10))
        gate.complete(Unit)
        advanceUntilIdle()

        // Last-write-wins: the latest tap was on an unliked post (liked=false) -> toggles to liked.
        val p1 = vm.items.asSnapshot().first { it.id == "p1" }
        assertTrue(p1.likedByMe)
    }

    @Test
    fun onHide_suppressesPost_filtersFromFeed() = runTest {
        val actions = FakePostActionsRepository()
        val vm = FeedViewModel(feedRepo(post("p1"), post("p2")), FakeEngagementRepository(), actions)

        vm.onHide("p1", index = 0)
        advanceUntilIdle()

        assertEquals(listOf("p1"), actions.hideCalls)
        val items = vm.items.asSnapshot()
        assertTrue(items.none { it.id == "p1" }) // filtered out
        assertTrue(items.any { it.id == "p2" })
    }

    @Test
    fun onNotInterested_callsNotInterested_suppresses() = runTest {
        val actions = FakePostActionsRepository()
        val vm = FeedViewModel(feedRepo(post("p1")), FakeEngagementRepository(), actions)

        vm.onNotInterested("p1", index = 0)
        advanceUntilIdle()

        assertEquals(listOf("p1"), actions.notInterestedCalls)
        assertTrue(vm.items.asSnapshot().none { it.id == "p1" })
    }

    @Test
    fun onUndo_unhides_restoresPost() = runTest {
        val actions = FakePostActionsRepository(initial = setOf("p1"))
        val vm = FeedViewModel(feedRepo(post("p1")), FakeEngagementRepository(), actions)

        // Initially suppressed -> filtered out.
        assertTrue(vm.items.asSnapshot().none { it.id == "p1" })

        vm.onUndo(FeedAction.Hide("p1", 0))
        advanceUntilIdle()

        assertEquals(listOf("p1"), actions.unhideCalls)
        assertTrue(vm.items.asSnapshot().any { it.id == "p1" })
    }
}
