package com.testlogon.android.feature.feed

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.feed.ChoiceMode
import com.testlogon.android.data.feed.FeedPage
import com.testlogon.android.data.feed.FeedPost
import com.testlogon.android.data.feed.Poll
import com.testlogon.android.data.feed.PollOption
import com.testlogon.android.data.feed.PollQuestion
import com.testlogon.android.data.feed.PollVoteResult
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

/** AND-176 / AND-179 — [FeedViewModel] bookmark + poll interaction-state tests. */
class FeedInteractionViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun feedRepo(vararg posts: FeedPost) =
        FakeFeedRepository(pagesByCursor = mapOf(null to FeedPage(posts.toList(), nextCursor = null)))

    private fun pollPost(id: String, closed: Boolean = false, voted: Boolean = false): FeedPost {
        val q = PollQuestion(
            id = "q1", text = "Q", choiceMode = ChoiceMode.SINGLE, maxSelections = null,
            options = listOf(PollOption("o1", "A"), PollOption("o2", "B")),
            counts = mapOf("o1" to 1, "o2" to 2),
            myVoteOptionIds = if (voted) listOf("o1") else emptyList(),
        )
        return FakeFeedRepository.post(id).copy(
            poll = Poll(id, listOf(q), totalVotes = 3, closed = closed, closesAtEpochSeconds = null, anonymous = false, allowVoteChange = false),
        )
    }

    private fun vm(
        feed: FakeFeedRepository,
        bookmarks: FakeFeedBookmarkRepository = FakeFeedBookmarkRepository(),
        polls: FakePollRepository = FakePollRepository(),
    ) = FeedViewModel(feed, FakeEngagementRepository(), FakePostActionsRepository(), bookmarks, polls)

    // ---- AND-176 bookmark ----

    @Test
    fun onToggleBookmark_savesAndReflectsInSavedIds() = runTest {
        val bookmarks = FakeFeedBookmarkRepository()
        val vm = vm(feedRepo(FakeFeedRepository.post("p1")), bookmarks = bookmarks)
        vm.onToggleBookmark("p1", currentlySaved = false)
        advanceUntilIdle()
        // The desired end-state passed to the repo is the inverse of currentlySaved (i.e. save = true).
        assertEquals("p1" to true, bookmarks.setCalls.first())
        assertTrue("p1" in vm.savedIds.value)
    }

    @Test
    fun onToggleBookmark_failure_emitsBookmarkFailedEvent() = runTest {
        val bookmarks = FakeFeedBookmarkRepository(result = { _, _ -> FakeFeedRepository.failure(500) })
        val vm = vm(feedRepo(FakeFeedRepository.post("p1")), bookmarks = bookmarks)
        val events = mutableListOf<FeedEvent>()
        val job = launch(UnconfinedTestDispatcher(testScheduler)) { vm.events.collect { events += it } }
        vm.onToggleBookmark("p1", currentlySaved = false)
        advanceUntilIdle()
        assertTrue(events.any { it is FeedEvent.BookmarkFailed })
        job.cancel()
    }

    @Test
    fun onToggleBookmark_rapidTaps_lastWriteWins() = runTest {
        val bookmarks = FakeFeedBookmarkRepository().apply { gate = CompletableDeferred() }
        val vm = vm(feedRepo(FakeFeedRepository.post("p1")), bookmarks = bookmarks)
        vm.onToggleBookmark("p1", currentlySaved = false) // intends save
        vm.onToggleBookmark("p1", currentlySaved = false) // intends save again (supersedes)
        bookmarks.gate!!.complete(Unit)
        advanceUntilIdle()
        // The superseded first job is cancelled; the final committed intent is "save".
        assertTrue("p1" in vm.savedIds.value)
    }

    // ---- AND-179 poll ----

    @Test
    fun ensurePollState_openPoll_seedsIdle() = runTest {
        val vm = vm(feedRepo(pollPost("p1")))
        vm.ensurePollState(pollPost("p1"))
        assertTrue(vm.pollUiStates.value["p1"] is PollCardState.Idle)
    }

    @Test
    fun ensurePollState_closedPoll_seedsResults() = runTest {
        val vm = vm(feedRepo(pollPost("p1", closed = true)))
        vm.ensurePollState(pollPost("p1", closed = true))
        assertTrue(vm.pollUiStates.value["p1"] is PollCardState.Results)
    }

    @Test
    fun ensurePollState_alreadyVoted_seedsResults_noNetwork() = runTest {
        val polls = FakePollRepository()
        val vm = vm(feedRepo(pollPost("p1", voted = true)), polls = polls)
        vm.ensurePollState(pollPost("p1", voted = true))
        assertTrue(vm.pollUiStates.value["p1"] is PollCardState.Results)
        assertTrue(polls.voteCalls.isEmpty())
    }

    @Test
    fun onPollOptionSelected_success_movesToResultsWithMergedCounts() = runTest {
        val polls = FakePollRepository(voteResult = { _, q, o ->
            ApiResult.Success(PollVoteResult(q, mapOf("o1" to 1, "o2" to 3), totalVotes = 4, myVoteOptionIds = listOf(o)))
        })
        val vm = vm(feedRepo(pollPost("p1")), polls = polls)
        vm.ensurePollState(pollPost("p1"))
        vm.onPollOptionSelected("p1", "q1", "o2")
        advanceUntilIdle()
        val s = vm.pollUiStates.value["p1"]
        assertTrue(s is PollCardState.Results)
        val q = (s as PollCardState.Results).poll.questions.single()
        assertTrue(q.isOptionSelected("o2"))
        assertEquals(4, s.poll.totalVotes)
    }

    @Test
    fun onPollOptionSelected_doubleTapWhileVoting_oneCall() = runTest {
        val polls = FakePollRepository().apply { gate = CompletableDeferred() }
        val vm = vm(feedRepo(pollPost("p1")), polls = polls)
        vm.ensurePollState(pollPost("p1"))
        vm.onPollOptionSelected("p1", "q1", "o1")
        advanceUntilIdle()
        assertTrue(vm.pollUiStates.value["p1"] is PollCardState.Voting)
        vm.onPollOptionSelected("p1", "q1", "o2") // ignored while Voting
        polls.gate!!.complete(Unit)
        advanceUntilIdle()
        assertEquals(1, polls.voteCalls.size)
    }

    @Test
    fun onPollOptionSelected_failure_movesToError() = runTest {
        val polls = FakePollRepository(voteResult = { _, _, _ -> FakeFeedRepository.failure(422) })
        val vm = vm(feedRepo(pollPost("p1")), polls = polls)
        vm.ensurePollState(pollPost("p1"))
        vm.onPollOptionSelected("p1", "q1", "o1")
        advanceUntilIdle()
        assertTrue(vm.pollUiStates.value["p1"] is PollCardState.Error)
    }

    @Test
    fun onPollOptionSelected_closedPoll_isNoOp() = runTest {
        val polls = FakePollRepository()
        val vm = vm(feedRepo(pollPost("p1", closed = true)), polls = polls)
        vm.ensurePollState(pollPost("p1", closed = true))
        vm.onPollOptionSelected("p1", "q1", "o1")
        advanceUntilIdle()
        assertTrue(polls.voteCalls.isEmpty())
    }
}
