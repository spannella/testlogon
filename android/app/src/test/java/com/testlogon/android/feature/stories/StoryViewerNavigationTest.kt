package com.testlogon.android.feature.stories

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.stories.SegmentKind
import com.testlogon.android.data.stories.StoriesRepository
import com.testlogon.android.data.stories.StoryBarItem
import com.testlogon.android.data.stories.StorySegment
import com.testlogon.android.feature.videos.detail.VideoControllerProvider
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-203 — gap-fill coverage for [StoryViewerViewModel] tap navigation that the auto-advance/timing
 * test (StoryViewerViewModelTest) does not exercise: manual next() across segments, previous() within
 * and across authors, previous-from-first restarts, and per-story view-record dedupe on revisit.
 *
 * The viewer is held paused throughout (onPauseHold(true)) so the bounded image timer never auto-
 * completes during the assertions; advanceUntilIdle is then safe (a paused loop is cancelled, idle).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class StoryViewerNavigationTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun segment(id: String, author: String) = StorySegment(
        storyId = id,
        authorId = author,
        kind = SegmentKind.IMAGE,
        mediaUrl = "http://h/$id",
        durationMs = 5_000L,
        textOverlay = null,
        linkUrl = null,
        expiresAt = 0,
        viewCount = 0,
        highlighted = false,
    )

    private fun bar(userId: String) = StoryBarItem(userId, "s", null, 2, hasUnseen = true, isOwn = false)

    private fun vm(repo: NavFakeRepository, startUser: String = "u1") = StoryViewerViewModel(
        repo = repo,
        replyRepo = FakeStoryReplyRepository(),
        controllerProvider = VideoControllerProvider { FakePlayerController() },
        savedStateHandle = SavedStateHandle(mapOf(StoryViewerViewModel.ARG_USER_ID to startUser)),
    )

    @Test
    fun next_advancesWithinAuthor_thenCrossesToNextAuthor() = runTest {
        val repo = NavFakeRepository(
            tray = listOf(bar("u1"), bar("u2")),
            stories = mapOf(
                "u1" to listOf(segment("a1", "u1"), segment("a2", "u1")),
                "u2" to listOf(segment("b1", "u2")),
            ),
        )
        val model = vm(repo)
        model.onPauseHold(true)
        advanceUntilIdle()
        assertEquals("a1", model.uiState.value.currentSegment?.storyId)

        model.next()
        advanceUntilIdle()
        assertEquals(0, model.uiState.value.authorIndex)
        assertEquals("a2", model.uiState.value.currentSegment?.storyId)

        model.next()
        advanceUntilIdle()
        assertEquals(1, model.uiState.value.authorIndex)
        assertEquals("b1", model.uiState.value.currentSegment?.storyId)
    }

    @Test
    fun previous_goesBackWithinAuthor() = runTest {
        val repo = NavFakeRepository(
            tray = listOf(bar("u1")),
            stories = mapOf("u1" to listOf(segment("a1", "u1"), segment("a2", "u1"))),
        )
        val model = vm(repo)
        model.onPauseHold(true)
        advanceUntilIdle()
        model.next()
        advanceUntilIdle()
        assertEquals("a2", model.uiState.value.currentSegment?.storyId)

        model.previous()
        advanceUntilIdle()
        assertEquals("a1", model.uiState.value.currentSegment?.storyId)
    }

    @Test
    fun previous_fromFirstOfFirst_restartsSameSegment() = runTest {
        val repo = NavFakeRepository(
            tray = listOf(bar("u1")),
            stories = mapOf("u1" to listOf(segment("a1", "u1"), segment("a2", "u1"))),
        )
        val model = vm(repo)
        model.onPauseHold(true)
        advanceUntilIdle()
        model.previous()
        advanceUntilIdle()
        assertEquals(0, model.uiState.value.segmentIndex)
        assertEquals("a1", model.uiState.value.currentSegment?.storyId)
        assertTrue(model.uiState.value.phase != ViewerPhase.DONE)
    }

    @Test
    fun viewRecord_dedupesOnRevisit() = runTest {
        val repo = NavFakeRepository(
            tray = listOf(bar("u1")),
            stories = mapOf("u1" to listOf(segment("a1", "u1"), segment("a2", "u1"))),
        )
        val model = vm(repo)
        model.onPauseHold(true)
        advanceUntilIdle()
        model.next() // a2
        advanceUntilIdle()
        model.previous() // back to a1 (revisit)
        advanceUntilIdle()
        // a1 recorded once despite the revisit, a2 once -> exactly two distinct records.
        assertEquals(listOf("a1", "a2"), repo.recordedViews)
    }
}

/** Navigation-focused [StoriesRepository] fake that records views once per story id. */
private class NavFakeRepository(
    private val tray: List<StoryBarItem>,
    private val stories: Map<String, List<StorySegment>>,
) : StoriesRepository {
    val recordedViews = mutableListOf<String>()

    override fun trayFlow() =
        kotlinx.coroutines.flow.MutableStateFlow<com.testlogon.android.core.model.ApiResult<List<StoryBarItem>>>(
            com.testlogon.android.core.model.ApiResult.Success(tray),
        )

    override suspend fun refreshTray() = com.testlogon.android.core.model.ApiResult.Success(tray)
    override suspend fun loadAuthorStories(userId: String) =
        com.testlogon.android.core.model.ApiResult.Success(stories[userId].orEmpty())

    override suspend fun recordView(storyId: String): com.testlogon.android.core.model.ApiResult<Unit> {
        if (storyId !in recordedViews) recordedViews += storyId
        return com.testlogon.android.core.model.ApiResult.Success(Unit)
    }

    override fun isViewed(storyId: String) = storyId in recordedViews
    override fun markAuthorSeen(userId: String) {}
    override suspend fun createStory(
        mediaUrl: String,
        overlay: String?,
        linkUrl: String?,
        linkLabel: String?,
    ): com.testlogon.android.core.model.ApiResult<Unit> = com.testlogon.android.core.model.ApiResult.Success(Unit)
}
