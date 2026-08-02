package com.testlogon.android.feature.stories

import androidx.lifecycle.SavedStateHandle
import androidx.media3.common.Player
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.stories.SegmentKind
import com.testlogon.android.data.stories.StoriesRepository
import com.testlogon.android.data.stories.StoryBarItem
import com.testlogon.android.data.stories.StorySegment
import com.testlogon.android.data.stories.StoryReplyRepository
import com.testlogon.android.feature.player.MediaSourceSpec
import com.testlogon.android.feature.player.EffectiveQuality
import com.testlogon.android.feature.player.PlayerUiState
import com.testlogon.android.feature.player.VideoPlayerController
import com.testlogon.android.feature.videos.detail.VideoControllerProvider
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class StoryViewerViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun segment(id: String, author: String, kind: SegmentKind = SegmentKind.IMAGE, durationMs: Long = 5_000L) =
        StorySegment(
            storyId = id,
            authorId = author,
            kind = kind,
            mediaUrl = "http://h/$id",
            durationMs = durationMs,
            textOverlay = null,
            linkUrl = null,
            expiresAt = 0,
            viewCount = 7,
            highlighted = false,
        )

    private fun barItem(userId: String, isOwn: Boolean = false) =
        StoryBarItem(userId, "s", null, 1, hasUnseen = true, isOwn = isOwn)

    private fun vm(
        repo: FakeStoriesRepository,
        replyRepo: FakeStoryReplyRepository = FakeStoryReplyRepository(),
        startUser: String = "u1",
    ): StoryViewerViewModel = StoryViewerViewModel(
        repo = repo,
        replyRepo = replyRepo,
        controllerProvider = VideoControllerProvider { FakePlayerController() },
        savedStateHandle = SavedStateHandle(mapOf(StoryViewerViewModel.ARG_USER_ID to startUser)),
    )

    @Test
    fun imageTimer_autoAdvances_andRollsToNextAuthor_thenDismisses() = runTest {
        val repo = FakeStoriesRepository(
            tray = listOf(barItem("u1"), barItem("u2")),
            stories = mapOf(
                "u1" to listOf(segment("a1", "u1")),
                "u2" to listOf(segment("b1", "u2")),
            ),
        )
        val model = vm(repo)
        val effects = mutableListOf<StoryViewerEffect>()
        val job = launch { model.effectFlow.collect { effects += it } }

        advanceTimeBy(1) // run the 0-delay bootstrap (load u1 + start loop) without ticking the 5s timer
        assertEquals("a1", model.uiState.value.currentSegment?.storyId)

        // First image (5000ms) completes -> rolls to author u2 (its 0-delay load runs in this window).
        advanceTimeBy(5_100)
        assertEquals(1, model.uiState.value.authorIndex)
        assertEquals("b1", model.uiState.value.currentSegment?.storyId)

        // Second author's last image completes -> viewer dismisses.
        advanceTimeBy(5_100)
        advanceUntilIdle()
        assertEquals(ViewerPhase.DONE, model.uiState.value.phase)
        assertTrue(effects.any { it is StoryViewerEffect.Dismiss })

        // Each shown story was recorded exactly once.
        assertEquals(listOf("a1", "b1"), repo.recordedViews)
        job.cancel()
    }

    @Test
    fun pause_halts_andResumes_imageTimer() = runTest {
        val repo = FakeStoriesRepository(
            tray = listOf(barItem("u1")),
            stories = mapOf("u1" to listOf(segment("a1", "u1"))),
        )
        val model = vm(repo)
        // advanceTimeBy runs the 0-delay bootstrap (refreshTray/load) then ticks the loop 2000ms; we do
        // NOT advanceUntilIdle here (that would run the whole 5s image timer to completion).
        advanceTimeBy(2_000)
        val progressBeforePause = model.uiState.value.progress
        assertTrue(progressBeforePause > 0f && progressBeforePause < 1f)

        // NOTE: while a loop is active we use advanceTimeBy (finite) NOT advanceUntilIdle, because a
        // paused-but-active timer loop never becomes idle (bounded gotcha) — advanceUntilIdle would hang.
        model.onPauseHold(true)
        advanceTimeBy(10_000)
        // Still on the same segment (no advance while paused); progress frozen.
        assertEquals("a1", model.uiState.value.currentSegment?.storyId)
        assertEquals(progressBeforePause, model.uiState.value.progress, 0.05f)
        assertTrue(model.uiState.value.phase != ViewerPhase.DONE)

        model.onPauseHold(false)
        advanceUntilIdle()
        // After resume the only segment completes (loop exits) -> DONE.
        assertEquals(ViewerPhase.DONE, model.uiState.value.phase)
    }

    @Test
    fun sendReply_success_clearsField_andEmitsReplySent() = runTest {
        val repo = FakeStoriesRepository(
            tray = listOf(barItem("u1")),
            stories = mapOf("u1" to listOf(segment("a1", "u1"))),
        )
        val replyRepo = FakeStoryReplyRepository()
        val model = vm(repo, replyRepo)
        model.onPauseHold(true) // freeze timer so the segment doesn't auto-complete during the test
        advanceUntilIdle()

        val effects = mutableListOf<StoryViewerEffect>()
        val job = launch { model.effectFlow.collect { effects += it } }

        model.onReplyTextChange("nice!")
        model.sendReply("nice!")
        advanceUntilIdle()

        assertEquals("", model.uiState.value.composer.replyText)
        assertEquals(listOf("nice!"), replyRepo.replies.map { it.third })
        assertTrue(effects.any { it is StoryViewerEffect.ReplySent })
        job.cancel()
    }

    @Test
    fun whitespaceReply_isRejected_noNetworkCall() = runTest {
        val repo = FakeStoriesRepository(listOf(barItem("u1")), mapOf("u1" to listOf(segment("a1", "u1"))))
        val replyRepo = FakeStoryReplyRepository()
        val model = vm(repo, replyRepo)
        model.onPauseHold(true)
        advanceUntilIdle()
        model.sendReply("   ")
        advanceUntilIdle()
        assertTrue(replyRepo.replies.isEmpty())
    }

    @Test
    fun reply_failure_rollsBack_restoresText_andSetsError() = runTest {
        val repo = FakeStoriesRepository(listOf(barItem("u1")), mapOf("u1" to listOf(segment("a1", "u1"))))
        val replyRepo = FakeStoryReplyRepository(replyResult = ApiResult.Failure(ApiError(status = 503, message = "boom")))
        val model = vm(repo, replyRepo)
        model.onPauseHold(true)
        advanceUntilIdle()
        model.sendReply("retry me")
        advanceUntilIdle()
        assertEquals("retry me", model.uiState.value.composer.replyText)
        assertEquals("boom", model.uiState.value.composer.sendError)
    }

    @Test
    fun ownStory_suppressesReactionsAndReplies() = runTest {
        val repo = FakeStoriesRepository(listOf(barItem("u1", isOwn = true)), mapOf("u1" to listOf(segment("a1", "u1"))))
        val replyRepo = FakeStoryReplyRepository()
        val model = vm(repo, replyRepo)
        model.onPauseHold(true)
        advanceUntilIdle()
        assertTrue(model.uiState.value.isOwnStory)
        model.sendReaction("🔥")
        model.sendReply("hi")
        advanceUntilIdle()
        assertTrue(replyRepo.reactions.isEmpty())
        assertTrue(replyRepo.replies.isEmpty())
    }

    @Test
    fun sendReaction_success_emitsReactionSent() = runTest {
        val repo = FakeStoriesRepository(listOf(barItem("u1")), mapOf("u1" to listOf(segment("a1", "u1"))))
        val replyRepo = FakeStoryReplyRepository()
        val model = vm(repo, replyRepo)
        model.onPauseHold(true)
        advanceUntilIdle()
        val effects = mutableListOf<StoryViewerEffect>()
        val job = launch { model.effectFlow.collect { effects += it } }
        model.sendReaction("❤️")
        advanceUntilIdle()
        assertEquals(listOf("❤️"), replyRepo.reactions.map { it.third })
        assertTrue(effects.any { it is StoryViewerEffect.ReactionSent && it.emoji == "❤️" })
        job.cancel()
    }
}

// ---- Fakes ----

class FakeStoriesRepository(
    private val tray: List<StoryBarItem> = emptyList(),
    private val stories: Map<String, List<StorySegment>> = emptyMap(),
) : StoriesRepository {
    val recordedViews = mutableListOf<String>()
    val seenAuthors = mutableListOf<String>()

    override fun trayFlow() = MutableStateFlow<ApiResult<List<StoryBarItem>>>(ApiResult.Success(tray))
    override suspend fun refreshTray(): ApiResult<List<StoryBarItem>> = ApiResult.Success(tray)
    override suspend fun loadAuthorStories(userId: String): ApiResult<List<StorySegment>> =
        ApiResult.Success(stories[userId].orEmpty())
    override suspend fun recordView(storyId: String): ApiResult<Unit> {
        if (storyId !in recordedViews) recordedViews += storyId
        return ApiResult.Success(Unit)
    }
    override fun isViewed(storyId: String) = storyId in recordedViews
    override fun markAuthorSeen(userId: String) { seenAuthors += userId }
    override suspend fun createStory(
        mediaUrl: String,
        overlay: String?,
        linkUrl: String?,
        linkLabel: String?,
    ): ApiResult<Unit> = ApiResult.Success(Unit)
}

class FakeStoryReplyRepository(
    private val reactResult: ApiResult<Unit> = ApiResult.Success(Unit),
    private val replyResult: ApiResult<Unit> = ApiResult.Success(Unit),
) : StoryReplyRepository {
    val reactions = mutableListOf<Triple<String, String, String>>()
    val replies = mutableListOf<Triple<String, String, String>>()

    override suspend fun reactToStory(storyId: String, authorId: String, emoji: String): ApiResult<Unit> {
        reactions += Triple(storyId, authorId, emoji)
        return reactResult
    }

    override suspend fun replyToStory(storyId: String, authorId: String, text: String): ApiResult<Unit> {
        replies += Triple(storyId, authorId, text)
        return replyResult
    }
}

/** Minimal fake [VideoPlayerController] for JVM tests (no ExoPlayer). */
class FakePlayerController : VideoPlayerController {
    private val _state = MutableStateFlow(PlayerUiState())
    override val state: StateFlow<PlayerUiState> = _state
    override fun player(): Player = throw UnsupportedOperationException("not used in JVM tests")
    override fun setMedia(spec: MediaSourceSpec, autoPlay: Boolean) {}
    override fun setMediaUri(uri: String, autoPlay: Boolean) {}
    override fun play() {}
    override fun pause() {}
    override fun playPause() {}
    override fun seekTo(positionMs: Long) {}
    override fun skipBy(deltaMs: Long) {}
    override fun setVolume(volume: Float) {}
    override fun applyQuality(quality: EffectiveQuality) {}
    override fun retry() {}
    override fun release() {}
}
