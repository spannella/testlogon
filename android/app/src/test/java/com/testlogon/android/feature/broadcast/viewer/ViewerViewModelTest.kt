package com.testlogon.android.feature.broadcast.viewer

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.data.cache.Clock
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.analytics.PlaybackReporter
import com.testlogon.android.data.analytics.PlaybackTarget
import com.testlogon.android.data.broadcast.BroadcastInput
import com.testlogon.android.data.broadcast.BroadcastPlaybackUrl
import com.testlogon.android.data.broadcast.BroadcastRepository
import com.testlogon.android.data.broadcast.BroadcastScheduledPage
import com.testlogon.android.data.broadcast.BroadcastSession
import com.testlogon.android.data.broadcast.BroadcastSessionPage
import com.testlogon.android.data.broadcast.BroadcastSessionStatus
import com.testlogon.android.data.broadcast.BroadcastViewerCountApi
import com.testlogon.android.data.broadcast.BroadcastViewerCountRepository
import com.testlogon.android.data.broadcast.ViewerCountDto
import com.testlogon.android.data.broadcast.ViewerPresence
import com.squareup.moshi.Moshi
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.player.VideoPlayerController
import com.testlogon.android.feature.player.VideoPlayerFactory
import androidx.lifecycle.LifecycleOwner
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`
import java.time.Instant

class ViewerViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private val now = Instant.parse("2026-06-09T12:00:00Z")
    private val fixedClock = Clock { now.toEpochMilli() }

    private val noopReporter = object : PlaybackReporter {
        override fun attach(player: androidx.media3.common.Player, target: PlaybackTarget, owner: LifecycleOwner) = Unit
        override fun detach() = Unit
    }

    private fun session(status: BroadcastSessionStatus) = BroadcastSession(
        id = "s1",
        profileId = "p",
        name = "Live show",
        description = null,
        status = status,
        createdBy = "host",
        scheduledAt = null,
        startedAt = if (status == BroadcastSessionStatus.LIVE) now.minusSeconds(60) else null,
        stoppedAt = null,
        cancelledAt = null,
        playbackUrl = null,
        thumbnailUrl = null,
        tipTotalCents = null,
        tipCount = null,
        scheduleStatus = null,
        createdAt = Instant.EPOCH,
        updatedAt = Instant.EPOCH,
    )

    private class FakeRepo(
        var sessionResult: ApiResult<BroadcastSession>,
        var mintResult: ApiResult<BroadcastPlaybackUrl> =
            ApiResult.Success(BroadcastPlaybackUrl("s1", "http://h/x.m3u8", Instant.parse("2026-06-09T12:02:00Z"))),
    ) : BroadcastRepository {
        var mintCalls = 0
        override suspend fun sessions(status: String?, limit: Int?): ApiResult<BroadcastSessionPage> =
            ApiResult.Success(BroadcastSessionPage(emptyList(), false))
        override suspend fun liveSessions(limit: Int?): ApiResult<BroadcastSessionPage> =
            ApiResult.Success(BroadcastSessionPage(emptyList(), false))
        override suspend fun scheduledSessions(limit: Int?): ApiResult<BroadcastScheduledPage> =
            ApiResult.Success(BroadcastScheduledPage(emptyList(), 0))
        override suspend fun upcomingSessions(limit: Int?): ApiResult<BroadcastScheduledPage> =
            ApiResult.Success(BroadcastScheduledPage(emptyList(), 0))
        override suspend fun session(sessionId: String) = sessionResult
        override suspend fun mintPlaybackUrl(sessionId: String): ApiResult<BroadcastPlaybackUrl> {
            mintCalls++
            return mintResult
        }
        // AND-307 host mutations — unused by the viewer; stubbed.
        override suspend fun create(profileId: String): ApiResult<BroadcastSession> =
            ApiResult.Failure(ApiError(404, "nope"))
        override suspend fun schedule(
            sessionId: String,
            scheduledAtEpochSeconds: Long,
            name: String?,
            description: String?,
        ): ApiResult<BroadcastSession> = ApiResult.Failure(ApiError(404, "nope"))
        override suspend fun cancelSchedule(sessionId: String): ApiResult<BroadcastSession> =
            ApiResult.Failure(ApiError(404, "nope"))
        // AND-308 inputs control plane — unused by the viewer; stubbed.
        override suspend fun createInput(
            sessionId: String,
            inputType: String,
            label: String?,
        ): ApiResult<BroadcastInput> = ApiResult.Failure(ApiError(404, "nope"))
        override suspend fun activateInput(sessionId: String, inputId: String): ApiResult<Unit> =
            ApiResult.Failure(ApiError(404, "nope"))
        override suspend fun deactivateInput(sessionId: String, inputId: String): ApiResult<Unit> =
            ApiResult.Failure(ApiError(404, "nope"))
        override suspend fun removeInput(sessionId: String, inputId: String): ApiResult<Unit> =
            ApiResult.Failure(ApiError(404, "nope"))
    }

    private val presence = ViewerPresence()

    private val errorParser = ApiErrorParser(Moshi.Builder().build())

    /** A real count repo over a fake API: returns [count] (or throws to simulate a failed poll). */
    private fun countRepo(count: Int? = null): BroadcastViewerCountRepository {
        val api = object : BroadcastViewerCountApi {
            override suspend fun viewerCount(sessionId: String): ViewerCountDto {
                if (count == null) throw java.io.IOException("count poll unavailable")
                return ViewerCountDto(sessionId = sessionId, viewerCount = count)
            }
        }
        return BroadcastViewerCountRepository(api, errorParser)
    }

    private fun viewModel(
        repo: BroadcastRepository,
        viewerCountRepo: BroadcastViewerCountRepository = countRepo(),
    ): ViewerViewModel {
        val controller = mock(VideoPlayerController::class.java)
        val factory = mock(VideoPlayerFactory::class.java)
        `when`(factory.create()).thenReturn(controller)
        return ViewerViewModel(
            savedStateHandle = SavedStateHandle(mapOf(ViewerViewModel.ARG_SESSION_ID to "s1")),
            repo = repo,
            playerFactory = factory,
            reporter = noopReporter,
            presence = presence,
            viewerCountRepo = viewerCountRepo,
            clock = fixedClock,
        )
    }

    @Test
    fun liveSession_mintsUrl_reachesReady() = runTest {
        val repo = FakeRepo(ApiResult.Success(session(BroadcastSessionStatus.LIVE)))
        val vm = viewModel(repo)
        advanceUntilIdle()

        val state = vm.uiState.value
        assertTrue(state is ViewerUiState.Ready)
        assertEquals("http://h/x.m3u8", (state as ViewerUiState.Ready).playbackUrl)
        assertEquals(1, repo.mintCalls)
    }

    @Test
    fun endedSession_unavailableEnded_noMint() = runTest {
        val repo = FakeRepo(ApiResult.Success(session(BroadcastSessionStatus.STOPPED)))
        val vm = viewModel(repo)
        advanceUntilIdle()

        val state = vm.uiState.value
        assertTrue(state is ViewerUiState.Unavailable)
        assertEquals(PlaybackUnavailable.SESSION_ENDED, (state as ViewerUiState.Unavailable).reason)
        assertEquals(0, repo.mintCalls)
    }

    @Test
    fun scheduledSession_unavailableNotStarted() = runTest {
        val repo = FakeRepo(ApiResult.Success(session(BroadcastSessionStatus.SCHEDULED)))
        val vm = viewModel(repo)
        advanceUntilIdle()

        val state = vm.uiState.value
        assertEquals(
            PlaybackUnavailable.NOT_STARTED,
            (state as ViewerUiState.Unavailable).reason,
        )
    }

    @Test
    fun mint403_unavailableNotAuthorized() = runTest {
        val repo = FakeRepo(
            sessionResult = ApiResult.Success(session(BroadcastSessionStatus.LIVE)),
            mintResult = ApiResult.Failure(ApiError(403, "no access")),
        )
        val vm = viewModel(repo)
        advanceUntilIdle()

        assertEquals(
            PlaybackUnavailable.NOT_AUTHORIZED,
            (vm.uiState.value as ViewerUiState.Unavailable).reason,
        )
    }

    @Test
    fun sessionNetworkError_offline() = runTest {
        val repo = FakeRepo(ApiResult.NetworkError(java.io.IOException("down")))
        val vm = viewModel(repo)
        advanceUntilIdle()

        assertTrue(vm.uiState.value is ViewerUiState.Offline)
    }

    @Test
    fun refreshDelay_is75PercentOfRemaining() = runTest {
        val repo = FakeRepo(ApiResult.Success(session(BroadcastSessionStatus.LIVE)))
        val vm = viewModel(repo)
        advanceUntilIdle()
        // expires at now+120s -> remaining 120s -> 75% = 90s.
        assertEquals(90_000L, vm.refreshDelayMs())
    }

    // --- AND-285/287: viewer-count presence surfacing (no second loop; observes ViewerPresence) ---

    @Test
    fun ready_seedsViewerCountFromPoll() = runTest {
        val repo = FakeRepo(ApiResult.Success(session(BroadcastSessionStatus.LIVE)))
        val vm = viewModel(repo, viewerCountRepo = countRepo(count = 7))
        advanceUntilIdle()

        val state = vm.uiState.value
        assertTrue(state is ViewerUiState.Ready)
        assertEquals(7, (state as ViewerUiState.Ready).viewerCount)
    }

    @Test
    fun heartbeatPresenceCount_isMergedIntoReady() = runTest {
        val repo = FakeRepo(ApiResult.Success(session(BroadcastSessionStatus.LIVE)))
        // No poll seed (count poll fails); the count must arrive from the reused heartbeat presence.
        val vm = viewModel(repo, viewerCountRepo = countRepo(count = null))
        advanceUntilIdle()
        assertTrue(vm.uiState.value is ViewerUiState.Ready)

        // Simulate the heartbeat sink publishing the latest join/heartbeat viewer_count.
        presence.update(42)
        advanceUntilIdle()

        assertEquals(42, (vm.uiState.value as ViewerUiState.Ready).viewerCount)
    }

    @Test
    fun presenceCount_whileNotReady_doesNotCorruptState() = runTest {
        val repo = FakeRepo(ApiResult.Success(session(BroadcastSessionStatus.STOPPED)))
        val vm = viewModel(repo)
        advanceUntilIdle()
        // A stray presence update must not flip an Unavailable state into Ready.
        presence.update(99)
        advanceUntilIdle()
        assertTrue(vm.uiState.value is ViewerUiState.Unavailable)
    }
}
