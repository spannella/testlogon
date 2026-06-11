package com.testlogon.android.feature.broadcast.viewer

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.data.cache.Clock
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.analytics.PlaybackReporter
import com.testlogon.android.data.analytics.PlaybackTarget
import com.testlogon.android.data.broadcast.BroadcastPlaybackUrl
import com.testlogon.android.data.broadcast.BroadcastRepository
import com.testlogon.android.data.broadcast.BroadcastScheduledPage
import com.testlogon.android.data.broadcast.BroadcastSession
import com.testlogon.android.data.broadcast.BroadcastSessionPage
import com.testlogon.android.data.broadcast.BroadcastSessionStatus
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
        override suspend fun scheduledSessions(limit: Int?): ApiResult<BroadcastScheduledPage> =
            ApiResult.Success(BroadcastScheduledPage(emptyList(), 0))
        override suspend fun upcomingSessions(limit: Int?): ApiResult<BroadcastScheduledPage> =
            ApiResult.Success(BroadcastScheduledPage(emptyList(), 0))
        override suspend fun session(sessionId: String) = sessionResult
        override suspend fun mintPlaybackUrl(sessionId: String): ApiResult<BroadcastPlaybackUrl> {
            mintCalls++
            return mintResult
        }
    }

    private fun viewModel(repo: BroadcastRepository): ViewerViewModel {
        val controller = mock(VideoPlayerController::class.java)
        val factory = mock(VideoPlayerFactory::class.java)
        `when`(factory.create()).thenReturn(controller)
        return ViewerViewModel(
            savedStateHandle = SavedStateHandle(mapOf(ViewerViewModel.ARG_SESSION_ID to "s1")),
            repo = repo,
            playerFactory = factory,
            reporter = noopReporter,
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
}
