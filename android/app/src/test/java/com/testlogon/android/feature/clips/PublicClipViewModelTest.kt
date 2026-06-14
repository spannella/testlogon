package com.testlogon.android.feature.clips

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.auth.AuthStateProvider
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.clips.ClipStatus
import com.testlogon.android.data.clips.PublicClipShareResult
import com.testlogon.android.feature.player.EffectiveQuality
import com.testlogon.android.feature.player.MediaSourceSpec
import com.testlogon.android.feature.player.PlayerUiState
import com.testlogon.android.feature.player.VideoPlayerController
import com.testlogon.android.feature.videos.detail.VideoControllerProvider
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.IOException

@OptIn(ExperimentalCoroutinesApi::class)
class PublicClipViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeClipsRepository()
    private val controller = FakeVideoController()
    private val provider = VideoControllerProvider { controller }
    private val auth = FakeAuthStateProvider()

    private fun vm(id: String = "clp_1") = PublicClipViewModel(
        repository = repo,
        controllerProvider = provider,
        authStateProvider = auth,
        savedStateHandle = SavedStateHandle(mapOf(PublicClipViewModel.ARG_CLIP_ID to id)),
    )

    @Test
    fun loadsContent_withResolvedPlaybackUrl() = runTest {
        repo.publicClipResult = ApiResult.Success(FakeClipsRepository.sampleClip("clp_1"))
        repo.playbackUrlResult = "http://h/master.m3u8?token=tok"
        val vm = vm()
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is PublicClipUiState.Content)
        assertEquals("clp_1", (state as PublicClipUiState.Content).clip.clipId)
        assertEquals("http://h/master.m3u8?token=tok", state.playbackUrl)
    }

    @Test
    fun loadsContent_thumbnailOnly_whenNoPlaybackUrl() = runTest {
        repo.publicClipResult = ApiResult.Success(FakeClipsRepository.sampleClip("clp_1"))
        repo.playbackUrlResult = null
        val vm = vm()
        advanceUntilIdle()
        val state = vm.state.value as PublicClipUiState.Content
        assertNull(state.playbackUrl)
    }

    @Test
    fun notFound_404_mapsToUnavailable() = runTest {
        repo.publicClipResult = ApiResult.Failure(ApiError(status = 404, message = "x"))
        val vm = vm()
        advanceUntilIdle()
        assertEquals(PublicClipUiState.Unavailable, vm.state.value)
    }

    @Test
    fun networkError_mapsToOffline_thenRetrySucceeds() = runTest {
        repo.publicClipResult = ApiResult.NetworkError(IOException("offline"))
        val vm = vm()
        advanceUntilIdle()
        assertEquals(PublicClipUiState.Offline, vm.state.value)

        repo.publicClipResult = ApiResult.Success(FakeClipsRepository.sampleClip("clp_1"))
        vm.retry()
        advanceUntilIdle()
        assertTrue(vm.state.value is PublicClipUiState.Content)
        assertEquals(2, repo.publicClipCalls)
    }

    @Test
    fun serverError_5xx_mapsToOffline() = runTest {
        repo.publicClipResult = ApiResult.Failure(ApiError(status = 503, message = "x"))
        val vm = vm()
        advanceUntilIdle()
        assertEquals(PublicClipUiState.Offline, vm.state.value)
    }

    @Test
    fun setPlaybackSource_preparesControllerOnce_andReleasesOnCleared() = runTest {
        repo.publicClipResult = ApiResult.Success(FakeClipsRepository.sampleClip("clp_1"))
        repo.playbackUrlResult = "http://h/master.m3u8?token=tok"
        val vm = vm()
        advanceUntilIdle()
        vm.setPlaybackSource()
        vm.setPlaybackSource()
        assertEquals(1, controller.setMediaCalls)
        assertEquals("http://h/master.m3u8?token=tok", controller.lastSpec?.uri)
    }

    // ---- AND-394 ----

    @Test
    fun deletedClip_mapsToUnavailable() = runTest {
        repo.publicClipResult =
            ApiResult.Success(FakeClipsRepository.sampleClip("clp_1", status = ClipStatus.DELETED))
        val vm = vm()
        advanceUntilIdle()
        assertEquals(PublicClipUiState.Unavailable, vm.state.value)
    }

    @Test
    fun failedClip_mapsToUnavailable() = runTest {
        repo.publicClipResult =
            ApiResult.Success(FakeClipsRepository.sampleClip("clp_1", status = ClipStatus.FAILED))
        val vm = vm()
        advanceUntilIdle()
        assertEquals(PublicClipUiState.Unavailable, vm.state.value)
    }

    @Test
    fun processingClip_rendersContent_notUnavailable() = runTest {
        repo.publicClipResult =
            ApiResult.Success(FakeClipsRepository.sampleClip("clp_1", status = ClipStatus.PROCESSING))
        val vm = vm()
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is PublicClipUiState.Content)
        assertTrue((state as PublicClipUiState.Content).clip.isProcessing)
    }

    @Test
    fun recordsView_onceOnEntry_fireAndForget() = runTest {
        repo.publicClipResult = ApiResult.Success(FakeClipsRepository.sampleClip("clp_1"))
        val vm = vm()
        advanceUntilIdle()
        assertEquals(listOf("clp_1"), repo.recordedViews)
        // A re-load (retry) does not double-record the view (non-idempotent POST guarded).
        vm.retry()
        advanceUntilIdle()
        assertEquals(listOf("clp_1"), repo.recordedViews)
    }

    @Test
    fun unavailableClip_doesNotRecordView() = runTest {
        repo.publicClipResult =
            ApiResult.Success(FakeClipsRepository.sampleClip("clp_1", status = ClipStatus.DELETED))
        val vm = vm()
        advanceUntilIdle()
        assertTrue(repo.recordedViews.isEmpty())
    }

    @Test
    fun hasSession_reflectsAuthState_inContent() = runTest {
        repo.publicClipResult = ApiResult.Success(FakeClipsRepository.sampleClip("clp_1"))
        auth.set(true)
        val vm = vm()
        advanceUntilIdle()
        assertTrue((vm.state.value as PublicClipUiState.Content).hasSession)
    }

    @Test
    fun toggleMute_flipsOnlyInContent() = runTest {
        repo.publicClipResult = ApiResult.Success(FakeClipsRepository.sampleClip("clp_1"))
        val vm = vm()
        // No-op while Loading.
        vm.toggleMute()
        advanceUntilIdle()
        // Auto-muted on start.
        assertTrue((vm.state.value as PublicClipUiState.Content).isMuted)
        vm.toggleMute()
        assertFalse((vm.state.value as PublicClipUiState.Content).isMuted)
    }

    @Test
    fun share_recordsShare_andEmitsServerShareUrl() = runTest {
        repo.publicClipResult = ApiResult.Success(FakeClipsRepository.sampleClip("clp_1"))
        repo.shareResult = ApiResult.Success(
            PublicClipShareResult(shareUrl = "https://testlogon.com/c/clp_1?ref=srv", shareCount = 99),
        )
        val vm = vm()
        advanceUntilIdle()
        // Start a single-item collector, then trigger the share; the buffered channel delivers it.
        val emitted = async { vm.shareRequests.first() }
        vm.share()
        advanceUntilIdle()
        assertEquals(listOf("clp_1"), repo.recordedShares)
        assertEquals("https://testlogon.com/c/clp_1?ref=srv", emitted.await().url)
        assertEquals("Clip clp_1", emitted.await().title)
    }

    @Test
    fun share_fallsBackToCanonicalUrl_whenRecordFails() = runTest {
        repo.publicClipResult = ApiResult.Success(FakeClipsRepository.sampleClip("clp_1"))
        repo.shareResult = ApiResult.NetworkError(IOException("offline"))
        val vm = vm()
        advanceUntilIdle()
        val emitted = async { vm.shareRequests.first() }
        vm.share()
        advanceUntilIdle()
        assertEquals("https://testlogon.com/c/clp_1", emitted.await().url)
    }

    /** Minimal fake auth-state seam; default unauthenticated. */
    private class FakeAuthStateProvider : AuthStateProvider {
        private val _authed = MutableStateFlow(false)
        override val isAuthenticated: StateFlow<Boolean> = _authed.asStateFlow()
        fun set(value: Boolean) { _authed.value = value }
    }

    /** Minimal pure-JVM fake controller (never touches ExoPlayer; player() is unused in unit tests). */
    private class FakeVideoController : VideoPlayerController {
        override val state: StateFlow<PlayerUiState> = MutableStateFlow(PlayerUiState())
        var setMediaCalls = 0
        var lastSpec: MediaSourceSpec? = null

        override fun player() = throw UnsupportedOperationException("not used in JVM tests")
        override fun setMedia(spec: MediaSourceSpec, autoPlay: Boolean) {
            setMediaCalls++
            lastSpec = spec
        }
        override fun setMediaUri(uri: String, autoPlay: Boolean) = Unit
        override fun play() = Unit
        override fun pause() = Unit
        override fun playPause() = Unit
        override fun seekTo(positionMs: Long) = Unit
        override fun skipBy(deltaMs: Long) = Unit
        override fun setVolume(volume: Float) = Unit
        override fun applyQuality(quality: EffectiveQuality) = Unit
        override fun retry() = Unit
        override fun release() = Unit
    }
}
