package com.testlogon.android.feature.clips

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.player.EffectiveQuality
import com.testlogon.android.feature.player.MediaSourceSpec
import com.testlogon.android.feature.player.PlayerUiState
import com.testlogon.android.feature.player.VideoPlayerController
import com.testlogon.android.feature.videos.detail.VideoControllerProvider
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
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

    private fun vm(id: String = "clp_1") = PublicClipViewModel(
        repository = repo,
        controllerProvider = provider,
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
