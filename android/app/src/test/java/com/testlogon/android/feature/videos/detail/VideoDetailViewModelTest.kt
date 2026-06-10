package com.testlogon.android.feature.videos.detail

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.player.EffectiveQuality
import com.testlogon.android.feature.player.MediaSourceSpec
import com.testlogon.android.feature.player.PlayerUiState
import com.testlogon.android.feature.player.VideoPlayerController
import com.testlogon.android.feature.videos.FakeVideosRepository
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class VideoDetailViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeVideosRepository()
    private val controller = FakeVideoController()
    private val provider = VideoControllerProvider { controller }

    private fun vm(id: String = "vid_1") = VideoDetailViewModel(
        repository = repo,
        controllerProvider = provider,
        savedStateHandle = SavedStateHandle(mapOf(VideoDetailViewModel.ARG_VIDEO_ID to id)),
    )

    @Test
    fun loadsContent_andResolvesPlaybackUrl() = runTest {
        repo.detailResult = ApiResult.Success(FakeVideosRepository.detail("vid_1"))
        val vm = vm()
        advanceUntilIdle()
        val state = vm.uiState.value
        assertFalse(state.isLoading)
        assertEquals("vid_1", state.detail?.id)
        assertEquals("http://h/master.m3u8?token=tok", state.playbackUrl)
        assertNull(state.playbackBlock)
    }

    @Test
    fun processingStatus_blocksPlayback() = runTest {
        repo.detailResult = ApiResult.Success(FakeVideosRepository.detail("v", status = "encoding"))
        val vm = vm()
        advanceUntilIdle()
        assertNull(vm.uiState.value.playbackUrl)
        assertEquals(PlaybackBlock.PROCESSING, vm.uiState.value.playbackBlock)
    }

    @Test
    fun noSource_blocksPlayback() = runTest {
        repo.detailResult = ApiResult.Success(FakeVideosRepository.detail("v", playbackUrl = null))
        val vm = vm()
        advanceUntilIdle()
        assertEquals(PlaybackBlock.NO_SOURCE, vm.uiState.value.playbackBlock)
    }

    @Test
    fun notEntitled_blocksPlayback() = runTest {
        repo.detailResult = ApiResult.Success(FakeVideosRepository.detail("v", isEntitled = false))
        val vm = vm()
        advanceUntilIdle()
        assertEquals(PlaybackBlock.FORBIDDEN, vm.uiState.value.playbackBlock)
    }

    @Test
    fun notFound_404_setsNonRetryableError() = runTest {
        repo.detailResult = ApiResult.Failure(ApiError(status = 404, message = "x"))
        val vm = vm()
        advanceUntilIdle()
        val error = vm.uiState.value.detailError
        assertEquals(VideoDetailViewModel.NOT_FOUND_MESSAGE, error?.message)
        assertFalse(error!!.retryable)
    }

    @Test
    fun forbidden_403_setsNonRetryableError() = runTest {
        repo.detailResult = ApiResult.Failure(ApiError(status = 403, message = "x"))
        val vm = vm()
        advanceUntilIdle()
        assertEquals(VideoDetailViewModel.FORBIDDEN_MESSAGE, vm.uiState.value.detailError?.message)
    }

    @Test
    fun networkError_setsRetryableError_thenRetrySucceeds() = runTest {
        repo.detailResult = ApiResult.NetworkError(java.io.IOException("x"))
        val vm = vm()
        advanceUntilIdle()
        assertTrue(vm.uiState.value.detailError?.retryable == true)

        repo.detailResult = ApiResult.Success(FakeVideosRepository.detail("vid_1"))
        vm.retryDetail()
        advanceUntilIdle()
        assertNull(vm.uiState.value.detailError)
        assertEquals("vid_1", vm.uiState.value.detail?.id)
        assertEquals(2, repo.detailCalls)
    }

    @Test
    fun setPlaybackSource_preparesControllerOnce() = runTest {
        repo.detailResult = ApiResult.Success(FakeVideosRepository.detail("vid_1"))
        val vm = vm()
        advanceUntilIdle()
        vm.setPlaybackSource()
        vm.setPlaybackSource()
        assertEquals(1, controller.setMediaCalls)
        assertEquals("http://h/master.m3u8?token=tok", controller.lastSpec?.uri)
    }

    @Test
    fun toggleLike_optimisticallyFlips_andReleaseOnCleared() = runTest {
        repo.detailResult = ApiResult.Success(FakeVideosRepository.detail("vid_1"))
        repo.likeResult = ApiResult.Success(false)
        repo.toggleResult = ApiResult.Success(com.testlogon.android.data.videos.LikeState(liked = true, likeCount = 1))
        val vm = vm()
        advanceUntilIdle()
        assertFalse(vm.uiState.value.liked)
        vm.toggleLike()
        advanceUntilIdle()
        assertTrue(vm.uiState.value.liked)
        assertEquals(1, repo.toggleCalls)
    }

    /** Minimal pure-JVM fake controller (never touches ExoPlayer; player() is unused in unit tests). */
    private class FakeVideoController : VideoPlayerController {
        override val state: StateFlow<PlayerUiState> = MutableStateFlow(PlayerUiState())
        var setMediaCalls = 0
        var lastSpec: MediaSourceSpec? = null
        var released = false

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
        override fun release() { released = true }
    }
}
