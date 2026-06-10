package com.testlogon.android.feature.clips

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.clips.Clip
import com.testlogon.android.data.clips.ClipsRepository
import com.testlogon.android.feature.player.MediaSourceSpec
import com.testlogon.android.feature.player.VideoPlayerController
import com.testlogon.android.feature.videos.detail.VideoControllerProvider
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-196 — state for the public single-clip viewer (deep-linked by `/c/{clipId}`).
 *
 * [PublicClipUiState.Content.playbackUrl] is non-null only when the clip is READY and a tokenized HLS
 * URL was resolved from the source video (best-effort); otherwise the screen renders the thumbnail
 * (web parity). A 4xx (404/deleted/non-shareable) maps to [Unavailable]; transport failures map to
 * [Offline] with retry. There is NO server entitlement/locked state on a clip (verified §16), so there
 * is no Locked outcome.
 */
sealed interface PublicClipUiState {
    data object Loading : PublicClipUiState
    data class Content(
        val clip: Clip,
        val playbackUrl: String? = null,
    ) : PublicClipUiState

    /** Unknown / deleted / non-shareable clip (4xx) — render an "unavailable" message + CTA. */
    data object Unavailable : PublicClipUiState

    /** Transport failure — render an offline state with a working Retry. */
    data object Offline : PublicClipUiState
}

/**
 * AND-196 — public clip presentation. Fetches the unauthenticated [Clip] for the route's `clipId`,
 * best-effort resolves a playable HLS URL from the source video, and REUSES the AND-166/168 reusable
 * player: a lifecycle-scoped [VideoPlayerController] is created lazily by the injected
 * [VideoControllerProvider] on first [setPlaybackSource] and RELEASED in [onCleared] — never an eager
 * singleton / second player. A clip that never plays never spins up an ExoPlayer.
 */
@HiltViewModel
class PublicClipViewModel @Inject constructor(
    private val repository: ClipsRepository,
    private val controllerProvider: VideoControllerProvider,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val clipId: String = checkNotNull(savedStateHandle[ARG_CLIP_ID]) { "missing clipId arg" }

    private val _state = MutableStateFlow<PublicClipUiState>(PublicClipUiState.Loading)
    val state: StateFlow<PublicClipUiState> = _state.asStateFlow()

    private var controllerOrNull: VideoPlayerController? = null
    val controller: VideoPlayerController
        get() = controllerOrNull ?: controllerProvider.create().also { controllerOrNull = it }

    private var sourcePrepared = false

    init {
        load()
    }

    fun load() {
        _state.update { PublicClipUiState.Loading }
        sourcePrepared = false
        viewModelScope.launch {
            when (val result = repository.publicClip(clipId)) {
                is ApiResult.Success -> onClipLoaded(result.data)
                is ApiResult.Failure -> _state.update { mapFailure(result.error) }
                is ApiResult.NetworkError -> _state.update { PublicClipUiState.Offline }
            }
        }
    }

    fun retry() = load()

    /** Player-level Retry: re-prepares the current source via the reused controller. */
    fun retryPlayback() {
        if (controllerOrNull != null) controller.retry()
    }

    /**
     * Idempotently hands the resolved HLS source to the reused player. Called from the screen once the
     * playback URL is available; safe to call repeatedly (prepares only once).
     */
    fun setPlaybackSource() {
        val content = _state.value as? PublicClipUiState.Content ?: return
        val url = content.playbackUrl ?: return
        if (sourcePrepared) return
        sourcePrepared = true
        controller.setMedia(MediaSourceSpec(uri = url, title = content.clip.title), autoPlay = false)
    }

    private suspend fun onClipLoaded(clip: Clip) {
        // Best-effort: resolve a tokenized HLS URL from the source video; thumbnail-only if it fails.
        val playbackUrl = repository.resolvePlaybackUrl(clip)
        _state.update { PublicClipUiState.Content(clip = clip, playbackUrl = playbackUrl) }
    }

    // A clip 4xx (404/deleted/non-shareable) is "unavailable"; 5xx/unknown is retryable offline-style.
    private fun mapFailure(error: ApiError): PublicClipUiState = when {
        error.status in 400..499 -> PublicClipUiState.Unavailable
        else -> PublicClipUiState.Offline
    }

    override fun onCleared() {
        // Release the reused ExoPlayer-backed controller deterministically (it owns the player).
        controllerOrNull?.release()
        controllerOrNull = null
        super.onCleared()
    }

    companion object {
        const val ARG_CLIP_ID = "clipId"
    }
}
