package com.testlogon.android.feature.videos.detail

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.auth.AuthStateProvider
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.videos.VideoAccess
import com.testlogon.android.data.videos.VideoDetail
import com.testlogon.android.data.videos.VideoSummary
import com.testlogon.android.data.videos.VideosRepository
import com.testlogon.android.feature.player.MediaSourceSpec
import com.testlogon.android.feature.player.VideoPlayerController
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-190 — video-detail UI state. The list/detail Loading state is explicit (not Paging-owned). When
 * [playbackUrl] is non-null the player surface is enabled; processing/forbidden/no-url cases each carry
 * a distinct [PlaybackBlock] so the screen renders the right (non-Retry) message.
 */
data class VideoDetailUiState(
    val isLoading: Boolean = true,
    val detail: VideoDetail? = null,
    val playbackUrl: String? = null,
    val playbackBlock: PlaybackBlock? = null,
    val entitlement: Entitlement? = null,
    val liked: Boolean = false,
    val related: List<VideoSummary> = emptyList(),
    val detailError: DetailError? = null,
)

/** Why playback is unavailable even though detail loaded — drives a non-Retry message on the player. */
enum class PlaybackBlock { PROCESSING, NO_SOURCE, FORBIDDEN }

/** A detail-fetch failure surfaced as a full-screen state. [retryable] hides Retry for 4xx like 404. */
data class DetailError(val message: String, val retryable: Boolean)

/**
 * AND-190 — video detail presentation. Fetches [VideoDetail] for the route's `videoId`, resolves the
 * tokenized HLS URL, and REUSES the AND-166/168 reusable player: a lifecycle-scoped
 * [VideoPlayerController] is created lazily by the injected [VideoPlayerFactory] on first
 * [setPlaybackSource] and RELEASED in [onCleared] — never an eager singleton / second player. The
 * controller survives configuration change (it is VM-scoped) so playback position is preserved on
 * rotation.
 */
@HiltViewModel
class VideoDetailViewModel @Inject constructor(
    private val repository: VideosRepository,
    private val controllerProvider: VideoControllerProvider,
    private val authStateProvider: AuthStateProvider,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val videoId: String = checkNotNull(savedStateHandle[ARG_VIDEO_ID]) { "missing videoId arg" }

    private val _uiState = MutableStateFlow(VideoDetailUiState())
    val uiState: StateFlow<VideoDetailUiState> = _uiState.asStateFlow()

    // Lifecycle-scoped controller, created PER-SCREEN on first playable load (not eagerly) and released
    // in onCleared. The backing nullable means a detail that is never played never spins up an ExoPlayer.
    private var controllerOrNull: VideoPlayerController? = null
    val controller: VideoPlayerController
        get() = controllerOrNull ?: controllerProvider.create().also { controllerOrNull = it }

    private var sourcePrepared = false

    init {
        load()
    }

    fun load() {
        _uiState.update { it.copy(isLoading = true, detailError = null) }
        viewModelScope.launch {
            // AND-197 — detail + the authoritative access check load concurrently; if only access fails
            // the resolver runs with access = null (fail-closed inline fallback), never upgrading.
            val detailDeferred = async { repository.getVideoDetail(videoId) }
            val accessDeferred = async { repository.checkAccess(videoId) }
            val accessResult = accessDeferred.await()
            when (val result = detailDeferred.await()) {
                is ApiResult.Success -> onDetailLoaded(result.data, accessResult.accessOrNull())
                is ApiResult.Failure -> _uiState.update {
                    it.copy(isLoading = false, detailError = mapFailure(result.error))
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(
                        isLoading = false,
                        detailError = DetailError(OFFLINE_MESSAGE, retryable = true),
                    )
                }
            }
        }
    }

    private fun ApiResult<VideoAccess>.accessOrNull(): VideoAccess? =
        (this as? ApiResult.Success)?.data

    fun retryDetail() = load()

    /** Player-level Retry: re-prepares the current source via the reused controller. */
    fun retryPlayback() {
        if (controllerOrNull != null) controller.retry()
    }

    /** Toggles like for the current video, optimistically flipping the flag and rolling back on error. */
    fun toggleLike() {
        val previous = _uiState.value.liked
        _uiState.update { it.copy(liked = !previous) }
        viewModelScope.launch {
            when (val result = repository.toggleLike(videoId)) {
                is ApiResult.Success -> _uiState.update { it.copy(liked = result.data.liked) }
                else -> _uiState.update { it.copy(liked = previous) }
            }
        }
    }

    /**
     * Idempotently hands the resolved HLS source to the reused player. Called from the screen once the
     * playback URL is available; safe to call repeatedly (prepares only once).
     */
    fun setPlaybackSource() {
        val url = _uiState.value.playbackUrl ?: return
        if (sourcePrepared) return
        sourcePrepared = true
        controller.setMedia(
            MediaSourceSpec(uri = url, title = _uiState.value.detail?.title),
            autoPlay = false,
        )
    }

    private fun onDetailLoaded(detail: VideoDetail, access: VideoAccess?) {
        // AND-197 — resolve entitlement (fail-closed: access==null falls back to the inline flag).
        val entitlement = EntitlementResolver.resolve(
            detail = detail,
            access = access,
            isAuthenticated = authStateProvider.isAuthenticated.value,
        )
        // FR-5 — only Entitlement.Granted exposes a non-null playback id, and only then if a real
        // source/manifest exists. Map the gated outcomes onto the screen's PlaybackBlock.
        val granted = entitlement is Entitlement.Granted
        val block = when {
            !granted -> entitlement.toPlaybackBlock()
            detail.isProcessing -> PlaybackBlock.PROCESSING
            detail.playbackUrl == null -> PlaybackBlock.NO_SOURCE
            else -> null
        }
        val playable = if (granted && block == null) detail.playbackUrl else null
        _uiState.update {
            it.copy(
                isLoading = false,
                detail = detail,
                playbackUrl = playable,
                playbackBlock = block,
                entitlement = entitlement,
                detailError = null,
            )
        }
        loadLikeAndRelated()
    }

    /** Maps a non-Granted entitlement onto the screen's coarse PlaybackBlock affordance. */
    private fun Entitlement.toPlaybackBlock(): PlaybackBlock = when (this) {
        is Entitlement.Unavailable ->
            if (reason == UnavailableReason.NOT_READY) PlaybackBlock.PROCESSING else PlaybackBlock.NO_SOURCE
        else -> PlaybackBlock.FORBIDDEN
    }

    private fun loadLikeAndRelated() {
        viewModelScope.launch {
            (repository.checkLike(videoId) as? ApiResult.Success)?.let { liked ->
                _uiState.update { it.copy(liked = liked.data) }
            }
        }
        viewModelScope.launch {
            (repository.getSimilar(videoId) as? ApiResult.Success)?.let { related ->
                _uiState.update { it.copy(related = related.data.filter { v -> v.id != videoId }) }
            }
        }
    }

    private fun mapFailure(error: ApiError): DetailError = when (error.status) {
        404 -> DetailError(NOT_FOUND_MESSAGE, retryable = false)
        403 -> DetailError(FORBIDDEN_MESSAGE, retryable = false)
        // 5xx / unexpected statuses may be transient on the flaky dev host.
        else -> DetailError(error.message, retryable = error.status >= 500)
    }

    override fun onCleared() {
        // Release the reused ExoPlayer-backed controller deterministically (it owns the player).
        controllerOrNull?.release()
        controllerOrNull = null
        super.onCleared()
    }

    companion object {
        const val ARG_VIDEO_ID = "videoId"

        // User-facing fallbacks; the screen prefers string resources but the VM stays framework-free.
        const val NOT_FOUND_MESSAGE = "Video not found"
        const val FORBIDDEN_MESSAGE = "You don't have access to this video"
        const val OFFLINE_MESSAGE = "Network error — check your connection and try again."
    }
}
