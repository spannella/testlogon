package com.testlogon.android.feature.clips

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.auth.AuthStateProvider
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.clips.Clip
import com.testlogon.android.data.clips.ClipStatus
import com.testlogon.android.data.clips.ClipsRepository
import com.testlogon.android.data.clips.PublicClipShareLinks
import com.testlogon.android.feature.player.MediaSourceSpec
import com.testlogon.android.feature.player.VideoPlayerController
import com.testlogon.android.feature.videos.detail.VideoControllerProvider
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-196 / AND-394 — state for the public single-clip viewer (deep-linked by `/c/{clipId}`).
 *
 * [PublicClipUiState.Content.playbackUrl] is non-null only when the clip is READY and a tokenized HLS
 * URL was resolved from the source video (best-effort); otherwise the screen renders the thumbnail
 * (web parity). A status of `deleted`/`failed` and any 4xx/missing clip maps to [Unavailable]; transport
 * failures map to [Offline] with retry. There is NO server entitlement/locked state on a clip (verified
 * §16), so there is no Locked outcome.
 *
 * AND-394 additions: [Content.hasSession] drives the anonymous→app CTA label/target (FR-6), and
 * [Content.isMuted] holds the session-only mute preference (FR-8). Neither gates playback.
 */
sealed interface PublicClipUiState {
    data object Loading : PublicClipUiState
    data class Content(
        val clip: Clip,
        val playbackUrl: String? = null,
        // AND-394 — anonymous→app bridge: false ⇒ "Sign in", true ⇒ "Open in app" (FR-6/AC-7).
        val hasSession: Boolean = false,
        // AND-394 — session-only mute preference; auto-muted on start (FR-8/AC-8). Not persisted.
        val isMuted: Boolean = true,
    ) : PublicClipUiState

    /** Unknown / deleted / failed / non-shareable clip — render an "unavailable" message + CTA. */
    data object Unavailable : PublicClipUiState

    /** Transport failure — render an offline state with a working Retry. */
    data object Offline : PublicClipUiState
}

/**
 * AND-394 — a one-shot request for the screen to launch the system share sheet. [url] is the
 * server-canonical `share_url` when present, otherwise the locally-built canonical URL; never carries a
 * token/cookie/session id (FR-7/AC-6).
 */
data class PublicClipShareRequest(val url: String, val title: String)

/**
 * AND-196 / AND-394 — public clip presentation. Fetches the unauthenticated [Clip] for the route's
 * `clipId`, best-effort resolves a playable HLS URL from the source video, and REUSES the AND-166/168
 * reusable player: a lifecycle-scoped [VideoPlayerController] is created lazily by the injected
 * [VideoControllerProvider] on first [setPlaybackSource] and RELEASED in [onCleared] — never an eager
 * singleton / second player. A clip that never plays never spins up an ExoPlayer.
 *
 * AND-394 hardens the *public* surface: it records a view on entry (fire-and-forget, web parity),
 * surfaces session awareness for the CTA, exposes a [toggleMute] for the auto-muted player, and a
 * double-submit-guarded [share] that records a share and emits a [PublicClipShareRequest] using the
 * server `share_url` (falling back to the local canonical URL). The public GET/POSTs require no auth
 * params server-side, so a missing session never blocks playback.
 */
@HiltViewModel
class PublicClipViewModel @Inject constructor(
    private val repository: ClipsRepository,
    private val controllerProvider: VideoControllerProvider,
    private val authStateProvider: AuthStateProvider,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val clipId: String = checkNotNull(savedStateHandle[ARG_CLIP_ID]) { "missing clipId arg" }

    private val _state = MutableStateFlow<PublicClipUiState>(PublicClipUiState.Loading)
    val state: StateFlow<PublicClipUiState> = _state.asStateFlow()

    // One-shot share events (buffered so a tap is never dropped if the screen is briefly absent).
    private val _shareRequests = Channel<PublicClipShareRequest>(Channel.BUFFERED)
    val shareRequests = _shareRequests.receiveAsFlow()

    private var controllerOrNull: VideoPlayerController? = null
    val controller: VideoPlayerController
        get() = controllerOrNull ?: controllerProvider.create().also { controllerOrNull = it }

    private var sourcePrepared = false

    // Non-idempotent POST guards: a view is recorded at most once per VM; a share at most one in-flight.
    private var viewRecorded = false
    private var shareInFlight = false

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
     * AND-394 — flips the session-only mute preference; a no-op outside [PublicClipUiState.Content]
     * (FR-8/AC-8). The player surface reflects [Content.isMuted] via the AND-168 controller.
     */
    fun toggleMute() {
        _state.update { current ->
            if (current is PublicClipUiState.Content) current.copy(isMuted = !current.isMuted) else current
        }
    }

    /**
     * AND-394 — records a share (best-effort) and emits a [PublicClipShareRequest] for the system share
     * sheet. Prefers the server `share_url`; falls back to the local canonical URL on any failure/blank.
     * Double-submit guarded: a second tap while a record is in flight is ignored.
     */
    fun share() {
        val content = _state.value as? PublicClipUiState.Content ?: return
        if (shareInFlight) return
        shareInFlight = true
        viewModelScope.launch {
            val fallback = PublicClipShareLinks.urlFor(clipId)
            val url = when (val result = repository.recordPublicShare(clipId)) {
                is ApiResult.Success -> result.data.shareUrl.ifBlank { fallback }
                else -> fallback
            }
            _shareRequests.send(PublicClipShareRequest(url = url, title = content.clip.title))
            shareInFlight = false
        }
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
        // Status-driven terminal mapping (AC-4): deleted/failed are unavailable; processing/ready render
        // (processing shows the poster + "processing" copy, web parity).
        if (clip.status == ClipStatus.DELETED || clip.status == ClipStatus.FAILED) {
            _state.update { PublicClipUiState.Unavailable }
            return
        }
        // Best-effort: resolve a tokenized HLS URL from the source video; thumbnail-only if it fails.
        val playbackUrl = repository.resolvePlaybackUrl(clip)
        _state.update {
            PublicClipUiState.Content(
                clip = clip,
                playbackUrl = playbackUrl,
                hasSession = authStateProvider.isAuthenticated.value,
            )
        }
        recordViewOnce()
    }

    /** AND-394 — fire-and-forget view recording, exactly once per VM (web fires it on mount). */
    private fun recordViewOnce() {
        if (viewRecorded) return
        viewRecorded = true
        viewModelScope.launch { repository.recordPublicView(clipId) }
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
