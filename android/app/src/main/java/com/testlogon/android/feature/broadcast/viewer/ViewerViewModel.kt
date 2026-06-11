package com.testlogon.android.feature.broadcast.viewer

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.data.cache.Clock
import androidx.lifecycle.LifecycleOwner
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.analytics.PlaybackReporter
import com.testlogon.android.data.analytics.PlaybackTarget
import com.testlogon.android.data.broadcast.BroadcastRepository
import com.testlogon.android.data.broadcast.BroadcastViewerCountRepository
import com.testlogon.android.data.broadcast.ViewerPresence
import com.testlogon.android.feature.player.MediaSourceSpec
import com.testlogon.android.feature.player.PlayerMediaType
import com.testlogon.android.feature.player.VideoPlayerController
import com.testlogon.android.feature.player.VideoPlayerFactory
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
 * AND-280 — viewer playback presentation logic.
 *
 * Acquires session metadata + a signed HLS URL via the AND-278 [BroadcastRepository], maps the result
 * to [ViewerUiState], and owns a lifecycle-scoped [VideoPlayerController] created lazily by the AND-166
 * [VideoPlayerFactory] (NEVER an eager singleton) and released in [onCleared]. The viewer
 * join/heartbeat/leave analytics are NOT looped here — they are driven by the reused AND-171
 * PlaybackReporter wired in the Compose surface (bounded, lifecycle-scoped). The controller's media is
 * set from the minted URL; the proactive URL refresh fires at 75% of remaining lifetime (web parity).
 */
@HiltViewModel
class ViewerViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repo: BroadcastRepository,
    private val playerFactory: VideoPlayerFactory,
    private val reporter: PlaybackReporter,
    private val presence: ViewerPresence,
    private val viewerCountRepo: BroadcastViewerCountRepository,
    private val clock: Clock,
) : ViewModel() {

    val sessionId: String = requireNotNull(savedStateHandle[ARG_SESSION_ID]) {
        "viewer route requires a sessionId arg"
    }

    private val _uiState = MutableStateFlow<ViewerUiState>(ViewerUiState.Loading)
    val uiState: StateFlow<ViewerUiState> = _uiState.asStateFlow()

    /** One-shot effects consumed exactly once by the screen (AND-286 §4 FR-10). */
    private val _effects = Channel<ViewerEffect>(Channel.BUFFERED)
    val effects = _effects.receiveAsFlow()

    /** Lazily-created, per-screen controller; released in [onCleared] (no eager ExoPlayer). */
    private var controllerOrNull: VideoPlayerController? = null
    val controller: VideoPlayerController
        get() = controllerOrNull ?: playerFactory.create().also { controllerOrNull = it }

    /** Guards against a refresh storm (FR-6/§7). */
    private var refreshing: Boolean = false

    init {
        observePresenceCount()
        start()
    }

    /**
     * AND-285/286 — merges the live viewer count published by the REUSED PlaybackReporter/heartbeat
     * sink (from the `viewers/join`/`heartbeat` responses) into [ViewerUiState.Ready]. This is a
     * passive observer of the existing bounded heartbeat — it does NOT start a second presence loop.
     */
    private fun observePresenceCount() {
        viewModelScope.launch {
            presence.viewerCount.collect { count ->
                if (count == null) return@collect
                _uiState.update { (it as? ViewerUiState.Ready)?.copy(viewerCount = count) ?: it }
            }
        }
    }

    /** Loads session state then mints the playback URL; the mint result is the entitlement gate. */
    fun start() {
        _uiState.value = ViewerUiState.Loading
        viewModelScope.launch {
            when (val session = repo.session(sessionId)) {
                is ApiResult.Success -> {
                    val state = session.data.status.toPlaybackState()
                    val title = session.data.name?.takeIf { it.isNotBlank() } ?: DEFAULT_TITLE
                    when (state) {
                        SessionPlaybackState.ENDED ->
                            _uiState.value = ViewerUiState.Unavailable(PlaybackUnavailable.SESSION_ENDED)
                        SessionPlaybackState.SCHEDULED ->
                            _uiState.value = ViewerUiState.Unavailable(PlaybackUnavailable.NOT_STARTED)
                        SessionPlaybackState.LIVE -> acquireAndPlay(title)
                    }
                }
                is ApiResult.Failure -> _uiState.value = session.error.toUnavailableOrError()
                is ApiResult.NetworkError -> _uiState.value = ViewerUiState.Offline
            }
        }
    }

    fun retry() = start()

    /** Re-acquires the URL on expiry / player auth error and reattaches the source without flicker. */
    fun refreshUrl() {
        if (refreshing) return
        val current = _uiState.value as? ViewerUiState.Ready ?: return
        refreshing = true
        viewModelScope.launch {
            try {
                when (val mint = repo.mintPlaybackUrl(sessionId)) {
                    is ApiResult.Success -> {
                        controllerOrNull?.setMedia(mediaSpec(mint.data.playbackUrl, current.title), autoPlay = true)
                        _uiState.update {
                            (it as? ViewerUiState.Ready)?.copy(
                                playbackUrl = mint.data.playbackUrl,
                                expiresAtEpochMs = mint.data.expiresAt.toEpochMilli(),
                            ) ?: it
                        }
                    }
                    is ApiResult.Failure -> _uiState.value = mint.error.toUnavailableOrError()
                    is ApiResult.NetworkError -> _uiState.value = ViewerUiState.Error(retryable = true)
                }
            } finally {
                refreshing = false
            }
        }
    }

    fun onBuffering(buffering: Boolean) {
        _uiState.update { (it as? ViewerUiState.Ready)?.copy(buffering = buffering) ?: it }
    }

    fun onLiveEdgeChanged(atEdge: Boolean) {
        _uiState.update { (it as? ViewerUiState.Ready)?.copy(atLiveEdge = atEdge) ?: it }
    }

    fun goLive() {
        controllerOrNull?.seekTo(Long.MAX_VALUE) // clamp to live edge
        onLiveEdgeChanged(true)
    }

    /** Number of ms from now until [refreshUrl] should fire (75% of remaining), or null if not due. */
    fun refreshDelayMs(): Long? {
        val ready = _uiState.value as? ViewerUiState.Ready ?: return null
        val expiry = ready.expiresAtEpochMs ?: return null
        val remaining = expiry - clock.now()
        if (remaining <= MIN_REMAINING_MS) return null
        return (remaining * REFRESH_FRACTION_NUM) / REFRESH_FRACTION_DEN
    }

    /**
     * AND-280 §FR-2 — attaches the reused AND-171 [PlaybackReporter] to the live player + lifecycle.
     * The reporter emits join on the playing edge, a bounded/lifecycle-scoped heartbeat while watching,
     * and leave on stop/background/dispose — no unbounded loop is added here.
     */
    fun attachAnalytics(owner: LifecycleOwner) {
        val ctrl = controllerOrNull ?: return
        reporter.attach(ctrl.player(), PlaybackTarget.Broadcast(sessionId), owner)
    }

    /** Detaches the reporter (emits leave). Called from the Compose surface on dispose. */
    fun detachAnalytics() {
        reporter.detach()
    }

    override fun onCleared() {
        // Detaching the reporter emits the viewer `leave` (best-effort, exactly once) and cancels the
        // bounded heartbeat — AND-285 FR-3/FR-9. No separate presence teardown loop exists.
        reporter.detach()
        presence.reset()
        controllerOrNull?.release()
        controllerOrNull = null
    }

    private suspend fun acquireAndPlay(title: String) {
        when (val mint = repo.mintPlaybackUrl(sessionId)) {
            is ApiResult.Success -> {
                controller.setMedia(mediaSpec(mint.data.playbackUrl, title), autoPlay = true)
                _uiState.value = ViewerUiState.Ready(
                    sessionId = sessionId,
                    title = title,
                    playbackUrl = mint.data.playbackUrl,
                    expiresAtEpochMs = mint.data.expiresAt.toEpochMilli(),
                    viewerCount = presence.viewerCount.value,
                )
                seedViewerCount()
            }
            is ApiResult.Failure -> _uiState.value = mint.error.toUnavailableOrError()
            is ApiResult.NetworkError -> _uiState.value = ViewerUiState.Offline
        }
    }

    /**
     * AND-285 §16 R2 — a best-effort one-shot count poll so the badge shows a fresh value within one
     * interval, before the first heartbeat lands. Failure is non-fatal (presence is non-blocking);
     * the heartbeat-driven count then takes over via [observePresenceCount].
     */
    private fun seedViewerCount() {
        viewModelScope.launch {
            when (val result = viewerCountRepo.viewerCount(sessionId)) {
                is ApiResult.Success -> presence.update(result.data)
                is ApiResult.Failure, is ApiResult.NetworkError -> {
                    // Best-effort: the heartbeat-driven count still takes over. If nothing is known
                    // yet, surface a one-shot non-fatal notice (FR-4 stale/offline; AND-286 FR-10).
                    if (presence.viewerCount.value == null) {
                        _effects.trySend(ViewerEffect.Notice(ViewerNotice.PRESENCE_DEGRADED))
                    }
                }
            }
        }
    }

    private fun mediaSpec(url: String, title: String): MediaSourceSpec =
        MediaSourceSpec(uri = url, type = PlayerMediaType.HLS, title = title)

    private fun com.testlogon.android.core.model.ApiError.toUnavailableOrError(): ViewerUiState = when (status) {
        403 -> ViewerUiState.Unavailable(PlaybackUnavailable.NOT_AUTHORIZED)
        404 -> ViewerUiState.Error(retryable = false)
        401 -> ViewerUiState.Unavailable(PlaybackUnavailable.NOT_AUTHORIZED)
        com.testlogon.android.core.model.ApiError.STATUS_NETWORK -> ViewerUiState.Offline
        else -> ViewerUiState.Error(retryable = true)
    }

    companion object {
        const val ARG_SESSION_ID = "sessionId"
        const val DEFAULT_TITLE = "Live broadcast"

        /** Below this remaining window the web client skips scheduling a refresh (≤10s). */
        const val MIN_REMAINING_MS = 10_000L

        /** Refresh at 75% of remaining lifetime (web: remainingSec * 750ms). */
        const val REFRESH_FRACTION_NUM = 3L
        const val REFRESH_FRACTION_DEN = 4L
    }
}
