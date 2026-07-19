package com.testlogon.android.feature.broadcast.viewer

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.data.cache.Clock
import androidx.lifecycle.LifecycleOwner
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.analytics.PlaybackReporter
import com.testlogon.android.data.analytics.PlaybackTarget
import com.testlogon.android.data.broadcast.BroadcastAdEvents
import com.testlogon.android.data.broadcast.BroadcastPreRoll
import com.testlogon.android.data.broadcast.BroadcastRepository
import com.testlogon.android.data.ads.AdCtaClicker
import com.testlogon.android.data.ads.CtaAction
import com.testlogon.android.data.broadcast.BroadcastViewerAdRepository
import com.testlogon.android.data.broadcast.BroadcastViewerCountRepository
import com.testlogon.android.data.broadcast.ViewerPresence
import com.testlogon.android.feature.player.MediaSourceSpec
import com.testlogon.android.feature.player.PlayerMediaType
import com.testlogon.android.feature.player.VideoPlayerController
import com.testlogon.android.feature.player.VideoPlayerFactory
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
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
    private val adRepo: BroadcastViewerAdRepository,
    private val playerFactory: VideoPlayerFactory,
    private val reporter: PlaybackReporter,
    private val presence: ViewerPresence,
    private val viewerCountRepo: BroadcastViewerCountRepository,
    private val clock: Clock,
    private val adCtaClicker: AdCtaClicker,
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

    // TEST SEAM (unit tests only): the ad-break poll is an unbounded while(isActive){ delay(...) }
    // loop that is correct in production (cancelled in onCleared) but makes runTest.advanceUntilIdle()
    // walk virtual time forever. Unit tests reaching a LIVE Ready state set this false to disarm the
    // poll so the initial-load assertions can drain. Defaults true -> production behaviour is unchanged.
    internal var adBreakPollEnabled: Boolean = true

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
                        SessionPlaybackState.LIVE -> adGateThenPlay(title)
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
        adBreakPollJob?.cancel()
        // Detaching the reporter emits the viewer `leave` (best-effort, exactly once) and cancels the
        // bounded heartbeat — AND-285 FR-3/FR-9. No separate presence teardown loop exists.
        reporter.detach()
        presence.reset()
        controllerOrNull?.release()
        controllerOrNull = null
    }

    // ─── ADV FEATURE 1 — broadcast pre-roll gate ─────────────────────────────

    /**
     * Serves + gates a pre-roll ad before the live join. Calls POST .../ad-join; if a pre-roll is served
     * AND the viewer is not ad-free (subscriber / the broadcaster themselves — self-exclusion is enforced
     * server-side in serve_ad), enter the [ViewerUiState.PreRoll] AD phase and DEFER the live mint until
     * the ad completes/skips. Any ad-join failure / no-fill / ad-free viewer -> play live immediately
     * (an ad problem must NEVER block the broadcast).
     */
    private suspend fun adGateThenPlay(title: String) {
        val join = adRepo.adJoin(sessionId)
        val pre = (join as? ApiResult.Success)?.data?.preRoll
        val adFree = (join as? ApiResult.Success)?.data?.adFree ?: false
        if (pre != null && !adFree) {
            enterPreRoll(title, pre)
        } else {
            acquireAndPlay(title)
        }
    }

    private fun enterPreRoll(title: String, pre: BroadcastPreRoll) {
        val skipMs = pre.skipAfterSeconds * 1000L
        // Image creative: hold for skip-after + a short tail (auto-completes -> charge). Video creative:
        // completion is driven by the player ENDED; the cap only bounds the countdown display.
        val durationMs = if (pre.isImage) skipMs + PREROLL_IMAGE_HOLD_MS else skipMs + PREROLL_VIDEO_CAP_MS
        _uiState.value = ViewerUiState.PreRoll(
            sessionId = sessionId,
            title = title,
            ad = pre,
            durationMs = durationMs,
            remainingMs = if (pre.isImage) durationMs else skipMs,
            skipEnabled = false,
            skipCountdownMs = skipMs,
        )
        // Impression fires once at the start of the pre-roll (charges advertiser + credits broadcaster;
        // funds-guarded + idempotent per broadcast_preroll:{ad_click_id} on the backend).
        trackPreRoll(pre, BroadcastAdEvents.IMPRESSION, 0)
    }

    /** Composable-driven ad clock: [elapsedMs] since the pre-roll started. Updates remaining / skip state. */
    fun onPreRollPosition(elapsedMs: Long) {
        val s = _uiState.value as? ViewerUiState.PreRoll ?: return
        val skipMs = s.ad.skipAfterSeconds * 1000L
        val skipCountdown = (skipMs - elapsedMs).coerceAtLeast(0L)
        val remaining = if (s.ad.isImage) (s.durationMs - elapsedMs).coerceAtLeast(0L) else skipCountdown
        _uiState.update {
            (it as? ViewerUiState.PreRoll)?.copy(
                remainingMs = remaining,
                skipCountdownMs = skipCountdown,
                skipEnabled = elapsedMs >= skipMs,
            ) ?: it
        }
    }

    /** The pre-roll finished (image hold elapsed / video ENDED) — charge complete, then join live. */
    fun onPreRollCompleted() {
        val s = _uiState.value as? ViewerUiState.PreRoll ?: return
        trackPreRoll(s.ad, BroadcastAdEvents.COMPLETE, s.durationMs.toInt())
        proceedToLive(s.title)
    }

    /** The viewer skipped the pre-roll — record skip (no charge), then join live. */
    fun onPreRollSkip() {
        val s = _uiState.value as? ViewerUiState.PreRoll ?: return
        trackPreRoll(s.ad, BroadcastAdEvents.SKIP, 0)
        proceedToLive(s.title)
    }

    private fun proceedToLive(title: String) {
        _uiState.value = ViewerUiState.Loading
        viewModelScope.launch { acquireAndPlay(title) }
    }

    private fun trackPreRoll(pre: BroadcastPreRoll, event: String, viewTimeMs: Int) {
        viewModelScope.launch {
            adRepo.track(sessionId, pre.creativeId, event, pre.adClickId, viewTimeMs)
        }
    }

    // ADV2-105 - broadcast MID-ROLL interrupt / resume

    /** Break identity (started-at) already served, so the SAME break is never re-entered (ADV2-105 guard). */
    private var lastServedBreakStartedAt: Long? = null
    private var adBreakPollJob: Job? = null

    /**
     * Bounded poll (reuses the ~2s chat-poll cadence) that runs WHILE the viewer watches live. Poll-based on
     * purpose: on-device SSE is unreliable, so detection reads the persisted ad_break state. On a newly-active
     * break it serves + interrupts. Cancelled in [onCleared]; stopped while a mid-roll shows, re-armed on resume.
     */
    private fun startAdBreakPoll() {
        if (!adBreakPollEnabled) return
        adBreakPollJob?.cancel()
        adBreakPollJob = viewModelScope.launch {
            while (isActive) {
                delay(AD_BREAK_POLL_INTERVAL_MS)
                val ready = _uiState.value as? ViewerUiState.Ready ?: continue
                val data = (adRepo.adBreakState(sessionId) as? ApiResult.Success)?.data ?: continue
                if (data.adBreakActive && data.adBreakStartedAt != lastServedBreakStartedAt) {
                    if (enterMidRoll(ready, data.adBreakStartedAt)) {
                        return@launch // paused for the break; resume re-arms the poll
                    }
                    // else: fell open (ad-free / no-fill / serve failed) -> keep watching + polling.
                }
            }
        }
    }

    /**
     * Serves a per-viewer mid-roll and, IF a billable creative comes back, PAUSES the live media and shows the
     * ad overlay (returns true = interrupted). ADV2-107 client guard: a null creative / ad-free viewer / the
     * broadcaster themselves (server returns ad_free + no creative) is NEVER interrupted - fail open, keep
     * watching live (returns false). An ad must NEVER block the broadcast, so any serve failure stays live too.
     */
    private suspend fun enterMidRoll(live: ViewerUiState.Ready, breakStartedAt: Long?): Boolean {
        // Mark the break handled up-front so a serve failure / ad-free viewer never re-triggers this break.
        lastServedBreakStartedAt = breakStartedAt
        val serve = (adRepo.serveMidRoll(sessionId) as? ApiResult.Success)?.data
        val ad = serve?.ad
        if (serve == null || serve.adFree || ad == null) return false
        controllerOrNull?.pause() // OVERLAY-ONLY: pause our view of the still-running live stream
        val skipMs = ad.skipAfterSeconds * 1000L
        val durationMs = if (ad.isImage) skipMs + PREROLL_IMAGE_HOLD_MS else skipMs + PREROLL_VIDEO_CAP_MS
        _uiState.value = ViewerUiState.MidRoll(
            live = live,
            ad = ad,
            durationMs = durationMs,
            remainingMs = if (ad.isImage) durationMs else skipMs,
            skipEnabled = false,
            skipCountdownMs = skipMs,
        )
        // Impression charges the advertiser (CPM) + credits the broadcaster 70/30 (surface=broadcast_midroll),
        // funds-guarded + idempotent per broadcast_midroll:{ad_click_id} on the backend.
        trackMidRoll(ad, BroadcastAdEvents.IMPRESSION, 0)
        return true
    }

    /** Composable-driven ad clock for the mid-roll; mirrors [onPreRollPosition]. */
    fun onMidRollPosition(elapsedMs: Long) {
        val s = _uiState.value as? ViewerUiState.MidRoll ?: return
        val skipMs = s.ad.skipAfterSeconds * 1000L
        val skipCountdown = (skipMs - elapsedMs).coerceAtLeast(0L)
        val remaining = if (s.ad.isImage) (s.durationMs - elapsedMs).coerceAtLeast(0L) else skipCountdown
        _uiState.update {
            (it as? ViewerUiState.MidRoll)?.copy(
                remainingMs = remaining,
                skipCountdownMs = skipCountdown,
                skipEnabled = elapsedMs >= skipMs,
            ) ?: it
        }
    }

    /** The mid-roll finished (image hold elapsed / video ENDED) - charge complete, then resume to live edge. */
    fun onMidRollCompleted() {
        val s = _uiState.value as? ViewerUiState.MidRoll ?: return
        trackMidRoll(s.ad, BroadcastAdEvents.COMPLETE, s.durationMs.toInt())
        resumeLiveFromMidRoll(s)
    }

    /** The viewer skipped the mid-roll - record skip (no charge), then resume to live edge. */
    fun onMidRollSkip() {
        val s = _uiState.value as? ViewerUiState.MidRoll ?: return
        trackMidRoll(s.ad, BroadcastAdEvents.SKIP, 0)
        resumeLiveFromMidRoll(s)
    }

    /**
     * ADV2-211 (F2) - a CTA tap on the pre-roll / mid-roll CTA bar. Money side via the shared
     * [AdCtaClicker]: a NON-tip CTA fires the CPC charge (funds-guarded, idempotent) + stashes the
     * served ad_click_id so a resulting purchase/subscribe attributes CPA; a tip fires NO advertiser
     * charge. Navigation is the screen's concern (AdCtaRouter).
     */
    fun onCtaTap(action: CtaAction) {
        val ad = when (val st = _uiState.value) {
            is ViewerUiState.PreRoll -> st.ad
            is ViewerUiState.MidRoll -> st.ad
            else -> return
        }
        adCtaClicker.onTap(viewModelScope, ad.adClickId, action)
    }

    private fun trackMidRoll(ad: BroadcastPreRoll, event: String, viewTimeMs: Int) {
        viewModelScope.launch {
            adRepo.track(sessionId, ad.creativeId, event, ad.adClickId, viewTimeMs, BroadcastAdEvents.SLOT_MID_ROLL)
        }
    }

    /**
     * Resumes the LIVE stream after the mid-roll. Re-mints the signed URL if it expired while the ad played
     * (else re-attaches the saved URL when an ad VIDEO replaced the live media on the shared controller),
     * snaps to the LIVE EDGE, restores [ViewerUiState.Ready], and re-arms the break poll.
     */
    private fun resumeLiveFromMidRoll(s: ViewerUiState.MidRoll) {
        val live = s.live
        val servedVideo = !s.ad.isImage
        viewModelScope.launch {
            val expired = live.expiresAtEpochMs?.let { it - clock.now() <= MIN_REMAINING_MS } ?: false
            val restored: ViewerUiState.Ready = if (expired) {
                when (val mint = repo.mintPlaybackUrl(sessionId)) {
                    is ApiResult.Success -> {
                        controller.setMedia(mediaSpec(mint.data.playbackUrl, live.title), autoPlay = true)
                        live.copy(
                            playbackUrl = mint.data.playbackUrl,
                            expiresAtEpochMs = mint.data.expiresAt.toEpochMilli(),
                            atLiveEdge = true,
                        )
                    }
                    is ApiResult.Failure -> { _uiState.value = mint.error.toUnavailableOrError(); return@launch }
                    is ApiResult.NetworkError -> { _uiState.value = ViewerUiState.Offline; return@launch }
                }
            } else {
                if (servedVideo) {
                    controller.setMedia(mediaSpec(live.playbackUrl, live.title), autoPlay = true)
                } else {
                    controllerOrNull?.play()
                }
                live.copy(atLiveEdge = true)
            }
            controllerOrNull?.seekTo(Long.MAX_VALUE) // clamp to the LIVE EDGE
            _uiState.value = restored
            startAdBreakPoll()
        }
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
                startAdBreakPoll()
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

        /** ADV FEATURE 1 — image pre-roll auto-completes this long after the skip-after point. */
        const val PREROLL_IMAGE_HOLD_MS = 3_000L

        /** ADV FEATURE 1 — upper bound on the video pre-roll countdown display (completion is via ENDED). */
        const val PREROLL_VIDEO_CAP_MS = 60_000L

        /** ADV2-105 - mid-roll break poll cadence while watching live (reuses the ~2s chat-poll cadence). */
        const val AD_BREAK_POLL_INTERVAL_MS = 2_000L

        /** Below this remaining window the web client skips scheduling a refresh (≤10s). */
        const val MIN_REMAINING_MS = 10_000L

        /** Refresh at 75% of remaining lifetime (web: remainingSec * 750ms). */
        const val REFRESH_FRACTION_NUM = 3L
        const val REFRESH_FRACTION_DEN = 4L
    }
}
