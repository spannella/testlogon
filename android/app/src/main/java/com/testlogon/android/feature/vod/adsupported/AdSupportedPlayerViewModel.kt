package com.testlogon.android.feature.vod.adsupported

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.vod.adsupported.AdBreak
import com.testlogon.android.data.vod.adsupported.AdBreakScheduler
import com.testlogon.android.data.vod.adsupported.AdSupportedSession
import com.testlogon.android.data.vod.adsupported.VodAdSupportedApi
import com.testlogon.android.data.vod.adsupported.VodAdSupportedRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-194 — which timeline is on screen. */
enum class PlaybackPhase { CONTENT, AD }

/**
 * AND-194 — ad-supported playback UI state. Content controls (scrub / forward-seek) are disabled while
 * [phase] == AD; the skip affordance enables only after the current break's skip offset elapses; the
 * content timeline is gated server-side via [playbackUnlocked] / [nextRequiredBreakId].
 */
sealed interface AdSupportedUiState {
    data object Loading : AdSupportedUiState
    data class Error(val message: String, val offline: Boolean) : AdSupportedUiState
    data class Ready(
        val contentUrl: String,
        val phase: PlaybackPhase,
        val currentBreak: AdBreak?,
        val adRemainingMs: Long,
        val skipEnabled: Boolean,
        val skipCountdownMs: Long,
        val playbackUnlocked: Boolean,
        val nextRequiredBreakId: String?,
        val breaksCompleted: Int,
        val breaksTotal: Int,
        val adsFree: Boolean,
    ) : AdSupportedUiState
}

@HiltViewModel
class AdSupportedPlayerViewModel @Inject constructor(
    private val repo: VodAdSupportedRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val videoId: String = checkNotNull(savedStateHandle[ARG_VIDEO_ID]) { "missing videoId arg" }

    private val _uiState = MutableStateFlow<AdSupportedUiState>(AdSupportedUiState.Loading)
    val uiState: StateFlow<AdSupportedUiState> = _uiState.asStateFlow()

    private var session: AdSupportedSession? = null
    private var scheduler: AdBreakScheduler? = null
    private var adPositionMs: Long = 0L

    init {
        start()
    }

    fun start() {
        _uiState.update { AdSupportedUiState.Loading }
        viewModelScope.launch {
            when (val r = repo.start(videoId)) {
                is ApiResult.Success -> onStarted(r.data)
                is ApiResult.Failure -> _uiState.update {
                    AdSupportedUiState.Error(r.error.message, offline = false)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    AdSupportedUiState.Error(MSG_OFFLINE, offline = true)
                }
            }
        }
    }

    fun retry() = start()

    private fun onStarted(s: AdSupportedSession) {
        session = s
        scheduler = AdBreakScheduler(s.adSchedule)
        adPositionMs = 0L
        // ads_free => straight to content. Otherwise a pre-roll (if any) plays first.
        val preRoll = if (s.adsFree) null else scheduler?.preRoll()?.takeIf { !it.completed }
        if (preRoll != null) {
            enterAd(preRoll)
        } else {
            enterContent()
        }
    }

    /** Feeds the ad-creative position from the player listener while [PlaybackPhase.AD]. */
    fun onAdPosition(ms: Long) {
        val ready = _uiState.value as? AdSupportedUiState.Ready ?: return
        if (ready.phase != PlaybackPhase.AD) return
        val br = ready.currentBreak ?: return
        adPositionMs = ms
        val remaining = (br.durationMs - ms).coerceAtLeast(0L)
        val skipCountdown = (br.skipAfterMs - ms).coerceAtLeast(0L)
        val skipEnabled = br.isSkippable && ms >= br.skipAfterMs
        _uiState.update {
            (it as? AdSupportedUiState.Ready)?.copy(
                adRemainingMs = remaining,
                skipCountdownMs = skipCountdown,
                skipEnabled = skipEnabled,
            ) ?: it
        }
    }

    /** Content position from the player listener; crossing an unwatched mid-roll cue enters that ad. */
    fun onContentPosition(ms: Long) {
        val ready = _uiState.value as? AdSupportedUiState.Ready ?: return
        if (ready.phase != PlaybackPhase.CONTENT) return
        val due = scheduler?.breakCrossedBy(ms) ?: return
        enterAd(due)
    }

    /** Requests a forward seek; gated breaks snap to the ad first, then resume at the target. */
    fun onSeekRequested(currentMs: Long, targetMs: Long): Boolean {
        val sch = scheduler ?: return true
        val due = sch.breakDueForSeek(currentMs, targetMs)
        return if (due != null) {
            enterAd(due)
            false // seek blocked; ad plays first
        } else {
            true // allowed
        }
    }

    /** User tapped Skip; reports `skip` and advances out of the ad. */
    fun onSkipAd() {
        val br = (_uiState.value as? AdSupportedUiState.Ready)?.currentBreak ?: return
        reportAndAdvance(br, VodAdSupportedApi.EVENT_SKIP)
    }

    /** The ad creative finished; reports `complete` and advances. */
    fun onAdCompleted() {
        val br = (_uiState.value as? AdSupportedUiState.Ready)?.currentBreak ?: return
        reportAndAdvance(br, VodAdSupportedApi.EVENT_COMPLETE)
    }

    private fun reportAndAdvance(br: AdBreak, eventType: String) {
        viewModelScope.launch {
            when (val r = repo.reportBreak(videoId, br.breakId, eventType)) {
                is ApiResult.Success -> {
                    // Server-authoritative: apply unlock + watched, then resume content.
                    scheduler?.markWatched(br.breakId)
                    val report = r.data
                    _uiState.update {
                        (it as? AdSupportedUiState.Ready)?.copy(
                            playbackUnlocked = report.playbackUnlocked,
                            nextRequiredBreakId = report.nextRequiredBreakId,
                            breaksCompleted = report.breaksCompleted,
                            breaksTotal = report.breaksTotal,
                        ) ?: it
                    }
                    enterContent()
                }
                else -> {
                    // Mandatory mid-roll report failed: keep the gate closed (stay in the ad phase).
                    // Overlay/non-mandatory could resume; mid-roll must not skip the gate.
                    if (!br.isMidRoll) enterContent()
                    // else: remain in AD; the screen surfaces a retry on the report.
                }
            }
        }
    }

    private fun enterAd(br: AdBreak) {
        adPositionMs = 0L
        // Fire an impression (best-effort); does not block.
        viewModelScope.launch { repo.reportBreak(videoId, br.breakId, VodAdSupportedApi.EVENT_IMPRESSION) }
        _uiState.update {
            readyBase().copy(
                phase = PlaybackPhase.AD,
                currentBreak = br,
                adRemainingMs = br.durationMs,
                skipEnabled = false,
                skipCountdownMs = br.skipAfterMs,
            )
        }
    }

    private fun enterContent() {
        _uiState.update {
            readyBase().copy(
                phase = PlaybackPhase.CONTENT,
                currentBreak = null,
                adRemainingMs = 0L,
                skipEnabled = false,
                skipCountdownMs = 0L,
            )
        }
    }

    private fun readyBase(): AdSupportedUiState.Ready {
        val s = session
        val prev = _uiState.value as? AdSupportedUiState.Ready
        return prev ?: AdSupportedUiState.Ready(
            contentUrl = s?.playbackUrl.orEmpty(),
            phase = PlaybackPhase.CONTENT,
            currentBreak = null,
            adRemainingMs = 0L,
            skipEnabled = false,
            skipCountdownMs = 0L,
            playbackUnlocked = s?.playbackUnlocked ?: false,
            nextRequiredBreakId = s?.nextRequiredBreakId,
            breaksCompleted = s?.breaksCompleted ?: 0,
            breaksTotal = s?.breaksTotal ?: 0,
            adsFree = s?.adsFree ?: false,
        )
    }

    companion object {
        const val ARG_VIDEO_ID = "videoId"
        private const val MSG_OFFLINE = "You're offline. Try again."
    }
}
