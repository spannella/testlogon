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
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.videos.VideoReactionState
import com.testlogon.android.data.videos.VideosRepository
import com.testlogon.android.feature.player.MediaSourceSpec
import com.testlogon.android.feature.player.VideoPlayerController
import com.testlogon.android.data.vod.adsupported.AdBreak
import com.testlogon.android.data.vod.adsupported.AdBreakScheduler
import com.testlogon.android.data.vod.adsupported.AdSupportedSession
import com.testlogon.android.data.vod.adsupported.VodAdSupportedApi
import com.testlogon.android.data.vod.adsupported.VodAdSupportedRepository
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
    // B-VIDSOCIAL2 - video-level emoji reactions (feed-post parity) + running tip total.
    val reactions: Map<String, Int> = emptyMap(),
    val myReactions: Set<String> = emptySet(),
    val tipTotalCents: Int = 0,
    // True when the current viewer owns this video (hide the tip action, like the feed does on own posts).
    val isMine: Boolean = false,
    // ADV — pre-roll ad-supported playback woven into the NORMAL detail player. While [contentGated]
    // the main content is NOT prepared/played; the pre-roll creative + [AdOverlay] own the surface.
    val adActive: Boolean = false,
    val adBreak: AdBreak? = null,
    val adRemainingMs: Long = 0L,
    val adSkipEnabled: Boolean = false,
    val adSkipCountdownMs: Long = 0L,
    val adBreaksCompleted: Int = 0,
    val adBreaksTotal: Int = 0,
    val contentGated: Boolean = false,
)

/** The emoji reaction set the server allows on a video (mirrors ALLOWED_VIDEO_REACTION_EMOJIS). */
val VIDEO_REACTIONS = listOf("\uD83D\uDC4D", "\u2764\uFE0F", "\uD83D\uDE02", "\uD83D\uDD25", "\uD83D\uDE2E")

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
    private val authStateStore: AuthStateStore,
    private val vodAdRepo: VodAdSupportedRepository,
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
     * B-VIDSOCIAL2 - toggle an emoji reaction on the video itself (feed-post parity). Optimistic: the
     * chip flips immediately and the server response (authoritative counts) reconciles it; on failure
     * the optimistic change rolls back.
     */
    fun toggleReaction(emoji: String) {
        val before = _uiState.value
        val mineNow = emoji in before.myReactions
        val newMine = before.myReactions.toMutableSet().apply { if (mineNow) remove(emoji) else add(emoji) }
        val newCounts = before.reactions.toMutableMap().apply {
            val c = (this[emoji] ?: 0) + if (mineNow) -1 else 1
            if (c > 0) this[emoji] = c else remove(emoji)
        }
        _uiState.update { it.copy(reactions = newCounts, myReactions = newMine) }
        viewModelScope.launch {
            val r = if (mineNow) repository.unreactVideo(videoId, emoji)
            else repository.reactVideo(videoId, emoji)
            when (r) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(reactions = r.data.reactions, myReactions = r.data.myReactions)
                }
                else -> _uiState.update { it.copy(reactions = before.reactions, myReactions = before.myReactions) }
            }
        }
    }

    /** Bumps the displayed running tip total after a successful tip (the sheet owns the charge flow). */
    fun applyTipTotal(tipTotalCents: Int) {
        _uiState.update { it.copy(tipTotalCents = tipTotalCents) }
    }

    /**
     * Idempotently hands the resolved HLS source to the reused player. Called from the screen once the
     * playback URL is available; safe to call repeatedly (prepares only once).
     */
    fun setPlaybackSource() {
        val url = _uiState.value.playbackUrl ?: return
        // Pre-roll must play first on an ad_supported video: the ad flow binds content itself.
        if (_uiState.value.contentGated) return
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
        val me = authStateStore.userSub.value
        val isMine = me != null && me == detail.ownerUserId
        // Weave the pre-roll into the normal player: gate content when this is an ad_supported
        // title the viewer can watch and does not own (owners preview their own content ad-free).
        val adGated = detail.accessMode == "ad_supported" && playable != null && !isMine
        _uiState.update {
            it.copy(
                contentGated = adGated,
                isLoading = false,
                detail = detail,
                playbackUrl = playable,
                playbackBlock = block,
                entitlement = entitlement,
                detailError = null,
                reactions = detail.reactions,
                myReactions = detail.myReactions,
                tipTotalCents = detail.tipTotalCents,
                isMine = isMine,
            )
        }
        loadLikeAndRelated()
        if (adGated) startPreRoll()
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

    // ─── ADV: pre-roll integrated into the NORMAL detail player ────────────────────────────────────
    // Mirrors AdSupportedPlayerViewModel but scoped to a single PRE-ROLL that gates the main content,
    // reusing the ONE lifecycle-scoped controller for both the ad creative and the content. The whole
    // detail screen (comments, likes, reactions, tip, engagement) stays composed throughout the ad.

    private var adScheduler: AdBreakScheduler? = null
    private var adSession: AdSupportedSession? = null
    private var adAdvancing = false

    /** Requests the ad-supported session; on a live pre-roll, enters the ad phase (content stays gated). */
    private fun startPreRoll() {
        viewModelScope.launch {
            when (val r = vodAdRepo.start(videoId)) {
                is ApiResult.Success -> onAdSessionStarted(r.data)
                // Fail-open to content (no ad shown, no charge) so a serve failure never blocks playback.
                else -> playContentPassively()
            }
        }
    }

    private fun onAdSessionStarted(session: AdSupportedSession) {
        adSession = session
        val scheduler = AdBreakScheduler(session.adSchedule)
        adScheduler = scheduler
        val preRoll = if (session.adsFree) null else scheduler.preRoll()?.takeIf { !it.completed }
        if (preRoll == null) {
            playContentPassively()
        } else {
            enterAd(preRoll)
        }
    }

    private fun enterAd(br: AdBreak) {
        // Fire the impression (best-effort); the completion report is what charges (backend ADV-203).
        viewModelScope.launch { vodAdRepo.reportBreak(videoId, br.breakId, VodAdSupportedApi.EVENT_IMPRESSION) }
        _uiState.update {
            it.copy(
                adActive = true,
                contentGated = true,
                adBreak = br,
                adRemainingMs = br.durationMs,
                adSkipEnabled = false,
                adSkipCountdownMs = br.skipAfterMs,
                adBreaksTotal = (adSession?.breaksTotal ?: 1).coerceAtLeast(1),
                adBreaksCompleted = adSession?.breaksCompleted ?: 0,
            )
        }
    }

    /** Position ticks from the screen while the pre-roll plays; enables Skip after the skip offset. */
    fun onAdPosition(ms: Long) {
        val st = _uiState.value
        if (!st.adActive) return
        val br = st.adBreak ?: return
        val remaining = (br.durationMs - ms).coerceAtLeast(0L)
        val skipCd = (br.skipAfterMs - ms).coerceAtLeast(0L)
        val skipEnabled = br.isSkippable && ms >= br.skipAfterMs
        _uiState.update {
            it.copy(adRemainingMs = remaining, adSkipCountdownMs = skipCd, adSkipEnabled = skipEnabled)
        }
    }

    fun onSkipAd() { _uiState.value.adBreak?.let { reportAndAdvance(it, VodAdSupportedApi.EVENT_SKIP) } }
    fun onAdCompleted() { _uiState.value.adBreak?.let { reportAndAdvance(it, VodAdSupportedApi.EVENT_COMPLETE) } }

    private fun reportAndAdvance(br: AdBreak, eventType: String) {
        if (adAdvancing) return
        adAdvancing = true
        viewModelScope.launch {
            // Report complete|skip (complete charges the advertiser + credits the poster server-side),
            // then lift the gate and play the content on the SAME controller.
            vodAdRepo.reportBreak(videoId, br.breakId, eventType)
            adScheduler?.markWatched(br.breakId)
            finishAdAndPlayContent()
            adAdvancing = false
        }
    }

    /** Ends the ad phase and starts the gated content (autoplay — the viewer already committed to watch). */
    private fun finishAdAndPlayContent() {
        _uiState.update {
            it.copy(
                adActive = false,
                adBreak = null,
                contentGated = false,
                adRemainingMs = 0L,
                adSkipEnabled = false,
                adSkipCountdownMs = 0L,
            )
        }
        playContent(autoPlay = true)
    }

    /** No pre-roll (ads-free / serve miss): lift the gate and prepare content the normal way (no autoplay). */
    private fun playContentPassively() {
        _uiState.update { it.copy(adActive = false, contentGated = false) }
        setPlaybackSource()
    }

    private fun playContent(autoPlay: Boolean) {
        val url = _uiState.value.playbackUrl ?: return
        sourcePrepared = true
        controller.setMedia(
            MediaSourceSpec(uri = url, title = _uiState.value.detail?.title),
            autoPlay = autoPlay,
        )
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
