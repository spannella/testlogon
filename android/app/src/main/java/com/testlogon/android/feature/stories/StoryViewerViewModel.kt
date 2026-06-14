package com.testlogon.android.feature.stories

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.stories.StorySegment
import com.testlogon.android.data.stories.StoriesRepository
import com.testlogon.android.data.stories.StoryBarItem
import com.testlogon.android.data.stories.StoryReplyRepository
import com.testlogon.android.feature.player.PlaybackPhase
import com.testlogon.android.feature.player.VideoPlayerController
import com.testlogon.android.feature.videos.detail.VideoControllerProvider
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject

/** Lifecycle phase of the viewer (AND-199 §4). */
enum class ViewerPhase { LOADING, PLAYING, ERROR, DONE }

/** Quick-reaction + reply composer state (AND-200 §4.1). */
data class ComposerState(
    val replyText: String = "",
    val reactionsExpanded: Boolean = false,
    val sending: Boolean = false,
    val sendError: String? = null,
)

/**
 * AND-199 + AND-200 — viewer UI state. The author list (tray order) drives cross-author advance; the
 * current author's segments are loaded lazily. [progress] is 0f..1f for the active segment.
 */
data class StoryViewerUiState(
    val authors: List<StoryBarItem> = emptyList(),
    val authorIndex: Int = 0,
    val segments: List<StorySegment> = emptyList(),
    val segmentIndex: Int = 0,
    val progress: Float = 0f,
    val paused: Boolean = false,
    val composer: ComposerState = ComposerState(),
    val phase: ViewerPhase = ViewerPhase.LOADING,
) {
    val currentAuthor: StoryBarItem? get() = authors.getOrNull(authorIndex)
    val currentSegment: StorySegment? get() = segments.getOrNull(segmentIndex)
    val isOwnStory: Boolean get() = currentAuthor?.isOwn == true
}

/** One-shot viewer effects (AND-200) — Channel-backed, never on a StateFlow. */
sealed interface StoryViewerEffect {
    data object Dismiss : StoryViewerEffect
    data class ReactionSent(val emoji: String) : StoryViewerEffect
    data object ReplySent : StoryViewerEffect
    data class ShowError(val message: String) : StoryViewerEffect
}

/**
 * AND-199 / AND-200 — full-screen story viewer state machine.
 *
 * Reuses the shared AND-168 player via [VideoControllerProvider] for video segments (created lazily,
 * released in onCleared — no second player, no eager ExoPlayer) and the bounded image timer loop for
 * image segments. Timing math is delegated to the pure [StorySegmentTimer]/[StoryNavigator]; the only
 * coroutine here is a BOUNDED tick loop that exits once the segment completes (so virtual-time tests
 * never hang). One-shot effects use a Channel + receiveAsFlow.
 */
@HiltViewModel
class StoryViewerViewModel @Inject constructor(
    private val repo: StoriesRepository,
    private val replyRepo: StoryReplyRepository,
    private val controllerProvider: VideoControllerProvider,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val initialUserId: String = checkNotNull(savedStateHandle.get<String>(ARG_USER_ID)) {
        "missing userId arg"
    }

    private val _uiState = MutableStateFlow(StoryViewerUiState())
    val uiState: StateFlow<StoryViewerUiState> = _uiState.asStateFlow()

    private val effects = Channel<StoryViewerEffect>(Channel.BUFFERED)
    val effectFlow = effects.receiveAsFlow()

    private val timer = StorySegmentTimer()
    private var tickJob: Job? = null

    /** Reaction emojis already in flight to debounce rapid double-taps (R-3). */
    private var reactionInFlight = false

    // Lifecycle-scoped controller, created PER-SCREEN on first video segment (not eagerly) and released
    // in onCleared. Null until a video segment is shown so an all-image story never spins up an ExoPlayer.
    private var controllerOrNull: VideoPlayerController? = null
    val controllerForUi: VideoPlayerController
        get() = controllerOrNull ?: controllerProvider.create().also { controllerOrNull = it }

    init {
        viewModelScope.launch { bootstrap() }
    }

    /** Resolves the tray (for cross-author advance), positions at the tapped author, loads its stories. */
    private suspend fun bootstrap() {
        val tray = when (val r = repo.refreshTray()) {
            is ApiResult.Success -> r.data
            else -> emptyList()
        }
        val authors = tray.ifEmpty { listOf(syntheticAuthor(initialUserId)) }
        val startIndex = authors.indexOfFirst { it.userId == initialUserId }.coerceAtLeast(0)
        _uiState.update { it.copy(authors = authors, authorIndex = startIndex) }
        loadCurrentAuthor()
    }

    /** A minimal placeholder author when the bar is unavailable but we still know the tapped user id. */
    private fun syntheticAuthor(userId: String) = StoryBarItem(
        userId = userId,
        latestStoryId = "",
        latestMediaUrl = null,
        storyCount = 0,
        hasUnseen = true,
        isOwn = false,
    )

    private suspend fun loadCurrentAuthor() {
        val author = _uiState.value.currentAuthor ?: run { finish(); return }
        _uiState.update { it.copy(phase = ViewerPhase.LOADING, segments = emptyList(), segmentIndex = 0, progress = 0f) }
        when (val r = repo.loadAuthorStories(author.userId)) {
            is ApiResult.Success -> {
                if (r.data.isEmpty()) {
                    // Empty author -> skip to the next author (defensive; bar should not list them).
                    advanceAuthorOrFinish()
                } else {
                    _uiState.update { it.copy(segments = r.data, segmentIndex = 0, phase = ViewerPhase.PLAYING) }
                    onSegmentShown()
                }
            }
            is ApiResult.Failure -> _uiState.update { it.copy(phase = ViewerPhase.ERROR) }
            is ApiResult.NetworkError -> _uiState.update { it.copy(phase = ViewerPhase.ERROR) }
        }
    }

    /** Called whenever a segment becomes active: marks viewed, (re)starts the timer/player. */
    fun onSegmentShown() {
        val s = _uiState.value
        val segment = s.currentSegment ?: return
        viewModelScope.launch { repo.recordView(segment.storyId) }
        timer.reset(segment.durationMs)
        _uiState.update { it.copy(progress = 0f) }
        // Prepare the video source eagerly, but do NOT start ticking while paused/expanded (the loop is
        // started by onPauseHold/onReactionsToggle on resume) — this keeps the dispatcher idle for tests.
        if (segment.kind == com.testlogon.android.data.stories.SegmentKind.VIDEO) {
            controllerForUi.setMediaUri(segment.mediaUrl, autoPlay = !s.paused && !s.composer.reactionsExpanded)
        }
        if (s.paused || s.composer.reactionsExpanded) return
        when (segment.kind) {
            com.testlogon.android.data.stories.SegmentKind.IMAGE -> startImageLoop(segment.durationMs)
            com.testlogon.android.data.stories.SegmentKind.VIDEO -> startVideoSegment(segment, prepare = false)
        }
    }

    /**
     * BOUNDED image timer loop. It runs ONLY while not paused/expanded and exits as soon as the segment
     * completes — it is NEVER an open-ended while-true: pause CANCELS the job (so the dispatcher goes
     * idle, advanceUntilIdle never hangs) and resume restarts the loop from the saved elapsed.
     */
    private fun startImageLoop(durationMs: Long) {
        tickJob?.cancel()
        tickJob = viewModelScope.launch {
            while (isActive && timer.elapsedMs < durationMs) {
                delay(StorySegmentTimer.TICK_MS)
                val done = timer.tick(StorySegmentTimer.TICK_MS)
                _uiState.update { it.copy(progress = timer.progress) }
                if (done) break
            }
            if (isActive && timer.complete) onSegmentComplete()
        }
    }

    /**
     * Video segment: drives the shared player and polls its position to fill the bar; advances on end.
     * Runs only while not paused (pause cancels the job + the player); resume restarts the polling.
     */
    private fun startVideoSegment(segment: StorySegment, prepare: Boolean = true) {
        tickJob?.cancel()
        val controller = controllerForUi
        if (prepare) controller.setMediaUri(segment.mediaUrl, autoPlay = true)
        tickJob = viewModelScope.launch {
            while (isActive) {
                delay(StorySegmentTimer.TICK_MS)
                val playerState = controller.state.value
                val dur = playerState.durationMs
                if (dur > 0L) {
                    timer.setProgress((playerState.positionMs.toFloat() / dur).coerceIn(0f, 1f))
                    _uiState.update { it.copy(progress = timer.progress) }
                }
                if (playerState.phase == PlaybackPhase.ENDED) break
            }
            if (isActive && controller.state.value.phase == PlaybackPhase.ENDED) onSegmentComplete()
        }
    }

    /** Auto-advance: next segment in this author, else next author, else dismiss. */
    fun onSegmentComplete() {
        val s = _uiState.value
        val pos = StoryNavigator.next(
            authorIndex = s.authorIndex,
            segmentIndex = s.segmentIndex,
            currentAuthorSegmentCount = s.segments.size,
            authorCount = s.authors.size,
        )
        when {
            pos.done -> finish()
            pos.authorIndex != s.authorIndex -> {
                _uiState.update { it.copy(authorIndex = pos.authorIndex) }
                viewModelScope.launch { loadCurrentAuthor() }
            }
            else -> {
                _uiState.update { it.copy(segmentIndex = pos.segmentIndex, progress = 0f) }
                onSegmentShown()
            }
        }
    }

    /** Tap-right / manual next. */
    fun next() = onSegmentComplete()

    /** Tap-left / manual previous (crosses author boundaries; first-of-first restarts). */
    fun previous() {
        val s = _uiState.value
        val prevAuthorCount = s.authors.getOrNull(s.authorIndex - 1)?.storyCount?.coerceAtLeast(1) ?: 1
        val pos = StoryNavigator.previous(s.authorIndex, s.segmentIndex, prevAuthorCount)
        when {
            pos.authorIndex != s.authorIndex -> {
                _uiState.update { it.copy(authorIndex = pos.authorIndex) }
                // Load the previous author then jump to its (already-known-or-clamped) last segment.
                viewModelScope.launch {
                    loadCurrentAuthorThenIndex(pos.segmentIndex)
                }
            }
            else -> {
                _uiState.update { it.copy(segmentIndex = pos.segmentIndex, progress = 0f) }
                onSegmentShown()
            }
        }
    }

    private suspend fun loadCurrentAuthorThenIndex(targetIndex: Int) {
        val author = _uiState.value.currentAuthor ?: return
        _uiState.update { it.copy(phase = ViewerPhase.LOADING, segments = emptyList(), progress = 0f) }
        when (val r = repo.loadAuthorStories(author.userId)) {
            is ApiResult.Success -> {
                val idx = targetIndex.coerceIn(0, (r.data.size - 1).coerceAtLeast(0))
                _uiState.update { it.copy(segments = r.data, segmentIndex = idx, phase = ViewerPhase.PLAYING) }
                if (r.data.isNotEmpty()) onSegmentShown() else advanceAuthorOrFinish()
            }
            else -> _uiState.update { it.copy(phase = ViewerPhase.ERROR) }
        }
    }

    private fun advanceAuthorOrFinish() {
        val s = _uiState.value
        if (s.authorIndex + 1 < s.authors.size) {
            _uiState.update { it.copy(authorIndex = s.authorIndex + 1) }
            viewModelScope.launch { loadCurrentAuthor() }
        } else {
            finish()
        }
    }

    /**
     * Press-and-hold pause / release resume. Pause CANCELS the active tick loop (so the dispatcher goes
     * idle — no busy spin, no advanceUntilIdle hang) and pauses any video; resume restarts the loop from
     * the saved elapsed for the current segment.
     */
    fun onPauseHold(paused: Boolean) {
        _uiState.update { it.copy(paused = paused) }
        if (paused) {
            tickJob?.cancel()
            controllerOrNull?.pause()
        } else {
            resumeCurrentSegment()
        }
    }

    /** Resumes ticking for the current segment from its saved elapsed (used on pause-release). */
    private fun resumeCurrentSegment() {
        val segment = _uiState.value.currentSegment ?: return
        when (segment.kind) {
            com.testlogon.android.data.stories.SegmentKind.IMAGE -> startImageLoop(segment.durationMs)
            com.testlogon.android.data.stories.SegmentKind.VIDEO -> {
                controllerOrNull?.play()
                startVideoSegment(segment, prepare = false)
            }
        }
    }

    fun onClose() = finish()

    private fun finish() {
        tickJob?.cancel()
        // Optimistically restyle the rings of authors viewed so far so the tray shows "seen" on return.
        val s = _uiState.value
        s.authors.take(s.authorIndex + 1).forEach { repo.markAuthorSeen(it.userId) }
        _uiState.update { it.copy(phase = ViewerPhase.DONE) }
        viewModelScope.launch { effects.send(StoryViewerEffect.Dismiss) }
    }

    // ---- AND-200 composer ----

    fun onReplyTextChange(text: String) {
        _uiState.update { it.copy(composer = it.composer.copy(replyText = text, sendError = null)) }
    }

    fun onReactionsToggle(expanded: Boolean) {
        _uiState.update { it.copy(composer = it.composer.copy(reactionsExpanded = expanded)) }
        // Expanding the reaction row pauses progress; collapsing resumes (FR-7).
        if (expanded) {
            tickJob?.cancel()
            controllerOrNull?.pause()
        } else if (!_uiState.value.paused) {
            resumeCurrentSegment()
        }
    }

    fun sendReaction(emoji: String) {
        val s = _uiState.value
        val segment = s.currentSegment ?: return
        if (s.isOwnStory || reactionInFlight) return
        reactionInFlight = true
        _uiState.update { it.copy(composer = it.composer.copy(sending = true, reactionsExpanded = false)) }
        viewModelScope.launch {
            val result = replyRepo.reactToStory(segment.storyId, segment.authorId, emoji)
            reactionInFlight = false
            _uiState.update { it.copy(composer = it.composer.copy(sending = false)) }
            when (result) {
                is ApiResult.Success -> effects.send(StoryViewerEffect.ReactionSent(emoji))
                is ApiResult.Failure -> failComposer(result.error.message)
                is ApiResult.NetworkError -> failComposer(OFFLINE_MESSAGE)
            }
        }
    }

    fun sendReply(text: String) {
        val s = _uiState.value
        val segment = s.currentSegment ?: return
        val trimmed = text.trim()
        if (s.isOwnStory || trimmed.isEmpty()) return
        _uiState.update { it.copy(composer = it.composer.copy(sending = true)) }
        viewModelScope.launch {
            val result = replyRepo.replyToStory(segment.storyId, segment.authorId, trimmed)
            when (result) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(composer = ComposerState()) }
                    effects.send(StoryViewerEffect.ReplySent)
                }
                is ApiResult.Failure -> failComposer(result.error.message, restoreText = trimmed)
                is ApiResult.NetworkError -> failComposer(OFFLINE_MESSAGE, restoreText = trimmed)
            }
        }
    }

    private suspend fun failComposer(message: String, restoreText: String? = null) {
        _uiState.update {
            it.copy(
                composer = it.composer.copy(
                    sending = false,
                    sendError = message,
                    replyText = restoreText ?: it.composer.replyText,
                ),
            )
        }
        effects.send(StoryViewerEffect.ShowError(message))
    }

    override fun onCleared() {
        tickJob?.cancel()
        controllerOrNull?.release()
        controllerOrNull = null
        super.onCleared()
    }

    companion object {
        const val ARG_USER_ID = "userId"
        private const val OFFLINE_MESSAGE = "You're offline"
    }
}
