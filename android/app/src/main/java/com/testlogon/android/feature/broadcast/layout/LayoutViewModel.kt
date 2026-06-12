package com.testlogon.android.feature.broadcast.layout

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.broadcast.BroadcastInput
import com.testlogon.android.data.broadcast.BroadcastLayout
import com.testlogon.android.data.broadcast.InputsRepository
import com.testlogon.android.data.broadcast.LayoutPosition
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-311 — presentation logic for the broadcast LAYOUT-management surface.
 *
 * [uiState] combines the Room-backed layout Flow ([LayoutRepository.observeLayout], AND-310 cache) + the
 * inputs Flow ([InputsRepository.observeInputs], AND-310, to compute [LayoutUiState.Content.activeInputCount]
 * and `needsSource`) + transient UI flows (pendingMode, stale, banner, cold error, in-memory positions) into
 * the sealed [LayoutUiState]. The four [ModeCard]s are a STATIC client list ([LayoutModeUi.SELECTABLE]) —
 * never fetched. The current mode is the cached layout mode (or [LayoutModeUi.SINGLE] when none is cached).
 *
 * onSelectMode is OPTIMISTIC: selecting the live mode is a NO-OP (FR-5, no redundant POST); selecting
 * another mode sets [pendingMode] (optimistic live badge) and POSTs the switch, clearing pendingMode on
 * success (the server layout is upserted into the cache) or rolling back + bannering on failure.
 *
 * POSITIONS (FR-4): positions are NOT persisted in Room (no migration). The read-only positions list is held
 * in [positions] (a MutableStateFlow) and refreshed from the in-memory [BroadcastLayout] returned by
 * [LayoutRepository.refresh] / [LayoutRepository.setLayout].
 *
 * A poll loop (refresh every [pollIntervalMillis]) runs only while the screen is subscribed. The interval is
 * a SETTABLE PROPERTY (NOT a constructor param — Hilt cannot inject a bare Long), so unit tests drive a
 * SINGLE iteration with runCurrent. Polling is NOT auto-started in init (an unbounded delay loop there would
 * spin runTest forever); the screen drives [startPolling] / [stopPolling] from a DisposableEffect.
 */
@HiltViewModel
class LayoutViewModel @Inject constructor(
    savedState: SavedStateHandle,
    private val layoutRepository: LayoutRepository,
    private val inputsRepository: InputsRepository,
) : ViewModel() {

    val sessionId: String = savedState.get<String>(ARG_SESSION_ID).orEmpty()

    /**
     * Poll interval (ms). NOT a constructor param — Hilt cannot provide a bare [Long] and ignores Kotlin
     * defaults. Tests set this directly after construction to drive fast single iterations.
     */
    internal var pollIntervalMillis: Long = DEFAULT_POLL_INTERVAL_MILLIS

    /** Optimistic in-flight switch target (rendered as the live badge; grid non-interactive while set). */
    private val pendingMode = MutableStateFlow<LayoutModeUi?>(null)

    /** Set when a refresh fails while a cached mode is shown (warm-cache stale). */
    private val stale = MutableStateFlow(false)

    /** One-shot human-readable banner (e.g. a rolled-back switch failure). */
    private val banner = MutableStateFlow<String?>(null)

    /** Cold-cache error (nothing cached AND a load failed). Null while content is renderable. */
    private val coldError = MutableStateFlow<ColdError?>(null)

    /** Read-only, in-memory positions from the last successful refresh (FR-4; not persisted in Room). */
    private val positions = MutableStateFlow<List<LayoutPosition>>(emptyList())

    private var pollJob: Job? = null

    private val transient =
        combine(pendingMode, stale, banner, coldError, positions) { pending, s, b, c, pos ->
            TransientState(pending, s, b, c, pos)
        }

    val uiState: StateFlow<LayoutUiState> =
        combine(
            layoutRepository.observeLayout(sessionId),
            inputsRepository.observeInputs(sessionId),
            transient,
        ) { layout, inputs, t ->
            reduce(layout, inputs, t)
        }.stateIn(
            scope = viewModelScope,
            started = SharingStarted.Eagerly,
            initialValue = LayoutUiState.Loading,
        )

    init {
        // NOTE: polling is NOT auto-started — an unbounded delay loop in init would spin runTest's
        // end-of-test drain forever. The screen drives [startPolling]/[stopPolling] from a DisposableEffect
        // (mirrors AND-310's InputsViewModel). Tests start it explicitly, drive ONE iteration with
        // runCurrent, then call [stopPolling] before the test ends.
        if (sessionId.isBlank()) {
            coldError.value = ColdError(NO_SESSION, retryable = false)
        }
    }

    /**
     * Begins the poll loop (refresh, then delay) while the screen is resumed. Bounded to [viewModelScope];
     * tests set [pollIntervalMillis], drive a SINGLE iteration with runCurrent, then call [stopPolling].
     * Safe to call repeatedly. No-op for a blank session.
     */
    fun startPolling() {
        if (sessionId.isBlank()) return
        if (pollJob != null) return
        pollJob = viewModelScope.launch {
            while (isActive) {
                applyRefreshOutcome(layoutRepository.refresh(sessionId))
                delay(pollIntervalMillis)
            }
        }
    }

    /** Updates cold-error / stale flags and the in-memory positions from a layout-refresh outcome. */
    private fun applyRefreshOutcome(result: ApiResult<BroadcastLayout>) {
        when (result) {
            is ApiResult.Success -> {
                stale.value = false
                coldError.value = null
                positions.value = result.data.positions
            }
            is ApiResult.Failure -> onRefreshFailed(result.error.message, retryable = false)
            is ApiResult.NetworkError -> onRefreshFailed(OFFLINE, retryable = true)
        }
    }

    /**
     * A refresh failed: if we already have a cached mode, mark stale (warm cache); otherwise surface a cold
     * error. The reducer decides which one wins based on whether a layout is cached.
     */
    private fun onRefreshFailed(message: String, retryable: Boolean) {
        stale.value = true
        coldError.value = ColdError(message, retryable)
    }

    /**
     * Switch the broadcast layout to [mode]. Selecting the live mode is a NO-OP (FR-5, no redundant POST).
     * Otherwise sets [pendingMode] (optimistic live badge) and POSTs the switch; on success the refreshed
     * server layout is upserted (clearing pendingMode), on failure it rolls back + banners.
     */
    fun onSelectMode(mode: LayoutModeUi) {
        if (sessionId.isBlank()) return
        if (mode == LayoutModeUi.UNKNOWN) return
        if (mode == currentModeOrDefault()) return
        if (pendingMode.value != null) return
        pendingMode.value = mode
        viewModelScope.launch {
            when (val result = layoutRepository.setLayout(sessionId, mode.wire)) {
                is ApiResult.Success -> {
                    // The authoritative layout arrived via the cache upsert -> drop the optimistic target.
                    pendingMode.value = null
                    positions.value = result.data.positions
                    stale.value = false
                }
                is ApiResult.Failure -> rollback(result.error.message)
                is ApiResult.NetworkError -> rollback(OFFLINE)
            }
        }
    }

    private fun rollback(message: String) {
        pendingMode.value = null
        banner.value = message
    }

    /** Retry a cold-cache failure (or a stale warm cache): re-run a single layout refresh. */
    fun onRetry() {
        if (sessionId.isBlank()) return
        viewModelScope.launch {
            applyRefreshOutcome(layoutRepository.refresh(sessionId))
        }
    }

    /** Clears the one-shot banner after the UI has shown it. */
    fun consumeBanner() {
        banner.value = null
    }

    /** Stops the poll loop (called by the screen when paused/disposed; tests call it before finishing). */
    fun stopPolling() {
        pollJob?.cancel()
        pollJob = null
    }

    override fun onCleared() {
        pollJob?.cancel()
    }

    /** The current (cached) mode, defaulting to SINGLE when nothing is cached. */
    private fun currentModeOrDefault(): LayoutModeUi =
        lastCachedWire?.let { LayoutModeUi.fromWire(it) } ?: LayoutModeUi.SINGLE

    /** Last wire mode seen from the cache (null = nothing cached yet -> SINGLE default). */
    private var lastCachedWire: String? = null

    /**
     * Pure-ish reducer: derives the current mode (optimistic [pendingMode] wins for the live badge), builds
     * the four fixed [ModeCard]s, and picks Loading / Content / Error. A cached mode (warm) wins over a cold
     * error even when a refresh just failed — the failure shows as the stale flag instead.
     */
    private fun reduce(
        layout: BroadcastLayout?,
        inputs: List<BroadcastInput>,
        t: TransientState,
    ): LayoutUiState {
        lastCachedWire = layout?.mode
        val cachedMode = if (layout != null) LayoutModeUi.fromWire(layout.mode) else null
        val activeInputCount = inputs.count { it.isLive }
        val needsSource = activeInputCount == 0

        // The badge follows the optimistic pending target if one is in flight, else the cached/default mode.
        val effectiveCurrent = t.pendingMode ?: cachedMode ?: LayoutModeUi.SINGLE

        if (layout == null && t.coldError != null) {
            return LayoutUiState.Error(t.coldError.message, t.coldError.retryable)
        }

        val cards = LayoutModeUi.SELECTABLE.map { mode ->
            val isLive = mode == effectiveCurrent
            ModeCard(
                mode = mode,
                isLive = isLive,
                isSelectable = !isLive && t.pendingMode == null,
                needsSource = needsSource,
            )
        }
        return LayoutUiState.Content(
            cards = cards,
            currentMode = effectiveCurrent,
            activeInputCount = activeInputCount,
            isStale = t.stale,
            banner = t.banner,
            pendingMode = t.pendingMode,
            positions = t.positions,
        )
    }

    private data class TransientState(
        val pendingMode: LayoutModeUi?,
        val stale: Boolean,
        val banner: String?,
        val coldError: ColdError?,
        val positions: List<LayoutPosition>,
    )

    private data class ColdError(val message: String, val retryable: Boolean)

    companion object {
        /** Nav arg carrying the broadcast session id. */
        const val ARG_SESSION_ID = "sessionId"

        /** Default poll interval (ms). Override via [pollIntervalMillis] in tests. */
        const val DEFAULT_POLL_INTERVAL_MILLIS = 5_000L

        // Non-resource fallbacks (the screen prefers stringResource where it has a Context).
        private const val NO_SESSION = "No broadcast session is available."
        private const val OFFLINE = "Couldn't reach the server. Try again."
    }
}
