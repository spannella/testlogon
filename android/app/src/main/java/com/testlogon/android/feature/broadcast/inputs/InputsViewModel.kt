package com.testlogon.android.feature.broadcast.inputs

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.broadcast.BroadcastInput
import com.testlogon.android.data.broadcast.BroadcastLayout
import com.testlogon.android.data.broadcast.InputsRepository
import com.testlogon.android.data.broadcast.LayoutMode
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-310 — presentation logic for the broadcast inputs-management surface.
 *
 * [uiState] is derived by combining the Room-backed inputs Flow + layout Flow + transient UI flows
 * (pending toggles, stale, banner) into the sealed [InputsUiState]. The PROGRAM input is derived here by
 * joining each input against the layout's `primary_input_id` (id == primaryInputId -> isProgram). Toggle is
 * OPTIMISTIC: the input id goes into pendingIds with an optimistic is_live overlay, the repo runs, and on
 * success pending clears (authoritative state arrives from the refetch) / on failure it rolls back + shows a
 * banner. "Make live" POSTs the layout with the current mode (or "single") + the target as primary_input_id.
 *
 * A poll loop (refresh + refreshLayout every [pollIntervalMillis]) runs while the screen is subscribed. The
 * interval is a SETTABLE PROPERTY (NOT a constructor param — Hilt cannot inject a bare Long or honour Kotlin
 * ctor defaults), so unit tests drive a SINGLE iteration with runCurrent (never advanceUntilIdle).
 */
@HiltViewModel
class InputsViewModel @Inject constructor(
    savedState: SavedStateHandle,
    private val repository: InputsRepository,
) : ViewModel() {

    val sessionId: String = savedState.get<String>(ARG_SESSION_ID).orEmpty()

    /**
     * Poll interval (ms). NOT a constructor param — Hilt cannot provide a bare [Long] and ignores Kotlin
     * defaults. Tests set this directly after construction to drive fast single iterations.
     */
    internal var pollIntervalMillis: Long = DEFAULT_POLL_INTERVAL_MILLIS

    /** Inputs with an in-flight optimistic toggle (rendered non-interactive). */
    private val pendingIds = MutableStateFlow<Set<String>>(emptySet())

    /** Optimistic is_live overlays applied while a toggle is in flight (inputId -> desired is_live). */
    private val optimisticLive = MutableStateFlow<Map<String, Boolean>>(emptyMap())

    /** Set when a refresh fails while cached rows are shown (warm-cache stale). */
    private val stale = MutableStateFlow(false)

    /** One-shot human-readable banner (e.g. a rolled-back toggle failure). */
    private val banner = MutableStateFlow<String?>(null)

    /** Cold-cache error (nothing cached AND a load failed). Null while content/empty is renderable. */
    private val coldError = MutableStateFlow<ColdError?>(null)

    /** Latest known layout (kept for deriving program + the current mode used by "Make live"). */
    private var lastLayout: BroadcastLayout? = null

    private var pollJob: Job? = null

    private val transient = combine(pendingIds, optimisticLive, stale, banner, coldError) { p, o, s, b, c ->
        TransientState(p, o, s, b, c)
    }

    val uiState: StateFlow<InputsUiState> =
        combine(
            repository.observeInputs(sessionId),
            repository.observeLayout(sessionId),
            transient,
        ) { inputs, layout, t ->
            lastLayout = layout
            reduce(inputs, layout, t)
        }.stateIn(
            scope = viewModelScope,
            started = SharingStarted.Eagerly,
            initialValue = InputsUiState.Loading,
        )

    init {
        // NOTE: polling is NOT auto-started — an unbounded delay loop in init would spin runTest's
        // end-of-test advanceUntilIdle forever. The screen drives [startPolling]/[stopPolling] from a
        // DisposableEffect (mirrors AND-309's host-control health loop). Tests start it explicitly,
        // drive ONE iteration with runCurrent, then call [stopPolling] before the test ends.
        if (sessionId.isBlank()) {
            coldError.value = ColdError(NO_SESSION, retryable = false)
        }
    }

    /**
     * Begins the poll loop (refresh + refreshLayout, then delay) while the screen is resumed. Bounded to
     * [viewModelScope]; tests set [pollIntervalMillis], drive a SINGLE iteration with runCurrent, then call
     * [stopPolling]. Safe to call repeatedly. No-op for a blank session.
     */
    fun startPolling() {
        if (sessionId.isBlank()) return
        if (pollJob != null) return
        pollJob = viewModelScope.launch {
            while (isActive) {
                val refreshed = repository.refresh(sessionId)
                applyRefreshOutcome(refreshed)
                repository.refreshLayout(sessionId)
                delay(pollIntervalMillis)
            }
        }
    }

    /** Updates the cold-error / stale flags from a list-refresh outcome. */
    private fun applyRefreshOutcome(result: ApiResult<List<BroadcastInput>>) {
        when (result) {
            is ApiResult.Success -> {
                stale.value = false
                coldError.value = null
            }
            is ApiResult.Failure -> onRefreshFailed(result.error.message, retryable = false)
            is ApiResult.NetworkError -> onRefreshFailed(OFFLINE, retryable = true)
        }
    }

    /**
     * A refresh failed: if we already have cached rows, mark stale (warm cache); otherwise surface a cold
     * error. The reducer decides which one wins based on whether the cache is empty.
     */
    private fun onRefreshFailed(message: String, retryable: Boolean) {
        stale.value = true
        coldError.value = ColdError(message, retryable)
    }

    /**
     * Optimistically toggle [inputId] active/inactive to [target]. Adds to pendingIds + applies an
     * optimistic is_live overlay, calls the repo, then clears pending on success (authoritative state
     * arrives via the refetch) or rolls back + banners on failure.
     */
    fun onToggleActive(inputId: String, target: Boolean) {
        if (sessionId.isBlank()) return
        if (pendingIds.value.contains(inputId)) return
        pendingIds.update { it + inputId }
        optimisticLive.update { it + (inputId to target) }
        viewModelScope.launch {
            when (val result = repository.setActive(sessionId, inputId, target)) {
                is ApiResult.Success -> {
                    // Authoritative is_live arrived via the refetch -> drop the optimistic overlay.
                    optimisticLive.update { it - inputId }
                    pendingIds.update { it - inputId }
                    stale.value = false
                }
                is ApiResult.Failure -> rollbackToggle(inputId, result.error.message)
                is ApiResult.NetworkError -> rollbackToggle(inputId, OFFLINE)
            }
        }
    }

    private fun rollbackToggle(inputId: String, message: String) {
        optimisticLive.update { it - inputId }
        pendingIds.update { it - inputId }
        banner.value = message
    }

    /**
     * Promote [inputId] to the live program by switching the layout (mode = the current layout mode, or
     * "single" if none) with primary_input_id = [inputId]. On failure shows a banner.
     */
    fun onMakeLive(inputId: String) {
        if (sessionId.isBlank()) return
        val mode = lastLayout?.mode?.takeIf { it.isNotBlank() } ?: LayoutMode.SINGLE
        viewModelScope.launch {
            when (val result = repository.setProgram(sessionId, inputId, mode)) {
                is ApiResult.Success -> banner.value = null
                is ApiResult.Failure -> banner.value = result.error.message
                is ApiResult.NetworkError -> banner.value = OFFLINE
            }
        }
    }

    /** Retry a cold-cache failure (or a stale warm cache): re-run a single refresh + layout refresh. */
    fun onRetry() {
        if (sessionId.isBlank()) return
        viewModelScope.launch {
            applyRefreshOutcome(repository.refresh(sessionId))
            repository.refreshLayout(sessionId)
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

    /**
     * Pure reducer: joins inputs with the layout to derive isProgram, applies optimistic overlays, and
     * picks Loading / Content / Empty / Error. Warm cache (non-empty inputs) wins over a cold error even
     * when a refresh just failed — the failure shows as the stale flag instead.
     */
    private fun reduce(
        inputs: List<BroadcastInput>,
        layout: BroadcastLayout?,
        t: TransientState,
    ): InputsUiState {
        val programId = layout?.primaryInputId
        val rows = inputs.map { raw ->
            val isProgram = programId != null && raw.inputId == programId
            val isLive = t.optimisticLive[raw.inputId] ?: raw.isLive
            val input = raw.copy(isLive = isLive, isProgram = isProgram)
            InputRow(
                input = input,
                canMakeLive = input.isLive && !isProgram,
                canDeactivate = !isProgram,
            )
        }

        return when {
            rows.isNotEmpty() -> InputsUiState.Content(
                inputs = rows,
                isStale = t.stale,
                banner = t.banner,
                pendingIds = t.pendingIds,
            )
            t.coldError != null -> InputsUiState.Error(t.coldError.message, t.coldError.retryable)
            else -> InputsUiState.Empty(isStale = t.stale)
        }
    }

    private data class TransientState(
        val pendingIds: Set<String>,
        val optimisticLive: Map<String, Boolean>,
        val stale: Boolean,
        val banner: String?,
        val coldError: ColdError?,
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
