package com.testlogon.android.feature.broadcast.host.ads

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.broadcast.AdBreak
import com.testlogon.android.data.broadcast.AdConfig
import com.testlogon.android.data.broadcast.HostAdRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-316 — presentation logic for the host AD-BREAK / AD-CONFIG surface.
 *
 * SCOPE: HOST control plane only — edit the small ad-config (pre-roll toggle + mid-roll duration + skip-after)
 * and trigger / end a mid-roll ad break. Viewer ad RENDERING is OUT OF SCOPE (no ad SDK).
 *
 * [refresh] is a SINGLE non-looping load (NOT a delay loop) run on init — there is NO config poll on this
 * surface, so nothing here can spin runTest's end-of-test drain. Validation mirrors the server bounds
 * (duration 15..60, skip-after 5..30); [saveConfig] PATCHes ONLY the changed fields and reconciles from the
 * response. [triggerAdBreak] sets the active break from the AdBreakOut and starts the COUNTDOWN ticker;
 * [endAdBreak] clears it, stops the ticker, and re-reads ad-config.
 *
 * COUNTDOWN TICKER (ANTI-HANG): a cancellable [tickJob] started ONLY when the break becomes active (after a
 * trigger OR after a refresh that returns active) — NEVER in init. [tickIntervalMillis] is a settable
 * property (NOT a ctor param — Hilt cannot inject a bare Long). Each tick recomputes remainingSeconds =
 * startedAt + durationSeconds - now() via the injectable [now] clock seam (deterministic in tests). When it
 * reaches 0 the break is cleared locally and [refresh] reconciles total_ad_breaks (FR-5 auto-expire). The
 * ticker is cancelled on end / expire / onCleared. Tests set a small interval, drive bounded advanceTimeBy,
 * and ALWAYS reach inactive (cancelling the ticker) before finishing — NEVER advanceUntilIdle.
 */
@HiltViewModel
class AdControlViewModel @Inject constructor(
    private val repository: HostAdRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val sessionId: String = savedState.get<String>(ARG_SESSION_ID).orEmpty()

    /**
     * Countdown tick interval (ms). NOT a constructor param — Hilt cannot provide a bare [Long] and ignores
     * Kotlin defaults. Tests set this directly after construction to drive fast bounded ticks.
     */
    internal var tickIntervalMillis: Long = DEFAULT_TICK_INTERVAL_MILLIS

    /**
     * Injectable wall-clock seam (epoch SECONDS) for the countdown maths. Tests override it for deterministic
     * remaining-seconds assertions; production uses [System.currentTimeMillis].
     */
    internal var now: () -> Long = { System.currentTimeMillis() / 1_000L }

    private val _uiState = MutableStateFlow(AdControlUiState())
    val uiState: StateFlow<AdControlUiState> = _uiState.asStateFlow()

    /** The persisted server config (used to compute the `dirty` flag). Null until first loaded. */
    private var persisted: AdConfig? = null

    private var tickJob: Job? = null

    init {
        if (sessionId.isBlank()) {
            _uiState.update { it.copy(loading = false, error = NO_SESSION) }
        } else {
            refresh()
        }
    }

    /**
     * A SINGLE non-looping read of the current ad-config + ad-break state. Re-runnable via [onRetry]. If the
     * loaded config reports an active break, the COUNTDOWN ticker is (re)armed.
     */
    fun refresh() {
        if (sessionId.isBlank()) return
        _uiState.update { it.copy(loading = true, error = null, offline = false) }
        viewModelScope.launch {
            when (val result = repository.getAdConfig(sessionId)) {
                is ApiResult.Success -> applyConfig(result.data)
                is ApiResult.Failure ->
                    _uiState.update { it.copy(loading = false, error = result.error.message) }
                is ApiResult.NetworkError ->
                    _uiState.update { it.copy(loading = false, offline = true) }
            }
        }
    }

    /** Retry a load failure. */
    fun onRetry() = refresh()

    fun onPreRollToggled(enabled: Boolean) = mutateForm { it.copy(preRollEnabled = enabled) }

    fun onDurationChanged(seconds: Int) = mutateForm {
        it.copy(midRollDurationSeconds = seconds, durationValid = AdConfigBounds.durationValid(seconds))
    }

    fun onSkipAfterChanged(seconds: Int) = mutateForm {
        it.copy(skipAfterSeconds = seconds, skipValid = AdConfigBounds.skipValid(seconds))
    }

    /** PATCHes ONLY the changed fields, then reconciles the form + persisted config from the response. */
    fun saveConfig() {
        val state = _uiState.value
        val form = state.config
        if (!form.canSave) return
        if (state.mutationInFlight) return
        val base = persisted ?: return
        _uiState.update { it.copy(mutationInFlight = true, error = null) }
        viewModelScope.launch {
            // Send ONLY the fields that actually changed (nulls are omitted from the wire body by Moshi).
            val preRoll = form.preRollEnabled.takeIf { it != base.preRollEnabled }
            val duration = form.midRollDurationSeconds.takeIf { it != base.midRollDurationSeconds }
            val skip = form.skipAfterSeconds.takeIf { it != base.skipAfterSeconds }
            when (
                val result = repository.updateAdConfig(
                    sessionId = sessionId,
                    preRollEnabled = preRoll,
                    durationSeconds = duration,
                    skipAfterSeconds = skip,
                )
            ) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(mutationInFlight = false) }
                    applyConfig(result.data)
                }
                is ApiResult.Failure ->
                    _uiState.update { it.copy(mutationInFlight = false, error = result.error.message) }
                is ApiResult.NetworkError ->
                    _uiState.update { it.copy(mutationInFlight = false, offline = true) }
            }
        }
    }

    /** Triggers a mid-roll ad break; on success sets the active state from the AdBreakOut + starts the ticker. */
    fun triggerAdBreak() {
        if (sessionId.isBlank()) return
        val state = _uiState.value
        if (state.adBreakActive || state.mutationInFlight) return
        _uiState.update { it.copy(mutationInFlight = true, error = null) }
        viewModelScope.launch {
            when (val result = repository.triggerAdBreak(sessionId)) {
                is ApiResult.Success -> applyAdBreakStarted(result.data)
                is ApiResult.Failure ->
                    _uiState.update { it.copy(mutationInFlight = false, error = result.error.message) }
                is ApiResult.NetworkError ->
                    _uiState.update { it.copy(mutationInFlight = false, offline = true) }
            }
        }
    }

    /** Ends the active ad break early; clears active + stops the ticker + reconciles via [refresh]. */
    fun endAdBreak() {
        if (sessionId.isBlank()) return
        val state = _uiState.value
        if (!state.adBreakActive || state.mutationInFlight) return
        _uiState.update { it.copy(mutationInFlight = true, error = null) }
        viewModelScope.launch {
            when (val result = repository.endAdBreak(sessionId)) {
                is ApiResult.Success -> {
                    clearAdBreak()
                    _uiState.update { it.copy(mutationInFlight = false) }
                    refresh()
                }
                is ApiResult.Failure ->
                    _uiState.update { it.copy(mutationInFlight = false, error = result.error.message) }
                is ApiResult.NetworkError ->
                    _uiState.update { it.copy(mutationInFlight = false, offline = true) }
            }
        }
    }

    /** Folds a loaded [AdConfig] into the form + ad-break state, (re)arming the ticker iff a break is active. */
    private fun applyConfig(config: AdConfig) {
        persisted = config
        _uiState.update {
            it.copy(
                loading = false,
                hasConfig = true,
                error = null,
                offline = false,
                config = AdConfigForm(
                    preRollEnabled = config.preRollEnabled,
                    midRollDurationSeconds = config.midRollDurationSeconds,
                    skipAfterSeconds = config.skipAfterSeconds,
                    durationValid = AdConfigBounds.durationValid(config.midRollDurationSeconds),
                    skipValid = AdConfigBounds.skipValid(config.skipAfterSeconds),
                    dirty = false,
                ),
                adBreakActive = config.adBreakActive,
                adBreakStartedAt = config.adBreakStartedAt,
                adBreakDurationSeconds = config.midRollDurationSeconds,
                skipAfterSeconds = config.skipAfterSeconds,
                totalAdBreaks = config.totalAdBreaks,
            )
        }
        if (config.adBreakActive && config.adBreakStartedAt != null) {
            startTicker()
        } else {
            stopTicker()
        }
    }

    /** Folds a just-started [AdBreak] (from trigger) into the active state + starts the countdown ticker. */
    private fun applyAdBreakStarted(adBreak: AdBreak) {
        _uiState.update {
            it.copy(
                mutationInFlight = false,
                adBreakActive = true,
                adBreakStartedAt = adBreak.startedAt,
                adBreakDurationSeconds = adBreak.durationSeconds,
                skipAfterSeconds = adBreak.skipAfterSeconds,
            )
        }
        startTicker()
    }

    /** Clears the active ad-break state locally (does NOT touch the persisted config form). */
    private fun clearAdBreak() {
        stopTicker()
        _uiState.update {
            it.copy(adBreakActive = false, adBreakStartedAt = null, remainingSeconds = 0)
        }
    }

    /**
     * (Re)arms the countdown ticker. Cancellable, started ONLY when a break is active (NEVER in init). Each
     * tick recomputes remainingSeconds from the injectable [now] clock; when it hits 0 the break is cleared
     * locally and [refresh] reconciles total_ad_breaks (FR-5 auto-expire), which also stops the ticker.
     */
    private fun startTicker() {
        tickJob?.cancel()
        // Emit an immediate remaining value so the UI shows the countdown without waiting a full interval.
        if (recomputeRemaining()) return
        tickJob = viewModelScope.launch {
            while (isActive) {
                delay(tickIntervalMillis)
                if (recomputeRemaining()) break
            }
        }
    }

    /**
     * Recomputes remainingSeconds from startedAt + duration - now(). Returns true when the break has expired
     * (remaining <= 0), in which case it clears the break locally and triggers a reconciling [refresh].
     */
    private fun recomputeRemaining(): Boolean {
        val state = _uiState.value
        val startedAt = state.adBreakStartedAt
        if (!state.adBreakActive || startedAt == null) return true
        val remaining = (startedAt + state.adBreakDurationSeconds - now()).toInt()
        if (remaining <= 0) {
            clearAdBreak()
            refresh()
            return true
        }
        _uiState.update { it.copy(remainingSeconds = remaining) }
        return false
    }

    private fun stopTicker() {
        tickJob?.cancel()
        tickJob = null
    }

    /** Applies [transform] to the form, recomputing [AdConfigForm.dirty] relative to the persisted config. */
    private fun mutateForm(transform: (AdConfigForm) -> AdConfigForm) {
        val base = persisted ?: return
        _uiState.update { state ->
            val next = transform(state.config)
            val dirty = next.preRollEnabled != base.preRollEnabled ||
                next.midRollDurationSeconds != base.midRollDurationSeconds ||
                next.skipAfterSeconds != base.skipAfterSeconds
            state.copy(config = next.copy(dirty = dirty), error = null)
        }
    }

    override fun onCleared() {
        tickJob?.cancel()
    }

    companion object {
        /** Nav arg carrying the broadcast session id. */
        const val ARG_SESSION_ID = "sessionId"

        /** Default countdown tick interval (ms). Override via [tickIntervalMillis] in tests. */
        const val DEFAULT_TICK_INTERVAL_MILLIS = 1_000L

        private const val NO_SESSION = "No broadcast session is available."
    }
}
