package com.testlogon.android.feature.broadcast.host

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.broadcast.BroadcastSession
import com.testlogon.android.data.broadcast.BroadcastSessionStatus
import com.testlogon.android.data.broadcast.HostControlRepository
import com.testlogon.android.data.webrtc.BroadcastPublisher
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
 * AND-309 — host LIVE control presentation logic: start / stop / resume / reschedule + a health poll loop.
 *
 * Lifecycle calls go through the SEPARATE [HostControlRepository] (the shared BroadcastRepository fakes stay
 * untouched). NO optimistic state flips: an action sets [HostControlUiState.inFlight], calls the repo, and
 * on Success updates [HostControlUiState.session] FROM THE SERVER RESPONSE; on Failure it clears in-flight,
 * sets [HostControlUiState.transientError], and re-fetches the session (re-sync). A double-dispatch guard
 * ignores any new action while one is in flight.
 *
 * STOP is a two-step confirm: [onStop] only sets [HostControlUiState.showStopConfirm] (no network);
 * [onConfirmStopDialog] (true) dispatches STOP and, on success, tears down the FLAGGED publisher via
 * [BroadcastPublisher.stop] (idempotent — the bound StubBroadcastPublisher is a no-op). Because host media
 * is FLAGGED there are no real RTCStats, so the health report's rttMs / ingestConnected stay null.
 *
 * The health loop runs in [viewModelScope], polls every [pollIntervalMillis] (constructor-injectable so
 * unit tests can drive a SINGLE iteration with runCurrent and never spin under advanceUntilIdle), and is
 * gated on the session being LIVE. It keeps the last report and sets [HostControlUiState.healthStale] on a
 * failed iteration. The loop job is cancelled in [onCleared].
 */
@HiltViewModel
class HostControlViewModel @Inject constructor(
    private val repository: HostControlRepository,
    private val broadcastPublisher: BroadcastPublisher,
    savedState: SavedStateHandle,
    // #7c — the real native-WebRTC renderer (RealVideoRenderer) so "Manage broadcast" can show a live
    // self-view PIP of the host's own camera (the local track published by the ingest publisher).
    val videoRenderer: com.testlogon.android.core.webrtc.ui.VideoRenderer,
) : ViewModel() {

    val sessionId: String = savedState.get<String>(ARG_SESSION_ID).orEmpty()

    /**
     * Health poll interval (ms). NOT a constructor param — Hilt cannot provide a bare [Long] and ignores
     * Kotlin defaults. Tests set this directly after construction to drive fast single iterations.
     */
    internal var pollIntervalMillis: Long = DEFAULT_POLL_INTERVAL_MILLIS

    private val _uiState = MutableStateFlow(HostControlUiState())
    val uiState: StateFlow<HostControlUiState> = _uiState.asStateFlow()

    private var healthJob: Job? = null

    /** Whether the screen currently wants health polling (set while the surface is resumed). */
    private var pollingRequested: Boolean = false

    init {
        refreshSession()
    }

    /** Loads (or re-syncs) the session from the server; clears [HostControlUiState.loading]. */
    private fun refreshSession() {
        if (sessionId.isBlank()) {
            _uiState.update { it.copy(loading = false, transientError = NO_SESSION) }
            return
        }
        viewModelScope.launch {
            when (val result = repository.session(sessionId)) {
                is ApiResult.Success ->
                    _uiState.update { it.copy(session = result.data, loading = false) }
                is ApiResult.Failure ->
                    _uiState.update { it.copy(loading = false, transientError = result.error.message) }
                is ApiResult.NetworkError ->
                    _uiState.update { it.copy(loading = false, transientError = OFFLINE) }
            }
            // The session may now be LIVE -> (re)arm the health loop if the screen wants it.
            maybeRearmHealth()
        }
    }

    /** The host tapped Start. No optimistic flip: in-flight -> repo -> session from server response. */
    fun onStart() = dispatch(HostAction.START) { repository.start(sessionId) }

    /**
     * The host tapped Stop. This does NOT hit the network — it raises the confirm dialog. The actual STOP
     * is dispatched by [onConfirmStopDialog].
     */
    fun onStop() {
        if (_uiState.value.inFlight != null) return
        _uiState.update { it.copy(showStopConfirm = true) }
    }

    /**
     * Resolves the stop confirm dialog. (true) dispatches STOP and, on success, tears down the FLAGGED
     * publisher; (false) just dismisses the dialog with no request.
     */
    fun onConfirmStopDialog(confirmed: Boolean) {
        _uiState.update { it.copy(showStopConfirm = false) }
        if (!confirmed) return
        dispatch(HostAction.STOP, onSuccess = { broadcastPublisher.stop() }) {
            repository.stop(sessionId)
        }
    }

    /** The host tapped Resume. */
    fun onResume() = dispatch(HostAction.RESUME) { repository.resume(sessionId) }

    /** The host picked a new start time (Unix epoch SECONDS) for a not-yet-live session. */
    fun onReschedule(newStartAtEpochSeconds: Long) =
        dispatch(HostAction.RESCHEDULE) {
            repository.reschedule(sessionId, newStartAtEpochSeconds)
        }

    /** Clears a one-shot transient error after the UI has shown it. */
    fun consumeError() = _uiState.update { it.copy(transientError = null) }

    /**
     * Re-arms the health loop after a stale failure (e.g. the host tapped "retry" on the stale banner).
     * No-op unless polling is currently requested by the screen.
     */
    fun retryHealth() {
        maybeRearmHealth()
    }

    /**
     * Begin health polling while the control surface is resumed (called by the screen from a lifecycle
     * effect). The loop only actually runs while the session is LIVE; calling this when not LIVE simply
     * records intent so a later go-live arms it. Safe to call repeatedly.
     */
    fun startHealthPolling() {
        pollingRequested = true
        maybeRearmHealth()
    }

    /** Stop health polling (called by the screen when the surface is paused / disposed). */
    fun stopHealthPolling() {
        pollingRequested = false
        healthJob?.cancel()
        healthJob = null
    }

    /**
     * Single dispatch path for the four lifecycle actions. Guards against double-dispatch (ignores while an
     * action is in flight), sets in-flight, calls [block], and on Success updates the session FROM THE
     * SERVER (no optimistic flip) running the optional [onSuccess] teardown; on Failure / NetworkError it
     * clears in-flight, surfaces a transient error, and re-syncs the session.
     */
    private fun dispatch(
        action: HostAction,
        onSuccess: () -> Unit = {},
        block: suspend () -> ApiResult<BroadcastSession>,
    ) {
        if (_uiState.value.inFlight != null) return
        if (sessionId.isBlank()) {
            _uiState.update { it.copy(transientError = NO_SESSION) }
            return
        }
        _uiState.update { it.copy(inFlight = action, transientError = null) }
        viewModelScope.launch {
            when (val result = block()) {
                is ApiResult.Success -> {
                    onSuccess()
                    _uiState.update { it.copy(session = result.data, inFlight = null) }
                    // A successful action may have flipped to/from LIVE -> (re)arm or stop the loop.
                    maybeRearmHealth()
                }
                is ApiResult.Failure -> {
                    _uiState.update { it.copy(inFlight = null, transientError = result.error.message) }
                    resync()
                }
                is ApiResult.NetworkError -> {
                    _uiState.update { it.copy(inFlight = null, transientError = OFFLINE) }
                    resync()
                }
            }
        }
    }

    /** Best-effort re-fetch of the session after a failed action so the UI returns to server truth. */
    private suspend fun resync() {
        val result = repository.session(sessionId)
        if (result is ApiResult.Success) {
            _uiState.update { it.copy(session = result.data) }
        }
    }

    /**
     * (Re)arms the health poll loop IFF the screen requested polling AND the session is LIVE; otherwise it
     * cancels any running loop. Each iteration calls [HostControlRepository.health], updating health +
     * clearing stale on success, or keeping the last report + setting stale on failure, then delays
     * [pollIntervalMillis]. The loop self-terminates the moment the session is no longer LIVE. Tests inject a
     * small interval and drive iterations with runCurrent / advanceTimeBy (NEVER advanceUntilIdle), and call
     * [stopHealthPolling] before the test ends so the parked loop never spins the test scheduler.
     */
    private fun maybeRearmHealth() {
        healthJob?.cancel()
        if (!pollingRequested || sessionId.isBlank()) return
        if (_uiState.value.session?.status != BroadcastSessionStatus.LIVE) return
        healthJob = viewModelScope.launch {
            while (isActive && _uiState.value.session?.status == BroadcastSessionStatus.LIVE) {
                when (val result = repository.health(sessionId)) {
                    is ApiResult.Success ->
                        _uiState.update { it.copy(health = result.data, healthStale = false) }
                    is ApiResult.Failure ->
                        _uiState.update { it.copy(healthStale = true) }
                    is ApiResult.NetworkError ->
                        _uiState.update { it.copy(healthStale = true) }
                }
                delay(pollIntervalMillis)
            }
        }
    }

    override fun onCleared() {
        healthJob?.cancel()
        broadcastPublisher.stop()
    }

    companion object {
        /** Nav arg carrying the broadcast session id. */
        const val ARG_SESSION_ID = "sessionId"

        /** Default health poll interval (ms). Override via [pollIntervalMillis] in tests. */
        const val DEFAULT_POLL_INTERVAL_MILLIS = 5_000L

        // Non-resource fallbacks (the screen prefers stringResource where it has a Context).
        private const val NO_SESSION = "No broadcast session is available."
        private const val OFFLINE = "Couldn't reach the server. Try again."
    }
}
