package com.testlogon.android.feature.broadcast.privateshow

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.broadcast.BroadcastMonetizationRepository
import com.testlogon.android.data.broadcast.PrivateShowRequest
import com.testlogon.android.data.broadcast.PrivateShowSession
import com.testlogon.android.data.broadcast.PrivateStatus
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.time.Instant
import javax.inject.Inject

/**
 * AND-315 — presentation logic for the host PRIVATE-SHOW lifecycle (request -> accept -> active -> end).
 *
 * Real-time is POLLING (no private-show SSE): a request poll loop hits listPrivateRequests + getPrivateStatus
 * every [pollIntervalMillis] and folds the result into [PrivateShowState]. A SEPARATE cost ticker runs ONLY
 * while Active, recomputing the client-estimate elapsed + accrued cost each [tickIntervalMillis].
 *
 * TWO LOOPS, BOTH ANTI-HANG (CRITICAL):
 *  - NEITHER is auto-started in init (an unbounded delay loop / uncancelled ticker would hang runTest's
 *    end-of-test drain).
 *  - The screen drives [startPolling]/[stopPolling] from a DisposableEffect. [stopPolling] cancels BOTH the
 *    poll loop AND the cost ticker.
 *  - The ticker is started ONLY on entering Active and cancelled on leaving Active, in [stopPolling], and in
 *    [onCleared]. Tests drive bounded advanceTimeBy(n) then reach Ended / call stopPolling BEFORE finishing —
 *    NEVER advanceUntilIdle.
 *
 * DEFENSIVE conflict handling: accept / end can race a stale poll. On a 404/409 (stale / terminal) the
 * action re-reads getPrivateStatus to converge (the REST calls are idempotent). Viewer identity is never
 * logged.
 */
@HiltViewModel
class PrivateShowViewModel @Inject constructor(
    savedState: SavedStateHandle,
    private val repository: BroadcastMonetizationRepository,
) : ViewModel() {

    val sessionId: String = savedState.get<String>(ARG_SESSION_ID).orEmpty()

    /** Request-poll interval (ms). NOT a ctor param — Hilt cannot inject a bare Long. Tests set it directly. */
    internal var pollIntervalMillis: Long = DEFAULT_POLL_INTERVAL_MILLIS

    /** Cost-ticker interval (ms). NOT a ctor param. Tests drive advanceTimeBy against it (bounded). */
    internal var tickIntervalMillis: Long = DEFAULT_TICK_INTERVAL_MILLIS

    private val _uiState = MutableStateFlow(PrivateShowUiState())
    val uiState: StateFlow<PrivateShowUiState> = _uiState.asStateFlow()

    private var pollJob: Job? = null
    private var tickerJob: Job? = null

    // NOTE: NOTHING auto-starts in init. No poll loop, no ticker, no rehydrate launch — the screen drives
    // refreshStatus() + startPolling()/stopPolling(). This keeps runTest's drain from spinning a parked loop.

    /**
     * Rehydrates the lifecycle state from the server status (Idle / Pending / Active). Called on screen start
     * and as the convergence step after an accept/end conflict. Active (re)arms the cost ticker; leaving
     * Active cancels it.
     */
    fun refreshStatus() {
        if (sessionId.isBlank()) return
        viewModelScope.launch {
            when (val result = repository.getPrivateStatus(sessionId)) {
                is ApiResult.Success -> applyStatus(result.data)
                is ApiResult.Failure -> { /* keep current state; a poll tick will retry */ }
                is ApiResult.NetworkError -> { /* keep current state; a poll tick will retry */ }
            }
        }
    }

    /**
     * Begins the request poll loop (listPrivateRequests + getPrivateStatus, then delay) while the screen is
     * resumed. Bounded to [viewModelScope]; tests set [pollIntervalMillis], drive ONE iteration with
     * runCurrent, then call [stopPolling]. Safe to call repeatedly. No-op for a blank session.
     */
    fun startPolling() {
        if (sessionId.isBlank()) return
        if (pollJob != null) return
        pollJob = viewModelScope.launch {
            while (isActive) {
                pollOnce()
                delay(pollIntervalMillis)
            }
        }
    }

    /** One poll iteration: prefer the explicit status; fall back to a pending request from the list. */
    private suspend fun pollOnce() {
        when (val status = repository.getPrivateStatus(sessionId)) {
            is ApiResult.Success -> {
                // If the server reports idle but a pending request exists, surface the request.
                if (isIdleStatus(status.data.status)) {
                    foldRequests()
                } else {
                    applyStatus(status.data)
                }
            }
            is ApiResult.Failure -> foldRequests()
            is ApiResult.NetworkError -> { /* transient; keep state */ }
        }
    }

    /** Folds the pending-requests list into the state (Idle -> Pending on a new request). */
    private suspend fun foldRequests() {
        when (val result = repository.listPrivateRequests(sessionId)) {
            is ApiResult.Success -> {
                val pending = result.data.firstOrNull { isPendingStatus(it.status) }
                if (pending != null) {
                    moveToPending(pending)
                } else if (currentState() is PrivateShowState.Pending) {
                    // The previously-pending request is gone (declined / accepted elsewhere) -> Idle.
                    setState(PrivateShowState.Idle)
                }
            }
            is ApiResult.Failure -> { /* keep state */ }
            is ApiResult.NetworkError -> { /* keep state */ }
        }
    }

    /** Accept [requestId] with [behavior] (default pause). On 404/409 converge via [refreshStatus]. */
    fun accept(requestId: String, behavior: PrivateShowBehavior = PrivateShowBehavior.PAUSE) {
        if (sessionId.isBlank() || _uiState.value.inFlightAction) return
        setInFlight(true)
        viewModelScope.launch {
            when (val result = repository.acceptPrivateRequest(sessionId, requestId, behavior.wire)) {
                is ApiResult.Success -> {
                    setInFlight(false)
                    moveToActive(result.data)
                }
                is ApiResult.Failure -> {
                    setInFlight(false)
                    if (isConflict(result.error.status)) {
                        refreshStatus()
                    } else {
                        setActionError(result.error.message)
                    }
                }
                is ApiResult.NetworkError -> {
                    setInFlight(false)
                    setActionError(OFFLINE)
                }
            }
        }
    }

    /** Decline [requestId]. On success drop back to Idle (a later poll may surface a new request). */
    fun decline(requestId: String) {
        if (sessionId.isBlank() || _uiState.value.inFlightAction) return
        setInFlight(true)
        viewModelScope.launch {
            when (val result = repository.declinePrivateRequest(sessionId, requestId)) {
                is ApiResult.Success -> {
                    setInFlight(false)
                    if (currentState() is PrivateShowState.Pending) setState(PrivateShowState.Idle)
                }
                is ApiResult.Failure -> {
                    setInFlight(false)
                    if (isConflict(result.error.status)) refreshStatus() else setActionError(result.error.message)
                }
                is ApiResult.NetworkError -> {
                    setInFlight(false)
                    setActionError(OFFLINE)
                }
            }
        }
    }

    /** Ends the ACTIVE private show (keyed by private_session_id). On 404/409 converge via [refreshStatus]. */
    fun endShow() {
        if (sessionId.isBlank() || _uiState.value.inFlightAction) return
        val active = currentState() as? PrivateShowState.Active ?: return
        val privateSessionId = active.session.privateSessionId
        setInFlight(true)
        // Leaving Active -> stop the cost ticker immediately.
        cancelTicker()
        setState(PrivateShowState.Ending(privateSessionId))
        viewModelScope.launch {
            when (val result = repository.endPrivateSession(sessionId, privateSessionId)) {
                is ApiResult.Success -> {
                    setInFlight(false)
                    setState(PrivateShowState.Ended(result.data))
                }
                is ApiResult.Failure -> {
                    setInFlight(false)
                    if (isConflict(result.error.status)) {
                        refreshStatus()
                    } else {
                        setActionError(result.error.message)
                        // Restore the active view so the host can retry End.
                        setState(active)
                        startTicker()
                    }
                }
                is ApiResult.NetworkError -> {
                    setInFlight(false)
                    setActionError(OFFLINE)
                    setState(active)
                    startTicker()
                }
            }
        }
    }

    /** Clears the one-shot action error after the UI has shown it. */
    fun consumeActionError() {
        _uiState.update { it.copy(actionError = null) }
    }

    /** Stops BOTH loops (called by the screen when paused/disposed; tests call it before finishing). */
    fun stopPolling() {
        pollJob?.cancel()
        pollJob = null
        cancelTicker()
    }

    override fun onCleared() {
        pollJob?.cancel()
        cancelTicker()
    }

    // ---- state transitions ----

    private fun applyStatus(status: PrivateStatus) {
        when {
            isActiveStatus(status.status) && status.privateSessionId != null -> {
                moveToActive(
                    PrivateShowSession(
                        privateSessionId = status.privateSessionId,
                        sessionId = status.sessionId ?: sessionId,
                        status = status.status,
                        behavior = status.behavior,
                        callId = status.callId,
                        ratePerMinuteCents = status.ratePerMinuteCents ?: 0,
                        startedAt = status.startedAt,
                    ),
                )
            }
            isPendingStatus(status.status) && status.requestId != null -> {
                moveToPending(
                    PrivateShowRequest(
                        requestId = status.requestId,
                        privateSessionId = status.privateSessionId,
                        sessionId = status.sessionId ?: sessionId,
                        viewerId = status.viewerId ?: "",
                        viewerDisplayName = status.viewerDisplayName,
                        ratePerMinuteCents = status.ratePerMinuteCents ?: 0,
                        status = status.status,
                        maxDurationMinutes = null,
                        requestedAt = null,
                        startedAt = status.startedAt,
                    ),
                )
            }
            isIdleStatus(status.status) -> {
                // Don't clobber a terminal Ended summary the host hasn't dismissed yet.
                if (currentState() !is PrivateShowState.Ended) setState(PrivateShowState.Idle)
            }
            else -> { /* unknown status -> leave state unchanged (safe default, never throw) */ }
        }
    }

    private fun moveToPending(request: PrivateShowRequest) {
        cancelTicker()
        setState(PrivateShowState.Pending(request))
    }

    private fun moveToActive(session: PrivateShowSession) {
        val seeded = PrivateShowState.Active(
            session = session,
            elapsedSeconds = computeElapsed(session.startedAt),
            accruedCents = 0,
        )
        setState(recomputeAccrued(seeded))
        startTicker()
    }

    /** Starts the cost ticker. Idempotent. Runs ONLY while Active; recomputes elapsed + accrued each tick. */
    private fun startTicker() {
        if (tickerJob != null) return
        tickerJob = viewModelScope.launch {
            while (isActive) {
                val active = currentState() as? PrivateShowState.Active ?: break
                setState(recomputeAccrued(active))
                delay(tickIntervalMillis)
            }
        }
    }

    private fun cancelTicker() {
        tickerJob?.cancel()
        tickerJob = null
    }

    /** Recomputes elapsed (from server started_at) + accrued cents (elapsed * rate / 60) — CLIENT estimate. */
    private fun recomputeAccrued(active: PrivateShowState.Active): PrivateShowState.Active {
        val elapsed = computeElapsed(active.session.startedAt)
        val rate = active.session.ratePerMinuteCents
        val accrued = elapsed * rate / 60
        return active.copy(elapsedSeconds = elapsed, accruedCents = accrued)
    }

    private fun computeElapsed(startedAt: Instant?): Long {
        if (startedAt == null) return 0
        val seconds = (now().epochSecond - startedAt.epochSecond)
        return if (seconds < 0) 0 else seconds
    }

    /** Overridable clock seam so tests can pin "now". Default is the system clock. */
    internal var now: () -> Instant = { Instant.now() }

    private fun currentState(): PrivateShowState = _uiState.value.state

    private fun setState(state: PrivateShowState) {
        _uiState.update { it.copy(state = state) }
    }

    private fun setInFlight(inFlight: Boolean) {
        _uiState.update { it.copy(inFlightAction = inFlight) }
    }

    private fun setActionError(message: String) {
        _uiState.update { it.copy(actionError = message) }
    }

    companion object {
        /** Nav arg carrying the broadcast session id. */
        const val ARG_SESSION_ID = "sessionId"

        /** Default request-poll interval (ms) — 5s per the web reference. Override via [pollIntervalMillis]. */
        const val DEFAULT_POLL_INTERVAL_MILLIS = 5_000L

        /** Default cost-ticker interval (ms). Override via [tickIntervalMillis]. */
        const val DEFAULT_TICK_INTERVAL_MILLIS = 1_000L

        private const val OFFLINE = "Couldn't reach the server. Try again."

        private fun isConflict(status: Int): Boolean = status == 404 || status == 409

        private fun isPendingStatus(status: String): Boolean = status.lowercase() == "pending"

        private fun isActiveStatus(status: String): Boolean =
            status.lowercase() in setOf("active", "started", "accepted", "in_progress")

        private fun isIdleStatus(status: String): Boolean =
            status.isBlank() || status.lowercase() in setOf("idle", "none", "ended", "completed", "declined")
    }
}
