package com.testlogon.android.feature.broadcast.host

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.broadcast.BroadcastSession
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.time.Instant
import javax.inject.Inject

/**
 * AND-317 — the @HiltViewModel that DRIVES the pure [HostSessionStateMachine] against the REAL (FLAGGED)
 * seams, mirroring the AND-305 [com.testlogon.android.feature.call.fsm.CallStateMachine] host idiom.
 *
 * CONTRACT
 * - [uiState]: a hot [StateFlow] of the latest [HostSessionState] (the screen renders this).
 * - [onEvent]: posts a [HostSessionEvent] to an UNBOUNDED [Channel] consumed by exactly ONE coroutine that
 *   reduces -> updates state -> runs effects, IN ORDER. The reducer is pure + lock-free; serialization comes
 *   from the single-consumer channel (no concurrent reduce can race).
 *
 * EFFECTS run on the injected [dispatcher] (FR-8) so tests use a StandardTestDispatcher:
 * - LoadSession / CallControl -> repo call -> fold result back as SessionLoaded / ControlResult.
 * - OpenIngest -> ingest.open (ingest.status is collected in init -> IngestStatusChanged); CloseIngest -> close.
 * - StartHealthTicker -> launch a CANCELLABLE ticker Job (NOT auto-started in init); each tick dispatches
 *   HealthTick. StopHealthTicker / onCleared cancel it. Cadence is a settable property, not a ctor param.
 * - Persist -> prefs.write; LogIllegalTransition -> analytics.
 *
 * IN-FLIGHT GUARD (FR-9): a duplicate GoLive / Stop while the corresponding effect is in flight is dropped
 * (gated on the phase + a boolean), so ingest is never opened twice / stop never double-fires.
 */
@HiltViewModel
class BroadcastHostViewModel @Inject constructor(
    private val repo: BroadcastHostRepository,
    private val ingest: WebRtcIngestController,
    private val prefs: HostSessionPrefs,
    @DefaultDispatcher private val dispatcher: CoroutineDispatcher,
    private val analytics: HostAnalytics,
    private val savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val _uiState = MutableStateFlow<HostSessionState>(HostSessionState.Idle)
    val uiState: StateFlow<HostSessionState> = _uiState.asStateFlow()

    /** Health ticker cadence. Settable (NOT a ctor param — Hilt cannot inject a bare Long). */
    internal var healthCadenceMillis: Long = 2_000L

    // Unbounded so onEvent never suspends/drops; drained by the single consumer below (serialization).
    private val events = Channel<HostSessionEvent>(Channel.UNLIMITED)

    private var healthTicker: Job? = null

    // FR-9 in-flight guards: a go-live / stop control call is currently running.
    private var goLiveInFlight = false
    private var stopInFlight = false

    init {
        // 1) Single-consumer event loop (serialized reduce -> setState -> runEffects).
        viewModelScope.launch(dispatcher) {
            for (event in events) {
                process(event)
            }
        }
        // 2) Collect the (mapped) ingest status and feed it back as events.
        viewModelScope.launch(dispatcher) {
            ingest.status.collect { status ->
                onEvent(HostSessionEvent.IngestStatusChanged(status, now()))
            }
        }
        // 3) Cold-start restore: if a session was persisted, seed + request a re-load.
        viewModelScope.launch(dispatcher) {
            val persistedId = savedStateHandle.get<String>(KEY_SESSION_ID) ?: prefs.activeSessionId()
            if (persistedId != null) {
                onEvent(HostSessionEvent.Load(persistedId))
            }
        }
    }

    /** Posts an event for serialized processing. Never blocks. */
    fun onEvent(event: HostSessionEvent) {
        // trySend on an UNLIMITED channel always succeeds.
        events.trySend(event)
    }

    private suspend fun process(event: HostSessionEvent) {
        // FR-9: drop duplicate GoLive / Stop while the matching control call is in flight.
        if (shouldDropDuplicate(event)) return

        val before = _uiState.value
        val (next, effects) = HostSessionStateMachine.reduce(before, event)
        if (next != before) {
            // FR-9: the in-flight guard is PHASE-driven (not control-return-timing-driven) so duplicate
            // GoLive/Stop are dropped deterministically while we occupy Connecting/Ending.
            goLiveInFlight = next is HostSessionState.Connecting
            stopInFlight = next is HostSessionState.Ending
            _uiState.value = next
            analytics.phaseChanged(before::class.simpleName ?: "?", next::class.simpleName ?: "?")
            // Mirror the active session id into SavedStateHandle for config-change survival.
            savedStateHandle[KEY_SESSION_ID] = next.sessionId
        }
        for (effect in effects) {
            runEffect(effect, next)
        }
    }

    private fun shouldDropDuplicate(event: HostSessionEvent): Boolean = when (event) {
        is HostSessionEvent.GoLive ->
            goLiveInFlight && _uiState.value is HostSessionState.Connecting
        is HostSessionEvent.Stop ->
            stopInFlight && _uiState.value is HostSessionState.Ending
        else -> false
    }

    private fun runEffect(effect: HostEffect, state: HostSessionState) {
        when (effect) {
            is HostEffect.LoadSession -> launchEffect {
                val result = repo.loadSession(effect.sessionId)
                onEvent(HostSessionEvent.SessionLoaded(result, now()))
            }
            is HostEffect.CallControl -> launchEffect {
                runControl(effect.action, state)
            }
            HostEffect.OpenIngest -> launchEffect { ingest.open(state.sessionId.orEmpty()) }
            HostEffect.CloseIngest -> ingest.close()
            HostEffect.StartHealthTicker -> startHealthTicker()
            HostEffect.StopHealthTicker -> stopHealthTicker()
            is HostEffect.Persist -> launchEffect { prefs.write(effect.sessionId, effect.status) }
            is HostEffect.LogIllegalTransition ->
                analytics.illegalTransition(effect.from, effect.event)
        }
    }

    private suspend fun runControl(action: ControlAction, state: HostSessionState) {
        val sessionId = state.sessionId
        val result: ApiResult<BroadcastSession> = when {
            // Schedule/CancelSchedule can run with no prior session id (create-then-schedule); the adapter
            // requires an id, so guard: a null id means we can only forward what we have.
            sessionId == null && action == ControlAction.Schedule ->
                // No draft session yet -> create a draft first, then schedule it.
                createThenSchedule(state)
            sessionId == null ->
                ApiResult.NetworkError(IllegalStateException("no session id for $action"))
            else -> repo.control(
                action = action,
                sessionId = sessionId,
                draft = (state as? HostSessionState.Scheduling)?.draft,
                startsAt = (state as? HostSessionState.Scheduling)?.draft?.scheduledAt,
            )
        }
        onEvent(HostSessionEvent.ControlResult(action, result, now()))
    }

    private suspend fun createThenSchedule(state: HostSessionState): ApiResult<BroadcastSession> {
        val draft = (state as? HostSessionState.Scheduling)?.draft
        val profileId = savedStateHandle.get<String>(KEY_PROFILE_ID).orEmpty()
        return when (val created = repo.create(profileId)) {
            is ApiResult.Success -> repo.control(
                action = ControlAction.Schedule,
                sessionId = created.data.id,
                draft = draft,
                startsAt = draft?.scheduledAt,
            )
            is ApiResult.Failure -> created
            is ApiResult.NetworkError -> created
        }
    }

    private fun startHealthTicker() {
        if (healthTicker?.isActive == true) return
        healthTicker = viewModelScope.launch(dispatcher) {
            while (isActive) {
                delay(healthCadenceMillis)
                onEvent(HostSessionEvent.HealthTick(now()))
            }
        }
    }

    private fun stopHealthTicker() {
        healthTicker?.cancel()
        healthTicker = null
    }

    private fun launchEffect(block: suspend () -> Unit) {
        viewModelScope.launch(dispatcher) { block() }
    }

    override fun onCleared() {
        stopHealthTicker()
        events.close()
        super.onCleared()
    }

    /** Wall clock is read HERE (the host), never in the pure reducer. Overridable for tests. */
    internal var clock: () -> Instant = { Instant.now() }

    private fun now(): Instant = clock()

    private companion object {
        const val KEY_SESSION_ID = "host_active_session_id"
        const val KEY_PROFILE_ID = "host_profile_id"
    }
}
