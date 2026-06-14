package com.testlogon.android.feature.broadcast.host

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.broadcast.BroadcastSession
import com.testlogon.android.data.broadcast.BroadcastSessionStatus
import java.time.Instant
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/**
 * AND-317 — the CANONICAL, PURE host-broadcast finite-state-machine reducer.
 *
 * Mirrors the AND-305 [com.testlogon.android.feature.call.fsm.CallFsm] idiom: [reduce] is PURE and TOTAL.
 * Every (state, event) pair maps to a defined transition OR an explicit no-op that records exactly one
 * [HostEffect.LogIllegalTransition] (state UNCHANGED). It NEVER throws, has NO Android/coroutine imports,
 * and reads NO wall clock — timestamps arrive via events. Returned effects are DESCRIPTIONS only; the host
 * ([BroadcastHostViewModel]) performs the IO.
 *
 * Pause is CLIENT-ONLY: Live + Pause -> Paused emits CloseIngest, NEVER a CallControl. There is no server
 * pause endpoint and no [ControlAction.Pause].
 *
 * AND-318 will exercise this reducer's full transition table; AND-317 ships the table tests for the legal
 * edges + a sample of illegal pairs + a totality (never-throws) property.
 */
object HostSessionStateMachine {

    /** A reduction outcome: the next state + the ordered effects to run. */
    data class Result(
        val state: HostSessionState,
        val effects: List<HostEffect>,
    )

    private fun HostSessionState.with(vararg effects: HostEffect): Result = Result(this, effects.toList())

    private fun HostSessionState.with(effects: List<HostEffect>): Result = Result(this, effects)

    /** No state change; record exactly one LogIllegalTransition (NEVER throw). */
    private fun illegal(state: HostSessionState, event: HostSessionEvent): Result = Result(
        state,
        listOf(
            HostEffect.LogIllegalTransition(
                from = state::class.simpleName ?: "Unknown",
                event = event::class.simpleName ?: "Unknown",
            ),
        ),
    )

    fun reduce(state: HostSessionState, event: HostSessionEvent): Result {
        // Cross-cutting events handled the same in (almost) every phase first; phase-specific handling falls
        // through to the per-state reducers below.
        return when (state) {
            is HostSessionState.Idle -> reduceIdle(state, event)
            is HostSessionState.Scheduling -> reduceScheduling(state, event)
            is HostSessionState.Scheduled -> reduceScheduled(state, event)
            is HostSessionState.PreFlight -> reducePreFlight(state, event)
            is HostSessionState.Connecting -> reduceConnecting(state, event)
            is HostSessionState.Live -> reduceLive(state, event)
            is HostSessionState.Paused -> reducePaused(state, event)
            is HostSessionState.Reconnecting -> reduceReconnecting(state, event)
            is HostSessionState.Ending -> reduceEnding(state, event)
            is HostSessionState.Ended -> reduceEnded(state, event)
            is HostSessionState.Error -> reduceError(state, event)
        }
    }

    // ─── Idle ──────────────────────────────────────────────────────────────────────────────────────────

    private fun reduceIdle(state: HostSessionState.Idle, event: HostSessionEvent): Result = when (event) {
        is HostSessionEvent.Schedule ->
            HostSessionState.Scheduling(sessionId = null, draft = event.draft)
                .with(HostEffect.CallControl(ControlAction.Schedule))
        is HostSessionEvent.Load -> loadFrom(state, event)
        is HostSessionEvent.SessionLoaded -> applyLoaded(state, event)
        else -> illegal(state, event)
    }

    // ─── Scheduling ──────────────────────────────────────────────────────────────────────────────────────

    private fun reduceScheduling(state: HostSessionState.Scheduling, event: HostSessionEvent): Result =
        when (event) {
            is HostSessionEvent.ControlResult -> when (val r = event.result) {
                is ApiResult.Success -> {
                    val session = r.data
                    HostSessionState.Scheduled(
                        sessionId = session.id,
                        startsAt = session.scheduledAt ?: event.now,
                    ).with(persist(session.id, HostSessionStatus.SCHEDULED))
                }
                else -> errorFrom(state, r, recoverable = true)
            }
            is HostSessionEvent.CancelSchedule ->
                HostSessionState.Idle.with(HostEffect.CallControl(ControlAction.CancelSchedule))
            is HostSessionEvent.SessionLoaded -> applyLoaded(state, event)
            else -> illegal(state, event)
        }

    // ─── Scheduled ───────────────────────────────────────────────────────────────────────────────────────

    private fun reduceScheduled(state: HostSessionState.Scheduled, event: HostSessionEvent): Result =
        when (event) {
            is HostSessionEvent.GoLive ->
                HostSessionState.Connecting(state.sessionId, attempt = 1)
                    .with(HostEffect.CallControl(ControlAction.Start), HostEffect.OpenIngest)
            is HostSessionEvent.Reschedule ->
                HostSessionState.Scheduling(state.sessionId, SessionDraft(scheduledAt = event.startsAt))
                    .with(HostEffect.CallControl(ControlAction.Reschedule))
            is HostSessionEvent.CancelSchedule ->
                HostSessionState.Ending(state.sessionId)
                    .with(HostEffect.CallControl(ControlAction.CancelSchedule))
            is HostSessionEvent.Schedule ->
                HostSessionState.Scheduling(state.sessionId, event.draft)
                    .with(HostEffect.CallControl(ControlAction.Schedule))
            is HostSessionEvent.ControlResult -> reduceControlResultGeneric(state, event)
            is HostSessionEvent.SessionLoaded -> applyLoaded(state, event)
            is HostSessionEvent.Refresh -> refresh(state)
            else -> illegal(state, event)
        }

    // ─── PreFlight ───────────────────────────────────────────────────────────────────────────────────────

    private fun reducePreFlight(state: HostSessionState.PreFlight, event: HostSessionEvent): Result =
        when (event) {
            is HostSessionEvent.GoLive ->
                HostSessionState.Connecting(state.sessionId, attempt = 1)
                    .with(HostEffect.CallControl(ControlAction.Start), HostEffect.OpenIngest)
            is HostSessionEvent.ControlResult -> reduceControlResultGeneric(state, event)
            is HostSessionEvent.SessionLoaded -> applyLoaded(state, event)
            is HostSessionEvent.Refresh -> refresh(state)
            else -> illegal(state, event)
        }

    // ─── Connecting ──────────────────────────────────────────────────────────────────────────────────────

    private fun reduceConnecting(state: HostSessionState.Connecting, event: HostSessionEvent): Result =
        when (event) {
            is HostSessionEvent.IngestStatusChanged -> when (event.status) {
                IngestStatus.Connected -> {
                    val health = HostHealth(uptime = Duration.ZERO, ingest = IngestStatus.Connected)
                    HostSessionState.Live(
                        sessionId = state.sessionId,
                        startedAt = event.now,
                        ingest = IngestStatus.Connected,
                        health = health,
                    ).with(
                        HostEffect.StartHealthTicker,
                        persist(state.sessionId, HostSessionStatus.LIVE),
                    )
                }
                IngestStatus.Failed, IngestStatus.Unavailable ->
                    HostSessionState.Error(
                        sessionId = state.sessionId,
                        cause = HostError.IngestFailed,
                        recoverable = true,
                        previous = state,
                    ).with(HostEffect.CloseIngest, HostEffect.StopHealthTicker)
                // Connecting / Reconnecting / Idle / Disconnected are intermediate; stay Connecting.
                IngestStatus.Connecting, IngestStatus.Reconnecting,
                IngestStatus.Idle, IngestStatus.Disconnected,
                -> state.with()
            }
            is HostSessionEvent.Stop ->
                HostSessionState.Ending(state.sessionId).with(
                    HostEffect.CallControl(ControlAction.Stop),
                    HostEffect.CloseIngest,
                    HostEffect.StopHealthTicker,
                )
            is HostSessionEvent.ControlResult -> reduceControlResultGeneric(state, event)
            is HostSessionEvent.SessionLoaded -> applyLoaded(state, event)
            else -> illegal(state, event)
        }

    // ─── Live ────────────────────────────────────────────────────────────────────────────────────────────

    private fun reduceLive(state: HostSessionState.Live, event: HostSessionEvent): Result = when (event) {
        is HostSessionEvent.Pause ->
            HostSessionState.Paused(state.sessionId, since = event.now, health = state.health)
                .with(HostEffect.CloseIngest)
        is HostSessionEvent.IngestStatusChanged -> when (event.status) {
            IngestStatus.Disconnected, IngestStatus.Reconnecting ->
                HostSessionState.Reconnecting(state.sessionId, attempt = 1, since = event.now)
                    .with(persist(state.sessionId, HostSessionStatus.RECONNECTING))
            IngestStatus.Failed, IngestStatus.Unavailable ->
                HostSessionState.Error(
                    sessionId = state.sessionId,
                    cause = HostError.IngestFailed,
                    recoverable = true,
                    previous = state,
                ).with(HostEffect.CloseIngest, HostEffect.StopHealthTicker)
            // Still healthy; refresh the ingest field on the existing health.
            IngestStatus.Connected ->
                state.copy(ingest = IngestStatus.Connected, health = state.health.copy(ingest = IngestStatus.Connected))
                    .with()
            IngestStatus.Connecting, IngestStatus.Idle -> state.with()
        }
        is HostSessionEvent.HealthTick ->
            state.copy(
                health = state.health.copy(
                    uptime = durationBetween(state.startedAt, event.now),
                    ingest = state.ingest,
                ),
            ).with()
        is HostSessionEvent.Stop ->
            HostSessionState.Ending(state.sessionId).with(
                HostEffect.CallControl(ControlAction.Stop),
                HostEffect.CloseIngest,
                HostEffect.StopHealthTicker,
            )
        is HostSessionEvent.ControlResult -> reduceControlResultGeneric(state, event)
        is HostSessionEvent.SessionLoaded -> applyLoaded(state, event)
        else -> illegal(state, event)
    }

    // ─── Paused (client-only) ──────────────────────────────────────────────────────────────────────────────

    private fun reducePaused(state: HostSessionState.Paused, event: HostSessionEvent): Result = when (event) {
        is HostSessionEvent.Resume ->
            // Re-open ingest; go back through Connecting so the ingest-connected event re-promotes to Live.
            HostSessionState.Connecting(state.sessionId, attempt = 1)
                .with(HostEffect.CallControl(ControlAction.Resume), HostEffect.OpenIngest)
        is HostSessionEvent.Stop ->
            HostSessionState.Ending(state.sessionId).with(
                HostEffect.CallControl(ControlAction.Stop),
                HostEffect.CloseIngest,
                HostEffect.StopHealthTicker,
            )
        is HostSessionEvent.ControlResult -> reduceControlResultGeneric(state, event)
        is HostSessionEvent.SessionLoaded -> applyLoaded(state, event)
        else -> illegal(state, event)
    }

    // ─── Reconnecting ────────────────────────────────────────────────────────────────────────────────────

    private fun reduceReconnecting(state: HostSessionState.Reconnecting, event: HostSessionEvent): Result =
        when (event) {
            is HostSessionEvent.IngestStatusChanged -> when (event.status) {
                IngestStatus.Connected -> {
                    val health = HostHealth(uptime = Duration.ZERO, ingest = IngestStatus.Connected)
                    HostSessionState.Live(
                        sessionId = state.sessionId,
                        startedAt = event.now,
                        ingest = IngestStatus.Connected,
                        health = health,
                    ).with(
                        HostEffect.StartHealthTicker,
                        persist(state.sessionId, HostSessionStatus.LIVE),
                    )
                }
                IngestStatus.Failed, IngestStatus.Unavailable ->
                    HostSessionState.Error(
                        sessionId = state.sessionId,
                        cause = HostError.IngestFailed,
                        recoverable = true,
                        previous = state,
                    ).with(HostEffect.CloseIngest, HostEffect.StopHealthTicker)
                IngestStatus.Connecting, IngestStatus.Reconnecting,
                IngestStatus.Disconnected, IngestStatus.Idle,
                -> state.with()
            }
            is HostSessionEvent.Stop ->
                HostSessionState.Ending(state.sessionId).with(
                    HostEffect.CallControl(ControlAction.Stop),
                    HostEffect.CloseIngest,
                    HostEffect.StopHealthTicker,
                )
            is HostSessionEvent.ControlResult -> reduceControlResultGeneric(state, event)
            is HostSessionEvent.SessionLoaded -> applyLoaded(state, event)
            else -> illegal(state, event)
        }

    // ─── Ending ──────────────────────────────────────────────────────────────────────────────────────────

    private fun reduceEnding(state: HostSessionState.Ending, event: HostSessionEvent): Result = when (event) {
        is HostSessionEvent.ControlResult -> when (val r = event.result) {
            is ApiResult.Success -> {
                val endedAt = r.data.stoppedAt ?: r.data.cancelledAt ?: event.now
                HostSessionState.Ended(state.sessionId, endedAt = endedAt)
                    .with(persist(state.sessionId, HostSessionStatus.ENDED))
            }
            else -> errorFrom(state, r, recoverable = false)
        }
        is HostSessionEvent.SessionLoaded -> applyLoaded(state, event)
        else -> illegal(state, event)
    }

    // ─── Ended (terminal) ──────────────────────────────────────────────────────────────────────────────────

    private fun reduceEnded(state: HostSessionState.Ended, event: HostSessionEvent): Result = when (event) {
        // A brand-new schedule may begin from a terminal state (the prior session is released).
        is HostSessionEvent.Schedule ->
            HostSessionState.Scheduling(sessionId = null, draft = event.draft)
                .with(HostEffect.CallControl(ControlAction.Schedule))
        is HostSessionEvent.Load -> loadFrom(state, event)
        is HostSessionEvent.SessionLoaded -> applyLoaded(state, event)
        else -> illegal(state, event)
    }

    // ─── Error ───────────────────────────────────────────────────────────────────────────────────────────

    private fun reduceError(state: HostSessionState.Error, event: HostSessionEvent): Result = when (event) {
        is HostSessionEvent.Refresh ->
            if (state.recoverable) {
                val restore = state.previous ?: HostSessionState.Idle
                val sid = restore.sessionId
                if (sid != null) restore.with(HostEffect.LoadSession(sid)) else restore.with()
            } else {
                illegal(state, event)
            }
        is HostSessionEvent.DismissError ->
            (state.previous ?: HostSessionState.Idle).with()
        is HostSessionEvent.SessionLoaded -> applyLoaded(state, event)
        is HostSessionEvent.Load -> loadFrom(state, event)
        else -> illegal(state, event)
    }

    // ─── Shared transitions ────────────────────────────────────────────────────────────────────────────────

    /**
     * Generic ControlResult handling for phases that issued a control call and are AWAITING it: success is
     * absorbed (no phase change here — the ingest event drives Live; Schedule/Stop have their own success
     * paths), but a FAILURE always tips into Error(prev=state).
     */
    private fun reduceControlResultGeneric(state: HostSessionState, event: HostSessionEvent.ControlResult): Result =
        when (val r = event.result) {
            is ApiResult.Success -> state.with()
            else -> errorFrom(state, r, recoverable = true)
        }

    /** Load(id): seed a restore phase + request the server session; Load(null) -> Idle (fresh). */
    private fun loadFrom(state: HostSessionState, event: HostSessionEvent.Load): Result {
        val id = event.sessionId ?: return HostSessionState.Idle.with()
        // Seed PreFlight as a safe placeholder; SessionLoaded will map the true phase.
        return HostSessionState.PreFlight(id, DeviceSelection()).with(HostEffect.LoadSession(id))
    }

    /**
     * Maps the server [BroadcastSessionStatus] to a client phase on SessionLoaded(ok). On a failed load we
     * tip to Error (recoverable) preserving the current state for Refresh.
     */
    private fun applyLoaded(state: HostSessionState, event: HostSessionEvent.SessionLoaded): Result =
        when (val r = event.result) {
            is ApiResult.Success -> {
                val s = r.data
                val next = mapServerStatus(s, event.now)
                next.with(persist(s.id, statusFor(next)))
            }
            else -> errorFrom(state, r, recoverable = true)
        }

    /** Server status -> client phase (the AND-317 §4.3 restore matrix). Unknown -> safe (Idle/Error). */
    private fun mapServerStatus(s: BroadcastSession, now: Instant): HostSessionState = when (s.status) {
        BroadcastSessionStatus.READY ->
            HostSessionState.PreFlight(s.id, DeviceSelection())
        BroadcastSessionStatus.PROVISIONING ->
            HostSessionState.Connecting(s.id, attempt = 1)
        BroadcastSessionStatus.LIVE ->
            HostSessionState.Live(
                sessionId = s.id,
                startedAt = s.startedAt ?: now,
                ingest = IngestStatus.Connecting,
                health = HostHealth(uptime = Duration.ZERO, ingest = IngestStatus.Connecting),
            )
        BroadcastSessionStatus.STOPPING ->
            HostSessionState.Ending(s.id)
        BroadcastSessionStatus.STOPPED, BroadcastSessionStatus.CANCELLED ->
            HostSessionState.Ended(s.id, endedAt = s.stoppedAt ?: s.cancelledAt ?: now)
        BroadcastSessionStatus.SCHEDULED ->
            HostSessionState.Scheduled(s.id, startsAt = s.scheduledAt ?: now)
        BroadcastSessionStatus.DRAFT ->
            // A loaded DRAFT is not a committed schedule (a stray scheduled_at is only a hint — only the
            // SCHEDULED status means scheduled), so a freshly-loaded draft restores to Idle.
            HostSessionState.Idle
        BroadcastSessionStatus.ERROR ->
            HostSessionState.Error(s.id, cause = HostError.Unknown, recoverable = true)
        BroadcastSessionStatus.UNKNOWN ->
            HostSessionState.Error(s.id, cause = HostError.Unknown, recoverable = false)
    }

    /** Builds an Error from a non-success [ApiResult], preserving [state] as previous for Refresh. */
    private fun errorFrom(state: HostSessionState, result: ApiResult<*>, recoverable: Boolean): Result {
        val cause = when (result) {
            is ApiResult.NetworkError -> if (result.isTimeout) HostError.Timeout else HostError.Network
            is ApiResult.Failure -> mapApiError(result.error)
            is ApiResult.Success -> HostError.Unknown
        }
        return HostSessionState.Error(
            sessionId = state.sessionId,
            cause = cause,
            recoverable = recoverable,
            previous = state,
        ).with()
    }

    /** Maps an [ApiError] to a coarse [HostError] band by HTTP status. */
    private fun mapApiError(error: ApiError): HostError = when (error.status) {
        401, 403 -> HostError.Auth
        409 -> HostError.Conflict
        419 -> HostError.Csrf
        422 -> HostError.Validation(field = null)
        else -> HostError.Unknown
    }

    private fun statusFor(state: HostSessionState): HostSessionStatus = when (state) {
        is HostSessionState.Idle -> HostSessionStatus.IDLE
        is HostSessionState.Scheduling -> HostSessionStatus.SCHEDULING
        is HostSessionState.Scheduled -> HostSessionStatus.SCHEDULED
        is HostSessionState.PreFlight -> HostSessionStatus.PREFLIGHT
        is HostSessionState.Connecting -> HostSessionStatus.CONNECTING
        is HostSessionState.Live -> HostSessionStatus.LIVE
        is HostSessionState.Paused -> HostSessionStatus.PAUSED
        is HostSessionState.Reconnecting -> HostSessionStatus.RECONNECTING
        is HostSessionState.Ending -> HostSessionStatus.ENDING
        is HostSessionState.Ended -> HostSessionStatus.ENDED
        is HostSessionState.Error -> HostSessionStatus.ERROR
    }

    private fun refresh(state: HostSessionState): Result {
        val id = state.sessionId ?: return state.with()
        return state.with(HostEffect.LoadSession(id))
    }

    private fun persist(sessionId: String?, status: HostSessionStatus): HostEffect =
        HostEffect.Persist(sessionId, status)

    private fun durationBetween(start: Instant, now: Instant): Duration =
        (now.toEpochMilli() - start.toEpochMilli()).coerceAtLeast(0L).milliseconds
}
