package com.testlogon.android.feature.broadcast.host

import androidx.annotation.StringRes
import com.testlogon.android.R
import java.time.Instant
import kotlin.time.Duration

/**
 * AND-317 — PURE presentation-layer models for the host broadcast FSM.
 *
 * This file is deliberately Android-light: only [androidx.annotation.StringRes] (a compile-time int
 * annotation) and [com.testlogon.android.R] string ids are referenced for the per-phase status label —
 * there are NO coroutines, NO Instant.now(), NO context here. All timestamps arrive via events (the
 * reducer is total + side-effect-free; see [HostSessionStateMachine]).
 *
 * The server "HostSession" is the EXISTING [com.testlogon.android.data.broadcast.BroadcastSession]; this
 * presentation FSM layers a client phase on top of its
 * [com.testlogon.android.data.broadcast.BroadcastSessionStatus].
 */

// ─── Control / status enums ──────────────────────────────────────────────────────────────────────────

/**
 * The set of SERVER control-plane actions the FSM can request. Each maps to an EXISTING repo call
 * ([com.testlogon.android.data.broadcast.HostControlRepository] /
 * [com.testlogon.android.data.broadcast.BroadcastRepository]) — see [BroadcastHostRepository].
 *
 * There is deliberately NO Pause member: there is NO server pause endpoint. Pause is CLIENT-ONLY
 * (it just closes/mutes the ingest); it NEVER emits a [HostEffect.CallControl].
 */
enum class ControlAction { Schedule, Start, Stop, Resume, Reschedule, CancelSchedule }

/**
 * Client ingest status, mapped from the FLAGGED publisher's
 * [com.testlogon.android.data.webrtc.PublishState] by [WebRtcIngestController]. Because host media is
 * FLAGGED, the live stub only ever resolves to [Unavailable]; the FSM logic over this enum is the
 * AND-317 deliverable, not real media.
 */
enum class IngestStatus { Idle, Connecting, Connected, Disconnected, Reconnecting, Failed, Unavailable }

/**
 * The persisted coarse phase token (DataStore last_status), mirroring the client phase. Kept separate
 * from the server [com.testlogon.android.data.broadcast.BroadcastSessionStatus] because the client has
 * extra phases (PreFlight / Connecting / Reconnecting / Paused) the server does not model.
 */
enum class HostSessionStatus {
    IDLE, SCHEDULING, SCHEDULED, PREFLIGHT, CONNECTING, LIVE, PAUSED, RECONNECTING, ENDING, ENDED, ERROR
}

// ─── Errors ──────────────────────────────────────────────────────────────────────────────────────────

/** A redaction-safe host error cause. [Validation] optionally carries the offending field. */
sealed interface HostError {
    data object Network : HostError
    data object Timeout : HostError
    data object Auth : HostError
    data object Csrf : HostError
    data object Conflict : HostError
    data object IngestFailed : HostError
    data class Validation(val field: String? = null) : HostError
    data object Unknown : HostError
}

// ─── Value objects ───────────────────────────────────────────────────────────────────────────────────

/** Live health snapshot, recomputed on each HealthTick from uptime + the latest [IngestStatus]. */
data class HostHealth(
    val uptime: Duration,
    val ingest: IngestStatus,
    val bitrateKbps: Int? = null,
    val droppedFrames: Int? = null,
    val lastError: HostError? = null,
)

/** Minimal scheduling draft (the full create/schedule form is AND-307's CreateBroadcast surface). */
data class SessionDraft(
    val name: String? = null,
    val scheduledAt: Instant? = null,
)

/** Minimal device-selection placeholder for the PreFlight phase (full picker is a follow-up). */
data class DeviceSelection(
    val cameraId: String? = null,
    val micId: String? = null,
)

// ─── State ───────────────────────────────────────────────────────────────────────────────────────────

/**
 * The host session phase. [sessionId] is null only before a draft session has been created. Each phase
 * exposes a [statusLabelKey] @StringRes id (a real R.string added in strings.xml — never English here).
 */
sealed interface HostSessionState {

    val sessionId: String?

    @get:StringRes
    val statusLabelKey: Int

    /** No session in progress. */
    data object Idle : HostSessionState {
        override val sessionId: String? = null
        override val statusLabelKey: Int = R.string.host_phase_idle
    }

    /** A schedule request is in flight (CallControl(Schedule)). */
    data class Scheduling(
        override val sessionId: String?,
        val draft: SessionDraft,
    ) : HostSessionState {
        override val statusLabelKey: Int = R.string.host_phase_scheduling
    }

    /** Scheduled for [startsAt]; not yet live. */
    data class Scheduled(
        override val sessionId: String,
        val startsAt: Instant,
    ) : HostSessionState {
        override val statusLabelKey: Int = R.string.host_phase_scheduled
    }

    /** Pre-flight device check before go-live. */
    data class PreFlight(
        override val sessionId: String,
        val devices: DeviceSelection,
    ) : HostSessionState {
        override val statusLabelKey: Int = R.string.host_phase_preflight
    }

    /** Go-live requested; awaiting ingest connect (attempt count drives reconnect/backoff display). */
    data class Connecting(
        override val sessionId: String,
        val attempt: Int,
    ) : HostSessionState {
        override val statusLabelKey: Int = R.string.host_phase_connecting
    }

    /** Live and publishing. */
    data class Live(
        override val sessionId: String,
        val startedAt: Instant,
        val ingest: IngestStatus,
        val health: HostHealth,
    ) : HostSessionState {
        override val statusLabelKey: Int = R.string.host_phase_live
    }

    /** Client-side paused (ingest closed/muted); the server session is still live. */
    data class Paused(
        override val sessionId: String,
        val since: Instant,
        val health: HostHealth,
    ) : HostSessionState {
        override val statusLabelKey: Int = R.string.host_phase_paused
    }

    /** Ingest dropped while live; attempting recovery. */
    data class Reconnecting(
        override val sessionId: String,
        val attempt: Int,
        val since: Instant,
    ) : HostSessionState {
        override val statusLabelKey: Int = R.string.host_phase_reconnecting
    }

    /** Stop requested; teardown in flight (CallControl(Stop)). */
    data class Ending(
        override val sessionId: String,
    ) : HostSessionState {
        override val statusLabelKey: Int = R.string.host_phase_ending
    }

    /** Terminal: stopped or cancelled. */
    data class Ended(
        override val sessionId: String,
        val endedAt: Instant,
    ) : HostSessionState {
        override val statusLabelKey: Int = R.string.host_phase_ended
    }

    /**
     * An error band. [recoverable] errors can Refresh back to [previous]; non-recoverable ones are
     * terminal-ish. [previous] is retained so Refresh can restore the pre-error phase.
     */
    data class Error(
        override val sessionId: String?,
        val cause: HostError,
        val recoverable: Boolean,
        val previous: HostSessionState? = null,
    ) : HostSessionState {
        override val statusLabelKey: Int = R.string.host_phase_error
    }
}

// ─── Events ──────────────────────────────────────────────────────────────────────────────────────────

/**
 * Inputs to [HostSessionStateMachine.reduce]. Timestamps that the reducer needs are carried IN the event
 * (e.g. [now]) so the reducer stays pure. [SessionLoaded] / [ControlResult] are the async results folded
 * back as internal events by the host ([BroadcastHostViewModel]).
 */
sealed interface HostSessionEvent {
    data class Load(val sessionId: String?) : HostSessionEvent
    data class Schedule(val draft: SessionDraft, val now: Instant) : HostSessionEvent
    data object CancelSchedule : HostSessionEvent
    data class GoLive(val now: Instant) : HostSessionEvent
    data class Pause(val now: Instant) : HostSessionEvent
    data class Resume(val now: Instant) : HostSessionEvent
    data class Reschedule(val startsAt: Instant) : HostSessionEvent
    data object Stop : HostSessionEvent
    data class IngestStatusChanged(val status: IngestStatus, val now: Instant) : HostSessionEvent
    data class HealthTick(val now: Instant) : HostSessionEvent
    data object Refresh : HostSessionEvent
    data object DismissError : HostSessionEvent
    data class SessionLoaded(
        val result: com.testlogon.android.core.model.ApiResult<com.testlogon.android.data.broadcast.BroadcastSession>,
        val now: Instant,
    ) : HostSessionEvent
    data class ControlResult(
        val action: ControlAction,
        val result: com.testlogon.android.core.model.ApiResult<com.testlogon.android.data.broadcast.BroadcastSession>,
        val now: Instant,
    ) : HostSessionEvent
}

// ─── Effects ─────────────────────────────────────────────────────────────────────────────────────────

/** Side-effect DESCRIPTIONS produced by the reducer; the host ([BroadcastHostViewModel]) performs the IO. */
sealed interface HostEffect {
    data class LoadSession(val sessionId: String) : HostEffect
    data class CallControl(val action: ControlAction) : HostEffect
    data object OpenIngest : HostEffect
    data object CloseIngest : HostEffect
    data object StartHealthTicker : HostEffect
    data object StopHealthTicker : HostEffect
    data class Persist(val sessionId: String?, val status: HostSessionStatus) : HostEffect
    data class LogIllegalTransition(val from: String, val event: String) : HostEffect
}
