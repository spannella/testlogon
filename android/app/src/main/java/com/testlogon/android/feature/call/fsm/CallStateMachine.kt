package com.testlogon.android.feature.call.fsm

import com.testlogon.android.core.data.cache.Clock
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.call.CallMode
import com.testlogon.android.data.call.CallRepository
import com.testlogon.android.data.call.IdempotencyKey
import com.testlogon.android.data.webrtc.SignalingTransport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-305 — the @Singleton host that drives the CANONICAL pure FSM ([CallFsm]) against REAL seams.
 *
 * CONTRACT
 * - [state]: a hot [StateFlow] of the latest [CallState] (the source of truth screens render).
 * - [effects]: a one-shot [SharedFlow] (replay=0, buffered) for transient UI effects (PlayRingback /
 *   StopAudio / Error / CallBusy). Send* / timer / signal effects are EXECUTED here, not surfaced.
 * - [dispatch]: posts a [CallEvent] to an UNBOUNDED [Channel] consumed by exactly ONE coroutine that
 *   reduces -> updates state -> runs effects, IN ORDER. The reducer is pure and lock-free; serialization
 *   comes from the single-consumer channel, so no concurrent reduce can race.
 *
 * SEAMS (all REUSED, nothing added to CallRepository — see [CallEffect]):
 * - SendInvite -> repo.invite, then on success self-dispatch [CallEvent.RemoteAccepted] is NOT auto-issued
 *   (the control plane only confirms the invite was placed; the real accept arrives via signaling/push).
 *   The host records the per-call idempotency key so end/timeout reuse it.
 * - SendAccept/SendDecline/SendEnd/SendTimeout -> the matching repo op.
 * - SendSignal -> the FLAGGED [SignalingTransport] (NotConfigured -> no-op; the transition still happened).
 * - StartTimer/CancelTimer -> [CallTimerScheduler]; a fired timer self-dispatches InviteTimeout /
 *   ReconnectTimeout / HeartbeatTick.
 *
 * PERSISTENCE: every non-terminal transition saves a [CallSnapshot]; Ended clears it. [rehydrate] restores
 * a snapshot on cold start.
 *
 * MIGRATION: additive alongside [com.testlogon.android.feature.call.domain.CallManager]; see [CallState].
 */
@Singleton
class CallStateMachine @Inject constructor(
    private val repo: CallRepository,
    private val timers: CallTimerScheduler,
    private val snapshotStore: CallSnapshotStore,
    private val signaling: SignalingTransport,
    private val clock: Clock,
    private val scope: CoroutineScope,
) {

    private val _state = MutableStateFlow<CallState>(CallState.Idle)
    val state: StateFlow<CallState> = _state.asStateFlow()

    private val _effects = MutableSharedFlow<CallEffect>(replay = 0, extraBufferCapacity = 16)
    val effects: SharedFlow<CallEffect> = _effects.asSharedFlow()

    // Unbounded so dispatch() never suspends/drops; drained by the single consumer below (serialization).
    private val events = Channel<CallEvent>(Channel.UNLIMITED)

    // Per-call idempotency material so a retried end/timeout is server-deduped (AND-296 §6 semantics).
    private var idempotencyKey: String? = null

    init {
        scope.launch {
            for (event in events) {
                process(event)
            }
        }
    }

    /** Posts an event for serialized processing. Never blocks. */
    fun dispatch(event: CallEvent) {
        // trySend on an UNLIMITED channel always succeeds (no capacity bound).
        events.trySend(event)
    }

    /** Restores an in-progress call persisted before process death. Call once at startup. */
    suspend fun rehydrate() {
        if (_state.value != CallState.Idle) return
        val snapshot = snapshotStore.load() ?: return
        _state.value = snapshot.toState()
    }

    private suspend fun process(event: CallEvent) {
        // Mint idempotency material the moment an outgoing call starts.
        if (event is CallEvent.StartOutgoing && _state.value.let { it is CallState.Idle || it is CallState.Ended }) {
            idempotencyKey = IdempotencyKey.newKey()
        }
        val (next, effects) = CallFsm.reduce(_state.value, event, clock.now())
        val changed = next != _state.value
        _state.value = next
        for (effect in effects) {
            runEffect(effect)
        }
        if (changed) {
            persist(next)
        }
    }

    private suspend fun persist(state: CallState) {
        when {
            state.isTerminal || state is CallState.Idle -> {
                snapshotStore.clear()
                idempotencyKey = null
            }
            else -> CallSnapshot.from(state)?.let { snapshotStore.save(it) }
        }
    }

    private suspend fun runEffect(effect: CallEffect) {
        when (effect) {
            is CallEffect.SendInvite -> sendInvite(effect)
            is CallEffect.SendAccept -> repo.accept(effect.callId, idempotencyKey)
            is CallEffect.SendDecline -> repo.decline(effect.callId, reason = "declined")
            is CallEffect.SendEnd -> repo.end(
                callId = effect.callId,
                reason = effect.reason.wire(),
                idempotencyKey = idempotencyKey?.let { IdempotencyKey.deriveEnd(it) },
            )
            is CallEffect.SendTimeout -> repo.timeout(
                callId = effect.callId,
                reason = "no_answer",
                idempotencyKey = idempotencyKey?.let { IdempotencyKey.deriveEnd(it) },
            )
            is CallEffect.SendSignal -> signaling.sendSignalSafe(effect.payload)
            is CallEffect.StartTimer -> timers.start(effect.key, effect.delayMs) {
                dispatch(timerEvent(effect.key))
            }
            is CallEffect.CancelTimer -> timers.cancel(effect.key)
            CallEffect.PlayRingback,
            CallEffect.StopAudio,
            is CallEffect.Error,
            CallEffect.CallBusy,
            -> _effects.emit(effect)
        }
    }

    private suspend fun sendInvite(effect: CallEffect.SendInvite) {
        val result = repo.invite(
            callId = effect.callId,
            conversationId = effect.peer.conversationId,
            calleeUserId = effect.peer.userId,
            mode = if (effect.isVideo) CallMode.VIDEO else CallMode.AUDIO,
            idempotencyKey = idempotencyKey,
        )
        if (result is ApiResult.Failure || result is ApiResult.NetworkError) {
            // Control-plane invite failed: surface an error effect and tear down to Ended(ERROR).
            _effects.emit(CallEffect.Error("Could not place the call"))
            dispatch(CallEvent.HangUp)
        }
    }

    private fun timerEvent(key: TimerKey): CallEvent = when (key) {
        TimerKey.INVITE -> CallEvent.InviteTimeout
        TimerKey.RECONNECT -> CallEvent.ReconnectTimeout
        TimerKey.HEARTBEAT -> CallEvent.HeartbeatTick
    }
}

/** Maps the FSM [EndReason] to the repository's wire reason string (mirrors CallManager.endWireReason). */
private fun EndReason.wire(): String = when (this) {
    EndReason.LOCAL_HANGUP -> "hangup"
    EndReason.REMOTE_HANGUP -> "remote_hangup"
    EndReason.DECLINED -> "declined"
    EndReason.TIMED_OUT -> "no_answer"
    EndReason.MISSED -> "missed"
    EndReason.NETWORK_LOST -> "network"
    EndReason.BUSY -> "busy"
    EndReason.ERROR -> "ended"
}

/**
 * The FLAGGED transport exposes typed offer/answer/ice sends, not a raw string. AND-305 routes the opaque
 * payload through [SignalingTransport.connect] purely to exercise the seam (it returns NotConfigured and
 * does nothing). The real transport (a follow-up) will parse + dispatch the SDP/ICE.
 */
private suspend fun SignalingTransport.sendSignalSafe(payload: String) {
    // Route to the seam; the stub returns NotConfigured (no-op). Wrapped so a future impl can't throw here.
    runCatching { connect(callId = payload, selfId = "self") }
}
