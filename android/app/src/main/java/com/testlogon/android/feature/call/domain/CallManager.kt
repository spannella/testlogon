package com.testlogon.android.feature.call.domain

import com.testlogon.android.core.data.cache.Clock
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.call.CallEvent
import com.testlogon.android.data.call.CallId
import com.testlogon.android.data.call.CallMode
import com.testlogon.android.data.call.CallRepository
import com.testlogon.android.data.call.IdempotencyKey
import com.testlogon.android.data.webrtc.IceServersProvider
import com.testlogon.android.data.webrtc.PeerConfig
import com.testlogon.android.data.webrtc.PeerConnectionController
import com.testlogon.android.data.webrtc.PeerResult
import com.testlogon.android.data.webrtc.PeerRole
import com.testlogon.android.data.webrtc.SignalingMessage
import com.testlogon.android.data.webrtc.SignalingTransport
import com.testlogon.android.data.webrtc.TransportResult
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-296 — process-singleton orchestrator for the outgoing 1:1 call flow (and, via AND-297, the
 * accept side of an incoming call). Owns the call lifecycle independent of any composable so the call
 * survives config changes / recomposition; screens merely render [state].
 *
 * CONTROL PLANE (REAL, implemented + tested): invite -> ringing -> answered/declined/ended via
 * [CallRepository] (AND-295). MEDIA (FLAGGED): TURN fetch (AND-291), peer offer (AND-289), and signaling
 * (AND-290) route through the seam stubs which return NotConfigured; the manager records
 * [CallSessionState.mediaUnavailable] = true ("call media unavailable") and NEVER starts a real peer.
 *
 * Timers are bounded coroutine jobs (ring timeout + heartbeat ticker), children of the orchestration
 * scope, cancelled on any terminal phase — no unbounded while+delay that would hang advanceUntilIdle.
 */
@Singleton
class CallManager @Inject constructor(
    private val callRepository: CallRepository,
    private val iceServers: IceServersProvider,
    private val peer: PeerConnectionController,
    private val signaling: SignalingTransport,
    private val clock: Clock,
    private val scope: CoroutineScope,
    private val timing: CallTiming,
) {

    private val _state = MutableStateFlow(CallSessionState())
    val state: StateFlow<CallSessionState> = _state.asStateFlow()

    private var orchestrationJob: Job? = null
    private var ringTimeoutJob: Job? = null
    private var heartbeatJob: Job? = null

    /** True while a call occupies the manager (single-active-call invariant, AND-296 FR-10). */
    fun isBusy(): Boolean = _state.value.phase != CallPhase.Idle && !_state.value.phase.isTerminal

    /**
     * Places a 1:1 call: invite (control plane) -> Ringing -> negotiate via the FLAGGED media seams.
     * Returns the invite [ApiResult] so the entry point can surface invite failure inline; the ongoing
     * negotiation continues on [scope].
     */
    fun placeCall(
        conversationId: String,
        calleeUserId: String,
        mode: CallMode = CallMode.AUDIO,
        peerName: String? = null,
        paid: Boolean = false,
        rateCentsPerMin: Int? = null,
    ) {
        if (isBusy()) return
        val idk = IdempotencyKey.newKey()
        val active = ActiveCall(
            callId = CallId.new(),
            conversationId = conversationId,
            peerUserId = calleeUserId,
            mode = mode,
            idempotencyKey = idk,
        )
        _state.value = CallSessionState(
            phase = CallPhase.Inviting,
            call = active,
            peerName = peerName,
            // AND-301: optimistic paid/rate from the entry point; reconciled with the invite RESPONSE
            // (authoritative paid/rate_cents_per_minute) in runOutgoing().
            paid = paid,
            rateCentsPerMinute = rateCentsPerMin ?: 0,
        )
        // AND-296: the orchestration coroutine only DRIVES setup (invite -> Ringing -> negotiate). It must
        // NOT cancel the ring-timeout/heartbeat in a finally: in the FLAGGED-media path negotiate() returns
        // promptly, so this coroutine completes almost immediately. The ring timeout has to OUTLIVE that
        // setup completion (a no-answer call must still time out) — it is cancelled only on answer/decline/
        // remote-end/teardown by the event handlers, onConnected(), and teardown(), never here.
        orchestrationJob = scope.launch { runOutgoing(active) }
    }

    /**
     * AND-297 — adopts an already-accepted incoming call (the incoming controller posted accept). Drives
     * the same negotiation/heartbeat path as the outgoing flow from the Connecting phase.
     */
    fun adoptAcceptedCall(active: ActiveCall, peerName: String?) {
        if (isBusy()) return
        _state.value = CallSessionState(
            phase = CallPhase.Connecting,
            call = active,
            peerName = peerName,
        )
        // As above (AND-297): do NOT cancel timers when this setup coroutine finishes. The heartbeat is
        // armed later by onConnected() and must survive; teardown()/endCall() own the terminal cancellation.
        // Media negotiation is driven by CallSignalingHub once the phase reaches Connecting.
    }

    private suspend fun runOutgoing(active: ActiveCall) {
        val current = _state.value
        when (
            val invited = callRepository.invite(
                callId = active.callId,
                conversationId = active.conversationId,
                calleeUserId = active.peerUserId,
                mode = active.mode,
                idempotencyKey = active.idempotencyKey,
                paid = current.paid,
                rateCentsPerMin = current.rateCentsPerMinute.takeIf { it > 0 },
            )
        ) {
            is ApiResult.Success -> {
                // AND-301: adopt the AUTHORITATIVE paid/rate from the invite response (web also relies on
                // the server echo) so the billing UI uses server-confirmed values.
                val data = invited.data
                _state.update {
                    it.copy(
                        phase = CallPhase.Ringing,
                        paid = data.paid,
                        rateCentsPerMinute = data.rateCentsPerMinute ?: it.rateCentsPerMinute,
                    )
                }
                armRingTimeout(active)
            }
            is ApiResult.Failure, is ApiResult.NetworkError ->
                // Invite failed: no peer was created. Surface a failed phase for Retry/Close.
                _state.update { it.copy(phase = CallPhase.Failed(CallEndReason.NETWORK)) }
        }
    }

    /**
     * Drives the media negotiation through the FLAGGED seams. Because the stubs return NotConfigured at
     * every step (TURN fetch still returns a STUN-only fallback list; peer/offer/signaling are inert),
     * the control plane reaches Ringing/Connecting but media is unavailable. NEVER starts a real peer.
     */

    /** Bounded ring timeout: a single delay (NOT a while-loop). Cancelled on any terminal/answer. */
    private fun armRingTimeout(active: ActiveCall) {
        ringTimeoutJob?.cancel()
        ringTimeoutJob = scope.launch {
            delay(timing.ringTimeoutMs)
            if (_state.value.phase == CallPhase.Ringing) {
                callRepository.timeout(
                    callId = active.callId,
                    reason = "no_answer",
                    idempotencyKey = IdempotencyKey.deriveEnd(active.idempotencyKey),
                )
                teardown(CallPhase.Ended(CallEndReason.NO_ANSWER))
            }
        }
    }

    /**
     * Marks the call connected and starts the bounded heartbeat ticker. Called by AND-290's transport
     * (real impl) when the peer reports CONNECTED; exposed so the staged loopback test can drive it.
     */
    fun onConnected() {
        val active = _state.value.call ?: run {
            android.util.Log.d("TLHUB", "onConnected: NO active call (ignored)")
            return
        }
        android.util.Log.d("TLHUB", "onConnected: phase->Connected call=${active.callId}")
        ringTimeoutJob?.cancel()
        _state.update { it.copy(phase = CallPhase.Connected(clock.now())) }
        startHeartbeat(active)
    }

    private fun startHeartbeat(active: ActiveCall) {
        heartbeatJob?.cancel()
        heartbeatJob = scope.launch {
            var consecutiveFailures = 0
            // Bounded loop: stops as soon as the phase leaves Connected (terminal/ending) — and the job
            // is also cancelled on teardown — so it never hangs advanceUntilIdle.
            while (isActive && _state.value.phase is CallPhase.Connected) {
                delay(timing.heartbeatIntervalMs)
                if (_state.value.phase !is CallPhase.Connected) break
                when (
                    val hb = callRepository.heartbeat(
                        callId = active.callId,
                        clientTsEpochSeconds = clock.now() / 1_000L,
                    )
                ) {
                    is ApiResult.Success -> {
                        consecutiveFailures = 0
                        val data = hb.data
                        _state.update {
                            it.copy(
                                elapsedSeconds = data.elapsedSeconds,
                                warnLowBalance = data.warnLowBalance,
                                minutesRemaining = data.minutesRemaining,
                                // AND-301: authoritative billing values (cents fit Int; server caps a call).
                                totalCostCents = data.totalCostCents.toInt(),
                                balanceRemainingCents = data.balanceRemainingCents.toInt(),
                                maxDurationWarning = data.maxDurationWarning,
                            )
                        }
                        if (data.shouldTerminate) {
                            endCall(CallEndReason.INSUFFICIENT_BALANCE)
                            break
                        }
                    }
                    is ApiResult.Failure, is ApiResult.NetworkError -> {
                        consecutiveFailures++
                        if (consecutiveFailures >= timing.maxConsecutiveHeartbeatFailures) {
                            endCall(CallEndReason.NETWORK)
                            break
                        }
                    }
                }
            }
        }
    }

    /** Applies an inbound [CallEvent] for the active call (remote decline/end/missed). */
    fun onCallEvent(event: CallEvent) {
        val active = _state.value.call ?: return
        val eventCallId = when (event) {
            is CallEvent.Accepted -> event.callId
            is CallEvent.Declined -> event.callId
            is CallEvent.Ended -> event.callId
            is CallEvent.Missed -> event.callId
            is CallEvent.Invite -> event.callId
            is CallEvent.Ignore -> return
        }
        if (eventCallId != active.callId) return
        when (event) {
            is CallEvent.Accepted -> if (_state.value.phase == CallPhase.Ringing) {
                ringTimeoutJob?.cancel()
                _state.update { it.copy(phase = CallPhase.Connecting) }
            }
            is CallEvent.Declined -> teardown(CallPhase.Ended(CallEndReason.DECLINED))
            is CallEvent.Ended -> teardown(CallPhase.Ended(CallEndReason.REMOTE_HANGUP))
            is CallEvent.Missed -> teardown(CallPhase.Ended(CallEndReason.NO_ANSWER))
            else -> Unit
        }
    }

    /**
     * User hang-up (or server-driven end): POST end (unless a no-POST teardown like remote decline) then
     * tear down. Teardown always runs even if the end POST fails (finally semantics).
     */
    fun endCall(reason: CallEndReason = CallEndReason.HANGUP) {
        val active = _state.value.call ?: return
        if (_state.value.phase.isTerminal || _state.value.phase == CallPhase.Ending) return
        _state.update { it.copy(phase = CallPhase.Ending) }
        scope.launch {
            try {
                callRepository.end(
                    callId = active.callId,
                    reason = reason.endWireReason(),
                    idempotencyKey = IdempotencyKey.deriveEnd(active.idempotencyKey),
                )
            } finally {
                teardown(CallPhase.Ended(reason))
            }
        }
    }

    /** Resets to Idle (after a terminal phase has been observed). */
    fun reset() {
        if (_state.value.phase.isTerminal) {
            cancelTimers()
            _state.value = CallSessionState()
        }
    }

    private fun teardown(terminal: CallPhase) {
        cancelTimers()
        // Idempotent media release: the stub close() only flips the lifecycle; no real peer existed.
        peer.close()
        signaling.close()
        orchestrationJob?.cancel()
        orchestrationJob = null
        _state.update { it.copy(phase = terminal) }
    }

    private fun cancelTimers() {
        ringTimeoutJob?.cancel()
        ringTimeoutJob = null
        heartbeatJob?.cancel()
        heartbeatJob = null
    }
}

private fun CallEndReason.endWireReason(): String = when (this) {
    CallEndReason.HANGUP -> "hangup"
    CallEndReason.INSUFFICIENT_BALANCE -> "insufficient_balance"
    CallEndReason.NETWORK -> "network"
    CallEndReason.NEGOTIATION_FAILED -> "negotiation_failed"
    else -> "ended"
}
