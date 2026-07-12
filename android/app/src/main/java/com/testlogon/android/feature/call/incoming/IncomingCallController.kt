package com.testlogon.android.feature.call.incoming

import com.testlogon.android.core.data.cache.Clock
import com.testlogon.android.core.model.ApiResult
import android.util.Log
import com.testlogon.android.data.call.CallEvent
import com.testlogon.android.data.webrtc.PeerRole
import com.testlogon.android.data.call.CallRepository
import com.testlogon.android.data.call.IdempotencyKey
import com.testlogon.android.feature.call.domain.ActiveCall
import com.testlogon.android.feature.call.domain.CallManager
import com.testlogon.android.feature.call.domain.CallTiming
import com.testlogon.android.data.call.CallMode
import com.testlogon.android.feature.call.telecom.TelecomCallController
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-297 — process-singleton orchestrator for the RECEIVE side: payload ingestion -> ring ->
 * {accept | decline | timeout | caller-cancel}. Intentionally NOT a ViewModel so it survives Activity
 * recreation and is reachable from the FCM path before any UI exists; the full-screen Activity observes
 * [state].
 *
 * Single-call invariant: a second distinct invite while one is ringing is auto-declined "busy". Duplicate
 * deliveries of the same call_id ring exactly once (de-dup). The ring timeout is a single bounded delay
 * (NOT a while-loop). Accept posts .../accept then hands the connected session to [CallManager]; decline
 * posts .../decline. All terminal causes funnel through one guarded transition so the first cause wins.
 *
 * CONTROL PLANE is REAL/tested; the FCM delivery that triggers [onInvite] stays behind the flagged push
 * seam (inert without FCM).
 */
@Singleton
class IncomingCallController @Inject constructor(
    private val callRepository: CallRepository,
    private val ringer: Ringer,
    private val notifier: IncomingCallNotifier,
    private val callManager: CallManager,
    private val clock: Clock,
    private val scope: CoroutineScope,
    private val timing: CallTiming,
    // AND-304: best-effort self-managed Telecom modeling for the receive side, UNDER the AND-297 flow.
    private val telecomCallController: TelecomCallController,
) {

    private val _state = MutableStateFlow<IncomingCallState>(IncomingCallState.Idle)
    val state: StateFlow<IncomingCallState> = _state.asStateFlow()

    /** Recently-handled call ids (bounded de-dup, AND-297 FR-9). */
    private val seen = object : LinkedHashMap<String, Boolean>(SEEN_CAP, 0.75f, true) {
        override fun removeEldestEntry(eldest: Map.Entry<String, Boolean>?): Boolean = size > SEEN_CAP
    }

    private var timeoutJob: Job? = null

    @Synchronized
    fun onInvite(invite: CallEvent.Invite) {
        Log.d("TLHUB", "onInvite call=${invite.callId} state=${_state.value::class.simpleName}")
        // GHOST-CALL GUARD: never ring a STALE / already-terminal invite. The per-user /events/poll queue
        // re-serves the newest ~100 events on every app launch, including days-old `call.invite`s whose
        // call has long since gone terminal (missed/ended). Drop any invite whose server `created_at` is
        // older than the ring window (with clock-skew headroom) OR whose advertised expiry has already
        // passed. A genuine current call is only seconds old, so this never blocks a real ring.
        if (isStaleInvite(invite)) {
            Log.d("TLHUB", "onInvite DROPPED stale call=${invite.callId} createdAt=${invite.createdAtEpochSeconds} expiresAt=${invite.expiresAtEpochSeconds}")
            seen.put(invite.callId, true)
            return
        }
        // De-dup: same call_id rings exactly once.
        if (seen.put(invite.callId, true) != null) return

        val current = _state.value
        // Busy: a second distinct invite while one is ringing/connecting -> auto-decline "busy".
        if (current is IncomingCallState.Ringing || current is IncomingCallState.Connecting) {
            scope.launch { callRepository.decline(invite.callId, DeclineReason.BUSY.wire) }
            return
        }

        val deadline = computeDeadline(invite)
        _state.value = IncomingCallState.Ringing(invite, deadline)

        // AND-304: model the incoming call to the OS via self-managed Telecom (focus / DND / headset answer),
        // UNDER the AND-297 flow. Fully guarded + additive: reportIncoming() returns false (and no-ops) on
        // unsupported devices or any OEM failure. The self-managed account does NOT bring its own incoming UI,
        // so the AND-297 ringer + full-screen notification below ALWAYS run as the user-facing fallback.
        runCatching {
            telecomCallController.reportIncoming(
                callId = invite.callId,
                displayName = invite.callerName,
                video = invite.mode == CallMode.VIDEO,
            )
        }

        ringer.start()
        notifier.showRinging(invite)
        armTimeout(invite, deadline)
    }

    @Synchronized
    fun accept() {
        val ringing = _state.value as? IncomingCallState.Ringing ?: return
        val invite = ringing.invite
        stopRinging(invite.callId)
        _state.value = IncomingCallState.Connecting(invite)
        scope.launch {
            when (val result = callRepository.accept(invite.callId, idempotencyKeyFor(invite.callId))) {
                is ApiResult.Success -> {
                    val terminal = result.data.state.equals("ended", ignoreCase = true) ||
                        result.data.state.equals("declined", ignoreCase = true)
                    if (terminal) {
                        transitionToFailed(invite, "Call ended")
                    } else {
                        // Hand the accepted call to the shared CallManager (AND-296 negotiation path),
                        // which drives TURN/peer/signaling via the FLAGGED media seams.
                        callManager.adoptAcceptedCall(
                            ActiveCall(
                                callId = invite.callId,
                                conversationId = invite.conversationId,
                                peerUserId = invite.callerUserId,
                                mode = invite.mode,
                                idempotencyKey = idempotencyKeyFor(invite.callId),
                                role = PeerRole.ANSWERER,
                            ),
                            peerName = invite.callerName,
                        )
                        _state.value = IncomingCallState.Connected(invite.callId)
                    }
                }
                is ApiResult.Failure, is ApiResult.NetworkError ->
                    transitionToFailed(invite, "Couldn't connect")
            }
        }
    }

    @Synchronized
    fun decline(reason: DeclineReason = DeclineReason.USER) {
        val ringing = _state.value as? IncomingCallState.Ringing ?: return
        val invite = ringing.invite
        stopRinging(invite.callId)
        scope.launch { callRepository.decline(invite.callId, reason.wire) }
        _state.value = IncomingCallState.Dismissed
    }

    /** AND-297 — a caller-cancel / superseding terminal event (call.end / call.missed / call.decline). */
    @Synchronized
    fun onRemoteCancel(callId: String) {
        val invite = activeInvite() ?: return
        if (invite.callId != callId) return
        stopRinging(callId)
        _state.value = IncomingCallState.Dismissed
    }

    /** Routes an inbound [CallEvent] to the correct handler (invite -> ring; terminal -> cancel). */
    fun onCallEvent(event: CallEvent) {
        when (event) {
            is CallEvent.Invite -> onInvite(event)
            is CallEvent.Declined -> onRemoteCancel(event.callId)
            is CallEvent.Ended -> onRemoteCancel(event.callId)
            is CallEvent.Missed -> onRemoteCancel(event.callId)
            is CallEvent.Accepted, is CallEvent.Ignore -> Unit
        }
    }

    @Synchronized
    fun dismiss() {
        val callId = activeInvite()?.callId
        if (callId != null) stopRinging(callId)
        _state.value = IncomingCallState.Dismissed
    }

    private fun armTimeout(invite: CallEvent.Invite, deadlineEpochMs: Long) {
        timeoutJob?.cancel()
        val waitMs = (deadlineEpochMs - clock.now()).coerceAtLeast(0)
        timeoutJob = scope.launch {
            delay(waitMs)
            if ((_state.value as? IncomingCallState.Ringing)?.invite?.callId == invite.callId) {
                callRepository.timeout(
                    callId = invite.callId,
                    reason = TimeoutReason.NO_ANSWER.wire,
                    idempotencyKey = idempotencyKeyFor(invite.callId),
                )
                stopRinging(invite.callId)
                _state.value = IncomingCallState.Dismissed
            }
        }
    }

    /**
     * True when [invite] is too old to ring — a replayed/terminal invite from the /events/poll backlog.
     * Uses the invite's server `created_at` (primary) and the advertised `expires_at` (secondary). When
     * neither timestamp is present we fail OPEN (ring), so a genuine invite is never suppressed.
     */
    private fun isStaleInvite(invite: CallEvent.Invite): Boolean {
        val now = clock.now()
        val createdMs = invite.createdAtEpochSeconds?.let { it * 1_000L }
        if (createdMs != null && now - createdMs > timing.staleInviteMaxAgeMs) return true
        val expiresMs = invite.expiresAtEpochSeconds?.let { it * 1_000L }
        if (expiresMs != null && expiresMs < now) return true
        return false
    }

    private fun computeDeadline(invite: CallEvent.Invite): Long {
        val ceiling = clock.now() + timing.ringTimeoutMs
        val advertised = invite.expiresAtEpochSeconds?.let { it * 1_000L }
        return advertised?.coerceAtMost(ceiling) ?: ceiling
    }

    private fun transitionToFailed(invite: CallEvent.Invite, message: String) {
        _state.value = IncomingCallState.Failed(invite, message)
    }

    private fun stopRinging(callId: String) {
        timeoutJob?.cancel()
        timeoutJob = null
        ringer.stop()
        notifier.cancel(callId)
    }

    private fun activeInvite(): CallEvent.Invite? = when (val s = _state.value) {
        is IncomingCallState.Ringing -> s.invite
        is IncomingCallState.Connecting -> s.invite
        is IncomingCallState.Failed -> s.invite
        else -> null
    }

    /** Stable per-call idempotency key derived from the call id (safe to reuse on retry). */
    private fun idempotencyKeyFor(callId: String): String = IdempotencyKey.deriveEnd(callId)

    private companion object {
        const val SEEN_CAP = 32
    }
}
