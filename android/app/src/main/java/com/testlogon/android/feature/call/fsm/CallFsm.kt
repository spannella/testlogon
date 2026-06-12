package com.testlogon.android.feature.call.fsm

/**
 * AND-305 — the CANONICAL, pure call finite-state-machine reducer.
 *
 * [reduce] is PURE and TOTAL: every (state, event) pair maps to a defined transition OR an explicit no-op
 * (the state returned unchanged with an empty effect list). It NEVER throws and has no undefined cases —
 * the exhaustive `when` over [CallState] plus an exhaustive `when` over [CallEvent] in each branch
 * guarantees this. Time is injected as [nowMs] (android-free; no java.time, no Clock here).
 *
 * Returned effects are DESCRIPTIONS only; the host ([CallStateMachine]) performs the IO. See [CallEffect].
 *
 * Single-call invariant: while a call occupies a non-terminal state, a NEW StartOutgoing / IncomingInvite
 * for a DIFFERENT callId leaves the state unchanged and emits [CallEffect.CallBusy]. (A repeat for the SAME
 * callId is also a no-op — defensive against duplicate push delivery.)
 *
 * This is ADDITIVE to the existing [com.testlogon.android.feature.call.domain.CallManager] runtime; see
 * [CallState] for the migration note.
 */
object CallFsm {

    /** No state change, no effects. */
    private fun CallState.noop(): Pair<CallState, List<CallEffect>> = this to emptyList()

    private infix fun CallState.with(effects: List<CallEffect>): Pair<CallState, List<CallEffect>> =
        this to effects

    fun reduce(
        state: CallState,
        event: CallEvent,
        nowMs: Long,
    ): Pair<CallState, List<CallEffect>> = when (state) {
        is CallState.Idle -> reduceIdle(state, event)
        is CallState.Dialing -> reduceDialing(state, event)
        is CallState.IncomingRinging -> reduceIncomingRinging(state, event)
        is CallState.Connecting -> reduceConnecting(state, event, nowMs)
        is CallState.Active -> reduceActive(state, event, nowMs)
        is CallState.Reconnecting -> reduceReconnecting(state, event)
        is CallState.Ending -> reduceEnding(state, event)
        is CallState.Ended -> reduceEnded(state, event)
    }

    // ─── Idle ────────────────────────────────────────────────────────────────────────────────────────

    private fun reduceIdle(
        state: CallState.Idle,
        event: CallEvent,
    ): Pair<CallState, List<CallEffect>> = when (event) {
        is CallEvent.StartOutgoing ->
            CallState.Dialing(event.callId, event.peer, event.isVideo) with listOf(
                CallEffect.SendInvite(event.callId, event.peer, event.isVideo),
                CallEffect.StartTimer(TimerKey.INVITE, CallTimeouts.INVITE_MS),
                CallEffect.PlayRingback,
            )
        is CallEvent.IncomingInvite ->
            CallState.IncomingRinging(event.callId, event.peer, event.isVideo) with listOf(
                CallEffect.StartTimer(TimerKey.INVITE, CallTimeouts.RING_MS),
                CallEffect.PlayRingback,
            )
        // Nothing else is meaningful with no call. No-op.
        CallEvent.Accept, CallEvent.Decline, CallEvent.HangUp,
        CallEvent.ToggleMute, CallEvent.ToggleCamera, CallEvent.ToggleSpeaker, CallEvent.FlipCamera,
        is CallEvent.RemoteAccepted, is CallEvent.RemoteDeclined, is CallEvent.RemoteEnded,
        is CallEvent.RemoteSignal,
        CallEvent.IceConnected, CallEvent.IceDisconnected, CallEvent.IceFailed,
        CallEvent.InviteTimeout, CallEvent.ReconnectTimeout, CallEvent.HeartbeatTick,
        -> state.noop()
    }

    // ─── Dialing (outgoing, awaiting answer) ──────────────────────────────────────────────────────────

    private fun reduceDialing(
        state: CallState.Dialing,
        event: CallEvent,
    ): Pair<CallState, List<CallEffect>> = when (event) {
        is CallEvent.RemoteAccepted ->
            if (event.callId != state.callId) state.noop()
            else CallState.Connecting(state.callId, state.peer, state.isVideo) with listOf(
                CallEffect.CancelTimer(TimerKey.INVITE),
                CallEffect.StopAudio,
            )
        is CallEvent.RemoteDeclined ->
            if (event.callId != state.callId) state.noop()
            else ended(state.callId, EndReason.DECLINED, 0L) with listOf(
                CallEffect.CancelTimer(TimerKey.INVITE),
                CallEffect.StopAudio,
            )
        is CallEvent.RemoteEnded ->
            if (event.callId != state.callId) state.noop()
            else ended(state.callId, EndReason.REMOTE_HANGUP, 0L) with listOf(
                CallEffect.CancelTimer(TimerKey.INVITE),
                CallEffect.StopAudio,
            )
        CallEvent.HangUp ->
            CallState.Ending(state.callId, EndReason.LOCAL_HANGUP) with listOf(
                CallEffect.SendEnd(state.callId, EndReason.LOCAL_HANGUP),
                CallEffect.CancelTimer(TimerKey.INVITE),
                CallEffect.StopAudio,
            )
        CallEvent.InviteTimeout ->
            ended(state.callId, EndReason.TIMED_OUT, 0L) with listOf(
                CallEffect.SendTimeout(state.callId),
                CallEffect.StopAudio,
            )
        is CallEvent.RemoteSignal -> passSignal(state, event)
        // Second-call rejected (single-call invariant); same-id repeat is a no-op too.
        is CallEvent.StartOutgoing -> busyOrNoop(state, event.callId)
        is CallEvent.IncomingInvite -> busyOrNoop(state, event.callId)
        // Not meaningful while dialing. No-op.
        CallEvent.Accept, CallEvent.Decline,
        CallEvent.ToggleMute, CallEvent.ToggleCamera, CallEvent.ToggleSpeaker, CallEvent.FlipCamera,
        CallEvent.IceConnected, CallEvent.IceDisconnected, CallEvent.IceFailed,
        CallEvent.ReconnectTimeout, CallEvent.HeartbeatTick,
        -> state.noop()
    }

    // ─── IncomingRinging (incoming, awaiting local answer) ───────────────────────────────────────────

    private fun reduceIncomingRinging(
        state: CallState.IncomingRinging,
        event: CallEvent,
    ): Pair<CallState, List<CallEffect>> = when (event) {
        CallEvent.Accept ->
            CallState.Connecting(state.callId, state.peer, state.isVideo) with listOf(
                CallEffect.SendAccept(state.callId),
                CallEffect.CancelTimer(TimerKey.INVITE),
                CallEffect.StopAudio,
            )
        CallEvent.Decline ->
            ended(state.callId, EndReason.DECLINED, 0L) with listOf(
                CallEffect.SendDecline(state.callId),
                CallEffect.CancelTimer(TimerKey.INVITE),
                CallEffect.StopAudio,
            )
        CallEvent.HangUp ->
            // Treat an explicit hang-up while ringing as a decline (local reject).
            ended(state.callId, EndReason.DECLINED, 0L) with listOf(
                CallEffect.SendDecline(state.callId),
                CallEffect.CancelTimer(TimerKey.INVITE),
                CallEffect.StopAudio,
            )
        is CallEvent.RemoteEnded ->
            if (event.callId != state.callId) state.noop()
            else ended(state.callId, EndReason.REMOTE_HANGUP, 0L) with listOf(
                CallEffect.CancelTimer(TimerKey.INVITE),
                CallEffect.StopAudio,
            )
        CallEvent.InviteTimeout ->
            // No local answer in the ring window -> a MISSED call.
            ended(state.callId, EndReason.MISSED, 0L) with listOf(
                CallEffect.SendTimeout(state.callId),
                CallEffect.StopAudio,
            )
        is CallEvent.RemoteSignal -> passSignal(state, event)
        is CallEvent.StartOutgoing -> busyOrNoop(state, event.callId)
        is CallEvent.IncomingInvite -> busyOrNoop(state, event.callId)
        // Not meaningful while ringing in. No-op.
        is CallEvent.RemoteAccepted, is CallEvent.RemoteDeclined,
        CallEvent.ToggleMute, CallEvent.ToggleCamera, CallEvent.ToggleSpeaker, CallEvent.FlipCamera,
        CallEvent.IceConnected, CallEvent.IceDisconnected, CallEvent.IceFailed,
        CallEvent.ReconnectTimeout, CallEvent.HeartbeatTick,
        -> state.noop()
    }

    // ─── Connecting (negotiating media) ───────────────────────────────────────────────────────────────

    private fun reduceConnecting(
        state: CallState.Connecting,
        event: CallEvent,
        nowMs: Long,
    ): Pair<CallState, List<CallEffect>> = when (event) {
        CallEvent.IceConnected ->
            CallState.Active(state.callId, state.peer, state.isVideo, startedAtMs = nowMs) with listOf(
                CallEffect.StartTimer(TimerKey.HEARTBEAT, CallTimeouts.HEARTBEAT_MS),
            )
        CallEvent.IceFailed ->
            ended(state.callId, EndReason.NETWORK_LOST, 0L) with listOf(
                CallEffect.SendEnd(state.callId, EndReason.NETWORK_LOST),
            )
        CallEvent.HangUp ->
            CallState.Ending(state.callId, EndReason.LOCAL_HANGUP) with listOf(
                CallEffect.SendEnd(state.callId, EndReason.LOCAL_HANGUP),
            )
        is CallEvent.RemoteEnded ->
            if (event.callId != state.callId) state.noop()
            else ended(state.callId, EndReason.REMOTE_HANGUP, 0L).noEffects()
        is CallEvent.RemoteSignal -> passSignal(state, event)
        is CallEvent.StartOutgoing -> busyOrNoop(state, event.callId)
        is CallEvent.IncomingInvite -> busyOrNoop(state, event.callId)
        // Not meaningful (or pass-through) while connecting. No-op.
        CallEvent.Accept, CallEvent.Decline,
        CallEvent.ToggleMute, CallEvent.ToggleCamera, CallEvent.ToggleSpeaker, CallEvent.FlipCamera,
        is CallEvent.RemoteAccepted, is CallEvent.RemoteDeclined,
        CallEvent.IceDisconnected,
        CallEvent.InviteTimeout, CallEvent.ReconnectTimeout, CallEvent.HeartbeatTick,
        -> state.noop()
    }

    // ─── Active (media up) ─────────────────────────────────────────────────────────────────────────────

    private fun reduceActive(
        state: CallState.Active,
        event: CallEvent,
        nowMs: Long,
    ): Pair<CallState, List<CallEffect>> = when (event) {
        CallEvent.IceDisconnected ->
            CallState.Reconnecting(
                callId = state.callId,
                peer = state.peer,
                isVideo = state.isVideo,
                startedAtMs = state.startedAtMs,
                since = nowMs,
            ) with listOf(CallEffect.StartTimer(TimerKey.RECONNECT, CallTimeouts.RECONNECT_MS))
        CallEvent.HangUp ->
            CallState.Ending(state.callId, EndReason.LOCAL_HANGUP) with listOf(
                CallEffect.SendEnd(state.callId, EndReason.LOCAL_HANGUP),
                CallEffect.CancelTimer(TimerKey.HEARTBEAT),
            )
        is CallEvent.RemoteEnded ->
            if (event.callId != state.callId) state.noop()
            else ended(state.callId, EndReason.REMOTE_HANGUP, durationOf(state, nowMs)) with listOf(
                CallEffect.CancelTimer(TimerKey.HEARTBEAT),
            )
        CallEvent.IceFailed ->
            ended(state.callId, EndReason.NETWORK_LOST, durationOf(state, nowMs)) with listOf(
                CallEffect.SendEnd(state.callId, EndReason.NETWORK_LOST),
                CallEffect.CancelTimer(TimerKey.HEARTBEAT),
            )
        is CallEvent.RemoteSignal -> passSignal(state, event)
        is CallEvent.StartOutgoing -> busyOrNoop(state, event.callId)
        is CallEvent.IncomingInvite -> busyOrNoop(state, event.callId)
        // Control toggles + heartbeat tick are passed through with NO state change (local media-control
        // state + the billing heartbeat live in the UI/host layers, mirroring AND-298's InCallViewModel).
        CallEvent.ToggleMute, CallEvent.ToggleCamera, CallEvent.ToggleSpeaker, CallEvent.FlipCamera,
        CallEvent.HeartbeatTick,
        -> state.noop()
        // Not meaningful while active. No-op.
        CallEvent.Accept, CallEvent.Decline,
        is CallEvent.RemoteAccepted, is CallEvent.RemoteDeclined,
        CallEvent.IceConnected,
        CallEvent.InviteTimeout, CallEvent.ReconnectTimeout,
        -> state.noop()
    }

    // ─── Reconnecting (ICE dropped; recovering) ──────────────────────────────────────────────────────

    private fun reduceReconnecting(
        state: CallState.Reconnecting,
        event: CallEvent,
    ): Pair<CallState, List<CallEffect>> = when (event) {
        CallEvent.IceConnected ->
            // Recovered: KEEP the original startedAtMs so duration continues uninterrupted.
            CallState.Active(state.callId, state.peer, state.isVideo, startedAtMs = state.startedAtMs) with
                listOf(CallEffect.CancelTimer(TimerKey.RECONNECT))
        CallEvent.ReconnectTimeout, CallEvent.IceFailed ->
            ended(state.callId, EndReason.NETWORK_LOST, durationOf(state)) with listOf(
                CallEffect.SendEnd(state.callId, EndReason.NETWORK_LOST),
                CallEffect.CancelTimer(TimerKey.RECONNECT),
                CallEffect.CancelTimer(TimerKey.HEARTBEAT),
            )
        CallEvent.HangUp ->
            CallState.Ending(state.callId, EndReason.LOCAL_HANGUP) with listOf(
                CallEffect.SendEnd(state.callId, EndReason.LOCAL_HANGUP),
                CallEffect.CancelTimer(TimerKey.RECONNECT),
                CallEffect.CancelTimer(TimerKey.HEARTBEAT),
            )
        is CallEvent.RemoteEnded ->
            if (event.callId != state.callId) state.noop()
            else ended(state.callId, EndReason.REMOTE_HANGUP, durationOf(state)) with listOf(
                CallEffect.CancelTimer(TimerKey.RECONNECT),
                CallEffect.CancelTimer(TimerKey.HEARTBEAT),
            )
        is CallEvent.RemoteSignal -> passSignal(state, event)
        is CallEvent.StartOutgoing -> busyOrNoop(state, event.callId)
        is CallEvent.IncomingInvite -> busyOrNoop(state, event.callId)
        // Control toggles + heartbeat pass through. No state change.
        CallEvent.ToggleMute, CallEvent.ToggleCamera, CallEvent.ToggleSpeaker, CallEvent.FlipCamera,
        CallEvent.HeartbeatTick,
        -> state.noop()
        // Not meaningful while reconnecting. No-op.
        CallEvent.Accept, CallEvent.Decline,
        is CallEvent.RemoteAccepted, is CallEvent.RemoteDeclined,
        CallEvent.IceDisconnected,
        CallEvent.InviteTimeout,
        -> state.noop()
    }

    // ─── Ending (terminal teardown in flight) ─────────────────────────────────────────────────────────

    private fun reduceEnding(
        state: CallState.Ending,
        event: CallEvent,
    ): Pair<CallState, List<CallEffect>> = when (event) {
        // The teardown is already committed; resolve to Ended on any terminal-ish confirmation, ignore the
        // rest. Duration is unknown here (Ending carries only the reason) so it resolves to 0; the host
        // computes the authoritative durationMs at the point it emits SendEnd from Active/Reconnecting.
        is CallEvent.RemoteEnded, CallEvent.IceFailed, CallEvent.InviteTimeout, CallEvent.ReconnectTimeout ->
            ended(state.callId, state.reason, 0L).noEffects()
        // Everything else is ignored during teardown.
        is CallEvent.StartOutgoing, is CallEvent.IncomingInvite,
        CallEvent.Accept, CallEvent.Decline, CallEvent.HangUp,
        CallEvent.ToggleMute, CallEvent.ToggleCamera, CallEvent.ToggleSpeaker, CallEvent.FlipCamera,
        is CallEvent.RemoteAccepted, is CallEvent.RemoteDeclined, is CallEvent.RemoteSignal,
        CallEvent.IceConnected, CallEvent.IceDisconnected,
        CallEvent.HeartbeatTick,
        -> state.noop()
    }

    // ─── Ended (terminal) ─────────────────────────────────────────────────────────────────────────────

    private fun reduceEnded(
        state: CallState.Ended,
        event: CallEvent,
    ): Pair<CallState, List<CallEffect>> = when (event) {
        // A brand-new call may begin from a terminal state (the prior call is fully released). This lets a
        // single machine be reused without an explicit reset. All other events are no-ops on a dead call.
        is CallEvent.StartOutgoing ->
            CallState.Dialing(event.callId, event.peer, event.isVideo) with listOf(
                CallEffect.SendInvite(event.callId, event.peer, event.isVideo),
                CallEffect.StartTimer(TimerKey.INVITE, CallTimeouts.INVITE_MS),
                CallEffect.PlayRingback,
            )
        is CallEvent.IncomingInvite ->
            CallState.IncomingRinging(event.callId, event.peer, event.isVideo) with listOf(
                CallEffect.StartTimer(TimerKey.INVITE, CallTimeouts.RING_MS),
                CallEffect.PlayRingback,
            )
        CallEvent.Accept, CallEvent.Decline, CallEvent.HangUp,
        CallEvent.ToggleMute, CallEvent.ToggleCamera, CallEvent.ToggleSpeaker, CallEvent.FlipCamera,
        is CallEvent.RemoteAccepted, is CallEvent.RemoteDeclined, is CallEvent.RemoteEnded,
        is CallEvent.RemoteSignal,
        CallEvent.IceConnected, CallEvent.IceDisconnected, CallEvent.IceFailed,
        CallEvent.InviteTimeout, CallEvent.ReconnectTimeout, CallEvent.HeartbeatTick,
        -> state.noop()
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────────────────────────────

    private fun ended(callId: String?, reason: EndReason, durationMs: Long): CallState.Ended =
        CallState.Ended(callId, reason, durationMs)

    private fun CallState.noEffects(): Pair<CallState, List<CallEffect>> = this to emptyList()

    private fun durationOf(state: CallState.Active, nowMs: Long): Long =
        (nowMs - state.startedAtMs).coerceAtLeast(0L)

    // For Reconnecting we cannot recompute live talk-time without nowMs at the reducer call site; the
    // duration up to the disconnect is (since - startedAtMs). Reconnect ends use that frozen value.
    private fun durationOf(state: CallState.Reconnecting): Long =
        (state.since - state.startedAtMs).coerceAtLeast(0L)

    /** RemoteSignal forwards to the transport; never changes state. No-op if there is no call id. */
    private fun passSignal(
        state: CallState,
        event: CallEvent.RemoteSignal,
    ): Pair<CallState, List<CallEffect>> {
        val id = state.callId ?: return state.noop()
        return state with listOf(CallEffect.SendSignal(id, event.payload))
    }

    /**
     * Single-call invariant. A different callId -> [CallEffect.CallBusy] with no state change; the SAME
     * callId (duplicate delivery) -> a silent no-op.
     */
    private fun busyOrNoop(state: CallState, incomingCallId: String): Pair<CallState, List<CallEffect>> =
        if (incomingCallId == state.callId) state.noop() else state with listOf(CallEffect.CallBusy)
}
