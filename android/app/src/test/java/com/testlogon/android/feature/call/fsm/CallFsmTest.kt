package com.testlogon.android.feature.call.fsm

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-305 — exhaustive table tests over the (state x event) matrix for the canonical [CallFsm.reduce].
 *
 * Pure JUnit (no coroutines): every DEFINED transition asserts next state + emitted effects; the no-op
 * cases assert state-unchanged + empty effects. Together with [CallFsmTotalityTest] (which fires EVERY
 * event at EVERY representative state and asserts reduce never throws) this proves reduce is total.
 */
class CallFsmTest {

    private val peer = PeerRef(userId = "u1", conversationId = "c1", displayName = "Alex")
    private val now = 1_000L

    private fun dialing(id: String = "call-1") = CallState.Dialing(id, peer, isVideo = false)
    private fun ringing(id: String = "call-1") = CallState.IncomingRinging(id, peer, isVideo = true)
    private fun connecting(id: String = "call-1") = CallState.Connecting(id, peer, isVideo = false)
    private fun active(id: String = "call-1", startedAt: Long = 500L) =
        CallState.Active(id, peer, isVideo = false, startedAtMs = startedAt)
    private fun reconnecting(id: String = "call-1", startedAt: Long = 500L, since: Long = 900L) =
        CallState.Reconnecting(id, peer, isVideo = false, startedAtMs = startedAt, since = since)

    private fun reduce(state: CallState, event: CallEvent, nowMs: Long = now) =
        CallFsm.reduce(state, event, nowMs)

    // ─── Idle ────────────────────────────────────────────────────────────────────────────────────────

    @Test
    fun idle_startOutgoing_goesDialing_withInviteAndTimerAndRingback() {
        val (next, effects) = reduce(
            CallState.Idle,
            CallEvent.StartOutgoing("call-1", peer, isVideo = true),
        )
        assertEquals(CallState.Dialing("call-1", peer, isVideo = true), next)
        assertEquals(
            listOf(
                CallEffect.SendInvite("call-1", peer, isVideo = true),
                CallEffect.StartTimer(TimerKey.INVITE, CallTimeouts.INVITE_MS),
                CallEffect.PlayRingback,
            ),
            effects,
        )
    }

    @Test
    fun idle_incomingInvite_goesRinging_withTimerAndRingback() {
        val (next, effects) = reduce(
            CallState.Idle,
            CallEvent.IncomingInvite("call-9", peer, isVideo = false),
        )
        assertEquals(CallState.IncomingRinging("call-9", peer, isVideo = false), next)
        assertEquals(
            listOf(
                CallEffect.StartTimer(TimerKey.INVITE, CallTimeouts.RING_MS),
                CallEffect.PlayRingback,
            ),
            effects,
        )
    }

    @Test
    fun idle_unrelatedEvents_areNoOp() {
        listOf(
            CallEvent.Accept, CallEvent.Decline, CallEvent.HangUp, CallEvent.ToggleMute,
            CallEvent.IceConnected, CallEvent.InviteTimeout, CallEvent.HeartbeatTick,
            CallEvent.RemoteAccepted("x"), CallEvent.RemoteEnded("x"),
        ).forEach { event ->
            val (next, effects) = reduce(CallState.Idle, event)
            assertEquals("no-op state for $event", CallState.Idle, next)
            assertTrue("no-op effects for $event", effects.isEmpty())
        }
    }

    // ─── Dialing ─────────────────────────────────────────────────────────────────────────────────────

    @Test
    fun dialing_remoteAccepted_goesConnecting_cancelInviteStopAudio() {
        val (next, effects) = reduce(dialing(), CallEvent.RemoteAccepted("call-1"))
        assertEquals(connecting(), next)
        assertEquals(
            listOf(CallEffect.CancelTimer(TimerKey.INVITE), CallEffect.StopAudio),
            effects,
        )
    }

    @Test
    fun dialing_remoteAccepted_wrongId_isNoOp() {
        val (next, effects) = reduce(dialing(), CallEvent.RemoteAccepted("other"))
        assertEquals(dialing(), next)
        assertTrue(effects.isEmpty())
    }

    @Test
    fun dialing_remoteDeclined_endsDeclined() {
        val (next, effects) = reduce(dialing(), CallEvent.RemoteDeclined("call-1"))
        assertEquals(CallState.Ended("call-1", EndReason.DECLINED, 0L), next)
        assertTrue(effects.contains(CallEffect.CancelTimer(TimerKey.INVITE)))
        assertTrue(effects.contains(CallEffect.StopAudio))
    }

    @Test
    fun dialing_remoteEnded_endsRemoteHangup() {
        val (next, _) = reduce(dialing(), CallEvent.RemoteEnded("call-1"))
        assertEquals(CallState.Ended("call-1", EndReason.REMOTE_HANGUP, 0L), next)
    }

    @Test
    fun dialing_hangUp_goesEnding_sendEnd() {
        val (next, effects) = reduce(dialing(), CallEvent.HangUp)
        assertEquals(CallState.Ending("call-1", EndReason.LOCAL_HANGUP), next)
        assertTrue(effects.contains(CallEffect.SendEnd("call-1", EndReason.LOCAL_HANGUP)))
        assertTrue(effects.contains(CallEffect.CancelTimer(TimerKey.INVITE)))
    }

    @Test
    fun dialing_inviteTimeout_endsTimedOut_sendTimeout() {
        val (next, effects) = reduce(dialing(), CallEvent.InviteTimeout)
        assertEquals(CallState.Ended("call-1", EndReason.TIMED_OUT, 0L), next)
        assertTrue(effects.contains(CallEffect.SendTimeout("call-1")))
    }

    @Test
    fun dialing_remoteSignal_passesThrough_noStateChange() {
        val (next, effects) = reduce(dialing(), CallEvent.RemoteSignal("sdp"))
        assertEquals(dialing(), next)
        assertEquals(listOf(CallEffect.SendSignal("call-1", "sdp")), effects)
    }

    @Test
    fun dialing_controlTogglesAndOddEvents_areNoOp() {
        listOf(
            CallEvent.Accept, CallEvent.Decline, CallEvent.ToggleMute, CallEvent.ToggleCamera,
            CallEvent.IceConnected, CallEvent.IceDisconnected, CallEvent.IceFailed,
            CallEvent.ReconnectTimeout, CallEvent.HeartbeatTick,
        ).forEach { event ->
            val (next, effects) = reduce(dialing(), event)
            assertEquals("no-op for $event", dialing(), next)
            assertTrue("empty for $event", effects.isEmpty())
        }
    }

    // ─── IncomingRinging ─────────────────────────────────────────────────────────────────────────────

    @Test
    fun ringing_accept_goesConnecting_sendAccept() {
        val (next, effects) = reduce(ringing(), CallEvent.Accept)
        assertEquals(CallState.Connecting("call-1", peer, isVideo = true), next)
        assertTrue(effects.contains(CallEffect.SendAccept("call-1")))
        assertTrue(effects.contains(CallEffect.CancelTimer(TimerKey.INVITE)))
        assertTrue(effects.contains(CallEffect.StopAudio))
    }

    @Test
    fun ringing_decline_endsDeclined_sendDecline() {
        val (next, effects) = reduce(ringing(), CallEvent.Decline)
        assertEquals(CallState.Ended("call-1", EndReason.DECLINED, 0L), next)
        assertTrue(effects.contains(CallEffect.SendDecline("call-1")))
    }

    @Test
    fun ringing_hangUp_isTreatedAsDecline() {
        val (next, effects) = reduce(ringing(), CallEvent.HangUp)
        assertEquals(CallState.Ended("call-1", EndReason.DECLINED, 0L), next)
        assertTrue(effects.contains(CallEffect.SendDecline("call-1")))
    }

    @Test
    fun ringing_inviteTimeout_endsMissed() {
        val (next, effects) = reduce(ringing(), CallEvent.InviteTimeout)
        assertEquals(CallState.Ended("call-1", EndReason.MISSED, 0L), next)
        assertTrue(effects.contains(CallEffect.SendTimeout("call-1")))
    }

    @Test
    fun ringing_remoteEnded_endsRemoteHangup() {
        val (next, _) = reduce(ringing(), CallEvent.RemoteEnded("call-1"))
        assertEquals(CallState.Ended("call-1", EndReason.REMOTE_HANGUP, 0L), next)
    }

    // ─── Connecting ───────────────────────────────────────────────────────────────────────────────────

    @Test
    fun connecting_iceConnected_goesActive_atNow_withHeartbeatTimer() {
        val (next, effects) = reduce(connecting(), CallEvent.IceConnected, nowMs = 5_000L)
        assertEquals(CallState.Active("call-1", peer, isVideo = false, startedAtMs = 5_000L), next)
        assertEquals(listOf(CallEffect.StartTimer(TimerKey.HEARTBEAT, CallTimeouts.HEARTBEAT_MS)), effects)
    }

    @Test
    fun connecting_iceFailed_endsNetworkLost_sendEnd() {
        val (next, effects) = reduce(connecting(), CallEvent.IceFailed)
        assertEquals(CallState.Ended("call-1", EndReason.NETWORK_LOST, 0L), next)
        assertTrue(effects.contains(CallEffect.SendEnd("call-1", EndReason.NETWORK_LOST)))
    }

    @Test
    fun connecting_hangUp_goesEnding() {
        val (next, effects) = reduce(connecting(), CallEvent.HangUp)
        assertEquals(CallState.Ending("call-1", EndReason.LOCAL_HANGUP), next)
        assertTrue(effects.contains(CallEffect.SendEnd("call-1", EndReason.LOCAL_HANGUP)))
    }

    @Test
    fun connecting_remoteEnded_endsRemoteHangup_noEffects() {
        val (next, effects) = reduce(connecting(), CallEvent.RemoteEnded("call-1"))
        assertEquals(CallState.Ended("call-1", EndReason.REMOTE_HANGUP, 0L), next)
        assertTrue(effects.isEmpty())
    }

    // ─── Active ───────────────────────────────────────────────────────────────────────────────────────

    @Test
    fun active_iceDisconnected_goesReconnecting_withReconnectTimer_keepsStartedAt() {
        val (next, effects) = reduce(active(startedAt = 500L), CallEvent.IceDisconnected, nowMs = 4_000L)
        assertEquals(
            CallState.Reconnecting("call-1", peer, isVideo = false, startedAtMs = 500L, since = 4_000L),
            next,
        )
        assertEquals(listOf(CallEffect.StartTimer(TimerKey.RECONNECT, CallTimeouts.RECONNECT_MS)), effects)
    }

    @Test
    fun active_hangUp_goesEnding_cancelHeartbeat() {
        val (next, effects) = reduce(active(), CallEvent.HangUp)
        assertEquals(CallState.Ending("call-1", EndReason.LOCAL_HANGUP), next)
        assertTrue(effects.contains(CallEffect.SendEnd("call-1", EndReason.LOCAL_HANGUP)))
        assertTrue(effects.contains(CallEffect.CancelTimer(TimerKey.HEARTBEAT)))
    }

    @Test
    fun active_remoteEnded_endsRemoteHangup_withDuration() {
        val (next, _) = reduce(active(startedAt = 1_000L), CallEvent.RemoteEnded("call-1"), nowMs = 6_000L)
        assertEquals(CallState.Ended("call-1", EndReason.REMOTE_HANGUP, 5_000L), next)
    }

    @Test
    fun active_iceFailed_endsNetworkLost_withDuration() {
        val (next, effects) = reduce(active(startedAt = 1_000L), CallEvent.IceFailed, nowMs = 3_000L)
        assertEquals(CallState.Ended("call-1", EndReason.NETWORK_LOST, 2_000L), next)
        assertTrue(effects.contains(CallEffect.SendEnd("call-1", EndReason.NETWORK_LOST)))
    }

    @Test
    fun active_controlToggles_areNoOp() {
        listOf(
            CallEvent.ToggleMute, CallEvent.ToggleCamera, CallEvent.ToggleSpeaker,
            CallEvent.FlipCamera, CallEvent.HeartbeatTick,
        ).forEach { event ->
            val (next, effects) = reduce(active(), event)
            assertEquals("toggle no-op for $event", active(), next)
            assertTrue("toggle empty for $event", effects.isEmpty())
        }
    }

    // ─── Reconnecting ─────────────────────────────────────────────────────────────────────────────────

    @Test
    fun reconnecting_iceConnected_resumesActive_keepingOriginalStartedAt() {
        val (next, effects) = reduce(
            reconnecting(startedAt = 500L, since = 900L),
            CallEvent.IceConnected,
            nowMs = 9_000L,
        )
        assertEquals(CallState.Active("call-1", peer, isVideo = false, startedAtMs = 500L), next)
        assertEquals(listOf(CallEffect.CancelTimer(TimerKey.RECONNECT)), effects)
    }

    @Test
    fun reconnecting_reconnectTimeout_endsNetworkLost_withFrozenDuration() {
        val (next, effects) = reduce(
            reconnecting(startedAt = 500L, since = 2_500L),
            CallEvent.ReconnectTimeout,
        )
        assertEquals(CallState.Ended("call-1", EndReason.NETWORK_LOST, 2_000L), next)
        assertTrue(effects.contains(CallEffect.SendEnd("call-1", EndReason.NETWORK_LOST)))
    }

    @Test
    fun reconnecting_iceFailed_endsNetworkLost() {
        val (next, _) = reduce(reconnecting(), CallEvent.IceFailed)
        assertTrue(next is CallState.Ended && (next as CallState.Ended).reason == EndReason.NETWORK_LOST)
    }

    @Test
    fun reconnecting_hangUp_endsLocalHangup() {
        val (next, effects) = reduce(reconnecting(), CallEvent.HangUp)
        assertEquals(CallState.Ending("call-1", EndReason.LOCAL_HANGUP), next)
        assertTrue(effects.contains(CallEffect.SendEnd("call-1", EndReason.LOCAL_HANGUP)))
    }

    @Test
    fun reconnecting_remoteEnded_endsRemoteHangup() {
        val (next, _) = reduce(reconnecting(startedAt = 0L, since = 4_000L), CallEvent.RemoteEnded("call-1"))
        assertEquals(CallState.Ended("call-1", EndReason.REMOTE_HANGUP, 4_000L), next)
    }

    // ─── Ending / Ended ───────────────────────────────────────────────────────────────────────────────

    @Test
    fun ending_resolvesToEnded_onTerminalConfirmations() {
        val ending = CallState.Ending("call-1", EndReason.LOCAL_HANGUP)
        listOf(
            CallEvent.RemoteEnded("call-1"), CallEvent.IceFailed,
            CallEvent.InviteTimeout, CallEvent.ReconnectTimeout,
        ).forEach { event ->
            val (next, effects) = reduce(ending, event)
            assertEquals("ending->ended for $event", CallState.Ended("call-1", EndReason.LOCAL_HANGUP, 0L), next)
            assertTrue("no effects for $event", effects.isEmpty())
        }
    }

    @Test
    fun ending_ignoresOtherEvents() {
        val ending = CallState.Ending("call-1", EndReason.LOCAL_HANGUP)
        listOf(CallEvent.Accept, CallEvent.HangUp, CallEvent.ToggleMute, CallEvent.IceConnected).forEach {
            val (next, effects) = reduce(ending, it)
            assertEquals(ending, next)
            assertTrue(effects.isEmpty())
        }
    }

    @Test
    fun ended_startOutgoing_beginsNewCall() {
        val ended = CallState.Ended("old", EndReason.REMOTE_HANGUP, 1_000L)
        val (next, effects) = reduce(ended, CallEvent.StartOutgoing("new", peer, isVideo = false))
        assertEquals(CallState.Dialing("new", peer, isVideo = false), next)
        assertTrue(effects.contains(CallEffect.SendInvite("new", peer, isVideo = false)))
    }

    @Test
    fun ended_incomingInvite_beginsNewRinging() {
        val ended = CallState.Ended("old", EndReason.MISSED, 0L)
        val (next, _) = reduce(ended, CallEvent.IncomingInvite("new", peer, isVideo = false))
        assertEquals(CallState.IncomingRinging("new", peer, isVideo = false), next)
    }

    @Test
    fun ended_otherEvents_areNoOp() {
        val ended = CallState.Ended("old", EndReason.MISSED, 0L)
        listOf(CallEvent.Accept, CallEvent.HangUp, CallEvent.IceConnected, CallEvent.HeartbeatTick).forEach {
            val (next, effects) = reduce(ended, it)
            assertEquals(ended, next)
            assertTrue(effects.isEmpty())
        }
    }
}
