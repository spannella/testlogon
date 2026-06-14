package com.testlogon.android.feature.call.fsm

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-305 — timeout/reconnect transitions exercised PURELY through the reducer (no coroutines). The
 * TIME-DRIVEN firing of these timers by the host is covered in [CallStateMachineHostTest] with a fake
 * scheduler — never with advanceUntilIdle on an infinite flow.
 */
class CallFsmTimeoutTest {

    private val peer = PeerRef("u1", "c1", "Alex")

    @Test
    fun dialing_inviteTimeout_endsTimedOut_withSendTimeout() {
        val (next, effects) = CallFsm.reduce(
            CallState.Dialing("c1", peer, isVideo = false),
            CallEvent.InviteTimeout,
            nowMs = 0L,
        )
        assertEquals(CallState.Ended("c1", EndReason.TIMED_OUT, 0L), next)
        assertTrue(effects.contains(CallEffect.SendTimeout("c1")))
    }

    @Test
    fun incomingRinging_inviteTimeout_endsMissed() {
        val (next, effects) = CallFsm.reduce(
            CallState.IncomingRinging("c1", peer, isVideo = false),
            CallEvent.InviteTimeout,
            nowMs = 0L,
        )
        assertEquals(CallState.Ended("c1", EndReason.MISSED, 0L), next)
        assertTrue(effects.contains(CallEffect.SendTimeout("c1")))
    }

    @Test
    fun active_iceDisconnected_goesReconnecting_withReconnectTimer() {
        val (next, effects) = CallFsm.reduce(
            CallState.Active("c1", peer, isVideo = false, startedAtMs = 100L),
            CallEvent.IceDisconnected,
            nowMs = 1_100L,
        )
        assertEquals(
            CallState.Reconnecting("c1", peer, isVideo = false, startedAtMs = 100L, since = 1_100L),
            next,
        )
        assertEquals(listOf(CallEffect.StartTimer(TimerKey.RECONNECT, CallTimeouts.RECONNECT_MS)), effects)
    }

    @Test
    fun reconnecting_reconnectTimeout_endsNetworkLost() {
        val (next, effects) = CallFsm.reduce(
            CallState.Reconnecting("c1", peer, isVideo = false, startedAtMs = 100L, since = 1_100L),
            CallEvent.ReconnectTimeout,
            nowMs = 9_999L,
        )
        assertEquals(CallState.Ended("c1", EndReason.NETWORK_LOST, 1_000L), next)
        assertTrue(effects.contains(CallEffect.SendEnd("c1", EndReason.NETWORK_LOST)))
    }
}
