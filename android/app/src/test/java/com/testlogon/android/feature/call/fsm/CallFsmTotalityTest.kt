package com.testlogon.android.feature.call.fsm

import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * AND-305 — proves [CallFsm.reduce] is TOTAL: firing EVERY [CallEvent] at EVERY representative [CallState]
 * never throws and always yields a defined (state, effects) pair. Combined with the explicit no-op
 * assertions in [CallFsmTest], this covers the full (state x event) matrix.
 */
class CallFsmTotalityTest {

    private val peer = PeerRef("u1", "c1", "Alex")

    private val states: List<CallState> = listOf(
        CallState.Idle,
        CallState.Dialing("c", peer, isVideo = false),
        CallState.IncomingRinging("c", peer, isVideo = true),
        CallState.Connecting("c", peer, isVideo = false),
        CallState.Active("c", peer, isVideo = false, startedAtMs = 0L),
        CallState.Reconnecting("c", peer, isVideo = false, startedAtMs = 0L, since = 100L),
        CallState.Ending("c", EndReason.LOCAL_HANGUP),
        CallState.Ended("c", EndReason.REMOTE_HANGUP, 0L),
        CallState.Ended(null, EndReason.ERROR, 0L),
    )

    private val events: List<CallEvent> = listOf(
        CallEvent.StartOutgoing("c", peer, isVideo = false),
        CallEvent.StartOutgoing("other", peer, isVideo = false),
        CallEvent.IncomingInvite("c", peer, isVideo = false),
        CallEvent.IncomingInvite("other", peer, isVideo = false),
        CallEvent.Accept,
        CallEvent.Decline,
        CallEvent.HangUp,
        CallEvent.ToggleMute,
        CallEvent.ToggleCamera,
        CallEvent.ToggleSpeaker,
        CallEvent.FlipCamera,
        CallEvent.RemoteAccepted("c"),
        CallEvent.RemoteAccepted("other"),
        CallEvent.RemoteDeclined("c"),
        CallEvent.RemoteEnded("c"),
        CallEvent.RemoteEnded("other"),
        CallEvent.RemoteSignal("payload"),
        CallEvent.IceConnected,
        CallEvent.IceDisconnected,
        CallEvent.IceFailed,
        CallEvent.InviteTimeout,
        CallEvent.ReconnectTimeout,
        CallEvent.HeartbeatTick,
    )

    @Test
    fun everyStateEventPair_isDefined_andNeverThrows() {
        for (state in states) {
            for (event in events) {
                val result = CallFsm.reduce(state, event, nowMs = 1_000L)
                assertNotNull("reduce($state, $event) must be defined", result)
                assertNotNull(result.first)
                assertNotNull(result.second)
            }
        }
    }
}
