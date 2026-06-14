package com.testlogon.android.feature.call.fsm

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-305 — the single-call invariant (pure reducer). A new StartOutgoing / IncomingInvite for a DIFFERENT
 * callId while a call occupies any non-terminal state -> state UNCHANGED + [CallEffect.CallBusy]. A repeat
 * for the SAME callId is a silent no-op (duplicate push delivery).
 */
class CallFsmBusyTest {

    private val peer = PeerRef("u1", "c1", "Alex")
    private val peer2 = PeerRef("u2", "c2", "Bo")

    private val nonTerminalStates: List<CallState> = listOf(
        CallState.Dialing("call-1", peer, isVideo = false),
        CallState.IncomingRinging("call-1", peer, isVideo = false),
        CallState.Connecting("call-1", peer, isVideo = false),
        CallState.Active("call-1", peer, isVideo = false, startedAtMs = 0L),
        CallState.Reconnecting("call-1", peer, isVideo = false, startedAtMs = 0L, since = 1L),
    )

    @Test
    fun secondStartOutgoing_duringActive_isBusy_stateUnchanged() {
        val active = CallState.Active("call-1", peer, isVideo = false, startedAtMs = 0L)
        val (next, effects) = CallFsm.reduce(
            active,
            CallEvent.StartOutgoing("call-2", peer2, isVideo = false),
            nowMs = 0L,
        )
        assertEquals(active, next)
        assertEquals(listOf(CallEffect.CallBusy), effects)
    }

    @Test
    fun secondCall_differentId_isBusy_inEveryNonTerminalState() {
        nonTerminalStates.forEach { state ->
            val (s1, e1) = CallFsm.reduce(state, CallEvent.StartOutgoing("call-2", peer2, false), 0L)
            assertEquals("busy keeps state for $state", state, s1)
            assertEquals("busy effect for $state", listOf(CallEffect.CallBusy), e1)

            val (s2, e2) = CallFsm.reduce(state, CallEvent.IncomingInvite("call-2", peer2, false), 0L)
            assertEquals("busy keeps state (incoming) for $state", state, s2)
            assertEquals("busy effect (incoming) for $state", listOf(CallEffect.CallBusy), e2)
        }
    }

    @Test
    fun duplicateInvite_sameId_isSilentNoOp() {
        val ringing = CallState.IncomingRinging("call-1", peer, isVideo = false)
        val (next, effects) = CallFsm.reduce(
            ringing,
            CallEvent.IncomingInvite("call-1", peer, isVideo = false),
            nowMs = 0L,
        )
        assertEquals(ringing, next)
        assertTrue(effects.isEmpty())
    }
}
