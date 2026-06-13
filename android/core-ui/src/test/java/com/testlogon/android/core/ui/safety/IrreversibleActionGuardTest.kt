package com.testlogon.android.core.ui.safety

import com.testlogon.android.core.ui.i18n.UiText
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-388 - exhaustive (100% line) unit coverage of [IrreversibleActionGuard] / [GuardPhase].
 *
 * Proves the destructive-action invariants FR-1..FR-4 (spec sec.11, AC-1/AC-4): request only opens
 * Confirming; confirm gates on acknowledgement; confirm is a no-op from Idle and re-entrant from
 * Submitting; cancel only unwinds Confirming; terminal transitions and reset behave. No Android,
 * no coroutines runtime - the guard owns no I/O.
 */
class IrreversibleActionGuardTest {

    private data class Action(val id: String)

    // TC-AND-388-01 - request opens Confirming; confirm submits; confirm from Idle is null (FR-1).
    @Test
    fun request_opensConfirming_andConfirmSubmits() {
        val guard = IrreversibleActionGuard<Action>()
        assertEquals(GuardPhase.Idle, guard.phase.value)

        // confirm() from Idle does nothing and returns null.
        assertNull(guard.confirm())
        assertEquals(GuardPhase.Idle, guard.phase.value)

        val action = Action("a")
        guard.request(action)
        assertEquals(GuardPhase.Confirming(action), guard.phase.value)

        // request never submits on its own.
        assertTrue(guard.phase.value is GuardPhase.Confirming)

        val confirmed = guard.confirm()
        assertEquals(action, confirmed)
        assertEquals(GuardPhase.Submitting(action), guard.phase.value)
    }

    // TC-AND-388-02 - acknowledgement gating (FR-2).
    @Test
    fun confirm_requiresAcknowledgement_whenConfigured() {
        val guard = IrreversibleActionGuard<Action>(requiresAcknowledgement = true)
        val action = Action("dmca")
        guard.request(action)

        // Without ack, confirm is rejected and the phase stays Confirming(acknowledged=false).
        assertNull(guard.confirm())
        assertEquals(GuardPhase.Confirming(action, acknowledged = false), guard.phase.value)

        guard.setAcknowledged(true)
        assertEquals(GuardPhase.Confirming(action, acknowledged = true), guard.phase.value)

        // With ack, confirm succeeds.
        assertEquals(action, guard.confirm())
        assertEquals(GuardPhase.Submitting(action), guard.phase.value)
    }

    // setAcknowledged is a no-op outside Confirming (covers the early-return branch).
    @Test
    fun setAcknowledged_isNoOp_outsideConfirming() {
        val guard = IrreversibleActionGuard<Action>(requiresAcknowledgement = true)

        // From Idle.
        guard.setAcknowledged(true)
        assertEquals(GuardPhase.Idle, guard.phase.value)

        // From Submitting.
        guard.request(Action("a"))
        guard.setAcknowledged(true)
        guard.confirm()
        assertTrue(guard.phase.value is GuardPhase.Submitting)
        guard.setAcknowledged(false)
        assertTrue(guard.phase.value is GuardPhase.Submitting)
    }

    // TC-AND-388-03 - re-entrancy + cancel semantics (FR-3, FR-4).
    @Test
    fun confirm_isReentrancyGuarded_andCancelOnlyUnwindsConfirming() {
        val guard = IrreversibleActionGuard<Action>()
        val action = Action("report")
        guard.request(action)
        assertEquals(action, guard.confirm())
        assertEquals(GuardPhase.Submitting(action), guard.phase.value)

        // Second confirm while Submitting is the duplicate-submission guard: null, phase unchanged.
        assertNull(guard.confirm())
        assertEquals(GuardPhase.Submitting(action), guard.phase.value)

        // cancel() from Submitting is a no-op.
        guard.cancel()
        assertEquals(GuardPhase.Submitting(action), guard.phase.value)
    }

    @Test
    fun cancel_fromConfirming_returnsToIdle_andIsNoOpFromIdle() {
        val guard = IrreversibleActionGuard<Action>()

        // No-op from Idle.
        guard.cancel()
        assertEquals(GuardPhase.Idle, guard.phase.value)

        guard.request(Action("a"))
        assertTrue(guard.phase.value is GuardPhase.Confirming)
        guard.cancel()
        assertEquals(GuardPhase.Idle, guard.phase.value)
    }

    @Test
    fun terminalTransitions_andReset() {
        val guard = IrreversibleActionGuard<Action>()
        guard.request(Action("a"))
        guard.confirm()

        guard.onSuccess()
        assertEquals(GuardPhase.Submitted, guard.phase.value)

        guard.reset()
        assertEquals(GuardPhase.Idle, guard.phase.value)

        guard.request(Action("b"))
        guard.confirm()
        val error = UiText.Raw("boom")
        guard.onFailure(error)
        assertEquals(GuardPhase.Failed(error), guard.phase.value)

        // reset() from a terminal phase returns to Idle.
        guard.reset()
        assertEquals(GuardPhase.Idle, guard.phase.value)
    }
}
