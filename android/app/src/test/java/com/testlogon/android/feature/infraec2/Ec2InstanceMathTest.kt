package com.testlogon.android.feature.infraec2

import com.testlogon.android.data.infraec2.Ec2Action
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM unit tests for the PURE [Ec2InstanceMath] lifecycle-action logic (no Android types). Covers the
 * running/stopped/terminated predicates (case-insensitive + trimmed), the allowed-action set per status,
 * canPerform gating, and conservative handling of transient / unknown statuses.
 */
class Ec2InstanceMathTest {

    @Test
    fun predicates_areCaseInsensitiveAndTrimmed() {
        assertTrue(Ec2InstanceMath.isRunning("  RUNNING "))
        assertTrue(Ec2InstanceMath.isStopped("Stopped"))
        assertTrue(Ec2InstanceMath.isTerminated("TERMINATED"))
        assertFalse(Ec2InstanceMath.isRunning("stopped"))
    }

    @Test
    fun running_allowsStopRebootTerminateOnly() {
        val actions = Ec2InstanceMath.allowedActions("running")
        assertEquals(listOf(Ec2Action.STOP, Ec2Action.REBOOT, Ec2Action.TERMINATE), actions)
    }

    @Test
    fun stopped_allowsStartAndTerminate() {
        val actions = Ec2InstanceMath.allowedActions("stopped")
        assertEquals(listOf(Ec2Action.START, Ec2Action.TERMINATE), actions)
    }

    @Test
    fun terminated_allowsNothing() {
        assertTrue(Ec2InstanceMath.allowedActions("terminated").isEmpty())
        assertFalse(Ec2InstanceMath.isActionable("terminated"))
    }

    @Test
    fun transientStatus_offersStartButNoTerminate() {
        // pending/starting are neither running nor stopped -> only Start is offered (mirrors Screen).
        val pending = Ec2InstanceMath.allowedActions("pending")
        assertEquals(listOf(Ec2Action.START), pending)
        assertFalse(Ec2InstanceMath.canPerform("pending", Ec2Action.TERMINATE))
        assertFalse(Ec2InstanceMath.canPerform("pending", Ec2Action.REBOOT))
    }

    @Test
    fun unknownStatus_isConservative() {
        val unknown = Ec2InstanceMath.allowedActions("weird-state")
        assertEquals(listOf(Ec2Action.START), unknown)
        assertTrue(Ec2InstanceMath.isActionable("weird-state"))
    }

    @Test
    fun canPerform_gatesEachAction() {
        assertTrue(Ec2InstanceMath.canPerform("running", Ec2Action.STOP))
        assertTrue(Ec2InstanceMath.canPerform("running", Ec2Action.REBOOT))
        assertFalse(Ec2InstanceMath.canPerform("running", Ec2Action.START))
        assertTrue(Ec2InstanceMath.canPerform("stopped", Ec2Action.START))
        assertFalse(Ec2InstanceMath.canPerform("stopped", Ec2Action.REBOOT))
        assertFalse(Ec2InstanceMath.canPerform("terminated", Ec2Action.START))
    }

    @Test
    fun emptyStatus_isConservativeStartOnly() {
        assertEquals(listOf(Ec2Action.START), Ec2InstanceMath.allowedActions(""))
    }
}
