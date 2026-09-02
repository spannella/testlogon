package com.testlogon.android.feature.agents.orchestrator.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AGENT-ORCHESTRATOR (web-parity) - JVM unit tests for the PURE loop-lifecycle logic in [OrchestratorMath].
 * Covers the action-availability guards (mirroring the backend transition rules), optimistic projection, and
 * the heartbeat-age / staleness helpers.
 */
class OrchestratorMathTest {

    private fun status(
        state: AgentLoopState = AgentLoopState.IDLE,
        loopRunning: Boolean = false,
        currentTicketId: String = "",
        heartbeatAt: Long = 0,
        ticketsCompleted: Int = 0,
    ) = AgentStatus(
        workerId = "w1",
        state = state,
        currentTicketId = currentTicketId,
        currentTicketTitle = if (currentTicketId.isNotBlank()) "Title" else "",
        ticketsCompleted = ticketsCompleted,
        ticketsFailed = 0,
        heartbeatAt = heartbeatAt,
        lastActivityAt = 0,
        ticketFilter = TicketFilter(),
        loopRunning = loopRunning,
    )

    // ---- state parsing ----

    @Test
    fun stateFrom_mapsKnownWireValues() {
        assertEquals(AgentLoopState.WORKING, AgentLoopState.from("working"))
        assertEquals(AgentLoopState.PAUSED, AgentLoopState.from("PAUSED"))
        assertEquals(AgentLoopState.STOPPED, AgentLoopState.from(" stopped "))
    }

    @Test
    fun stateFrom_unknownOrNull_isUnknown() {
        assertEquals(AgentLoopState.UNKNOWN, AgentLoopState.from("frobnicating"))
        assertEquals(AgentLoopState.UNKNOWN, AgentLoopState.from(null))
        assertEquals(AgentLoopState.UNKNOWN, AgentLoopState.from(""))
    }

    // ---- action availability ----

    @Test
    fun idleStopped_offersStart_notPauseResume() {
        val actions = OrchestratorMath.availableActions(status(state = AgentLoopState.IDLE, loopRunning = false))
        assertTrue(LoopAction.START in actions)
        assertFalse(LoopAction.PAUSE in actions)
        assertFalse(LoopAction.RESUME in actions)
    }

    @Test
    fun working_offersPauseAndStop_notStart() {
        val actions = OrchestratorMath.availableActions(status(state = AgentLoopState.WORKING, loopRunning = true))
        assertTrue(LoopAction.PAUSE in actions)
        assertTrue(LoopAction.STOP in actions)
        assertFalse(LoopAction.START in actions)
    }

    @Test
    fun paused_offersResumeAndStop_notPause() {
        val actions = OrchestratorMath.availableActions(status(state = AgentLoopState.PAUSED, loopRunning = true))
        assertTrue(LoopAction.RESUME in actions)
        assertTrue(LoopAction.STOP in actions)
        assertFalse(LoopAction.PAUSE in actions)
        assertFalse(LoopAction.START in actions)
    }

    @Test
    fun idleButLoopRunning_offersPauseNotStart() {
        // A worker can report state=idle while the loop is running (between tickets) -> no double-start.
        val actions = OrchestratorMath.availableActions(status(state = AgentLoopState.IDLE, loopRunning = true))
        assertFalse(LoopAction.START in actions)
        assertTrue(LoopAction.PAUSE in actions)
    }

    @Test
    fun noActiveTicket_offersClaim_notCompleteOrRelease() {
        val actions = OrchestratorMath.availableActions(status(currentTicketId = ""))
        assertTrue(LoopAction.CLAIM in actions)
        assertFalse(LoopAction.COMPLETE in actions)
        assertFalse(LoopAction.RELEASE in actions)
    }

    @Test
    fun activeTicket_offersCompleteAndRelease_notClaim() {
        val actions = OrchestratorMath.availableActions(
            status(state = AgentLoopState.WORKING, loopRunning = true, currentTicketId = "t7"),
        )
        assertTrue(LoopAction.COMPLETE in actions)
        assertTrue(LoopAction.RELEASE in actions)
        assertFalse(LoopAction.CLAIM in actions)
    }

    @Test
    fun heartbeat_alwaysAvailable() {
        assertTrue(LoopAction.HEARTBEAT in OrchestratorMath.availableActions(status(state = AgentLoopState.STOPPED)))
        assertTrue(LoopAction.HEARTBEAT in OrchestratorMath.availableActions(status(state = AgentLoopState.WORKING, loopRunning = true)))
    }

    @Test
    fun convenienceGuards_matchAvailableActions() {
        val s = status(state = AgentLoopState.PAUSED, loopRunning = true, currentTicketId = "t1")
        assertTrue(OrchestratorMath.canResume(s))
        assertTrue(OrchestratorMath.canStop(s))
        assertTrue(OrchestratorMath.canComplete(s))
        assertFalse(OrchestratorMath.canStart(s))
        assertFalse(OrchestratorMath.canClaim(s))
    }

    // ---- projection ----

    @Test
    fun projectStart_setsWorkingAndRunning() {
        val projected = OrchestratorMath.project(status(), LoopAction.START)
        assertEquals(AgentLoopState.WORKING, projected.state)
        assertTrue(projected.loopRunning)
    }

    @Test
    fun projectStop_setsStoppedAndNotRunning() {
        val projected = OrchestratorMath.project(status(state = AgentLoopState.WORKING, loopRunning = true), LoopAction.STOP)
        assertEquals(AgentLoopState.STOPPED, projected.state)
        assertFalse(projected.loopRunning)
    }

    @Test
    fun projectClaim_seedsTicketId() {
        val projected = OrchestratorMath.project(status(), LoopAction.CLAIM, claimedTicketId = "t99")
        assertEquals("t99", projected.currentTicketId)
    }

    @Test
    fun projectComplete_clearsTicketAndIncrementsCount() {
        val s = status(state = AgentLoopState.WORKING, loopRunning = true, currentTicketId = "t1", ticketsCompleted = 3)
        val projected = OrchestratorMath.project(s, LoopAction.COMPLETE)
        assertEquals("", projected.currentTicketId)
        assertEquals(4, projected.ticketsCompleted)
        assertEquals(AgentLoopState.IDLE, projected.state)
    }

    @Test
    fun projectRelease_clearsTicket_keepsCount() {
        val s = status(state = AgentLoopState.WORKING, loopRunning = true, currentTicketId = "t1", ticketsCompleted = 3)
        val projected = OrchestratorMath.project(s, LoopAction.RELEASE)
        assertEquals("", projected.currentTicketId)
        assertEquals(3, projected.ticketsCompleted)
    }

    @Test
    fun projectHeartbeat_isIdentity() {
        val s = status(state = AgentLoopState.WORKING, loopRunning = true, currentTicketId = "t1")
        assertEquals(s, OrchestratorMath.project(s, LoopAction.HEARTBEAT))
    }

    // ---- heartbeat helpers ----

    @Test
    fun heartbeatAge_neverBeaten_isNull() {
        assertNull(OrchestratorMath.heartbeatAgeSeconds(status(heartbeatAt = 0), nowSeconds = 1000))
    }

    @Test
    fun heartbeatAge_computesPositiveAge() {
        assertEquals(300L, OrchestratorMath.heartbeatAgeSeconds(status(heartbeatAt = 700), nowSeconds = 1000))
    }

    @Test
    fun heartbeatAge_clockBehind_isNull() {
        assertNull(OrchestratorMath.heartbeatAgeSeconds(status(heartbeatAt = 2000), nowSeconds = 1000))
    }

    @Test
    fun isStale_runningAndOld_isTrue() {
        val s = status(state = AgentLoopState.WORKING, loopRunning = true, heartbeatAt = 100)
        assertTrue(OrchestratorMath.isHeartbeatStale(s, nowSeconds = 1000, staleThresholdSeconds = 60))
    }

    @Test
    fun isStale_runningButFresh_isFalse() {
        val s = status(state = AgentLoopState.WORKING, loopRunning = true, heartbeatAt = 990)
        assertFalse(OrchestratorMath.isHeartbeatStale(s, nowSeconds = 1000, staleThresholdSeconds = 60))
    }

    @Test
    fun isStale_notRunning_isFalse() {
        val s = status(state = AgentLoopState.STOPPED, loopRunning = false, heartbeatAt = 1)
        assertFalse(OrchestratorMath.isHeartbeatStale(s, nowSeconds = 100000, staleThresholdSeconds = 60))
    }

    @Test
    fun summaryLine_reflectsStateRunningAndTicket() {
        val s = status(state = AgentLoopState.WORKING, loopRunning = true, currentTicketId = "t1")
        val line = OrchestratorMath.summaryLine(s)
        assertTrue(line.contains("Working"))
        assertTrue(line.contains("loop running"))
        assertTrue(line.contains("Title"))
    }

    @Test
    fun summaryLine_noTicket_saysNoActiveTicket() {
        val line = OrchestratorMath.summaryLine(status(state = AgentLoopState.IDLE, loopRunning = false))
        assertTrue(line.contains("no active ticket"))
        assertTrue(line.contains("loop stopped"))
    }
}
