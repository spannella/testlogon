package com.testlogon.android.core.model.helpdesk

import org.junit.Assert.assertEquals
import org.junit.Test

/** AND-379 — TC-AND-379-01: the availability -> heartbeat `status` vocabulary mapping. */
class AvailabilityTest {

    @Test
    fun heartbeatStatus_mapsOnlineToAvailable() {
        assertEquals("available", Availability.ONLINE.heartbeatStatus())
    }

    @Test
    fun heartbeatStatus_mapsAwayToAway() {
        assertEquals("away", Availability.AWAY.heartbeatStatus())
    }

    @Test
    fun agentAvailabilityState_defaultsToAway() {
        assertEquals(Availability.AWAY, AgentAvailabilityState().availability)
    }
}
