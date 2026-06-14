package com.testlogon.android.feature.messaging.helpdesk

import com.testlogon.android.core.model.helpdesk.Availability
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test

/** AND-379 — TC-AND-379-04: the claim-eligibility gate returns Allowed iff ONLINE. */
class HelpdeskClaimGateTest {

    @Test
    fun check_whenAway_returnsBlockedAway() = runBlocking {
        val gate = HelpdeskClaimGate(FakeAvailabilityRepository(Availability.AWAY))
        assertEquals(ClaimGateResult.BlockedAway, gate.check())
    }

    @Test
    fun check_whenOnline_returnsAllowed() = runBlocking {
        val gate = HelpdeskClaimGate(FakeAvailabilityRepository(Availability.ONLINE))
        assertEquals(ClaimGateResult.Allowed, gate.check())
    }
}
