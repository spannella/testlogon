package com.testlogon.android.feature.custody

import com.testlogon.android.feature.custody.CustodyProviderFormat.ApprovalStatus
import com.testlogon.android.feature.custody.CustodyProviderFormat.ProviderKind
import com.testlogon.android.feature.custody.CustodyProviderFormat.ProviderStatus
import com.testlogon.android.feature.custody.CustodyProviderFormat.Severity
import com.testlogon.android.feature.custody.CustodyProviderFormat.StepState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [CustodyProviderFormat] -- the pure display/decision logic behind the external
 * custody-provider surface (status badge, kind label, attestation label, and the withdrawal-approval
 * stepper). No Android, Hilt or network types are touched.
 */
class CustodyProviderFormatTest {

    // ---- status badge ----

    @Test
    fun statusBadge_mapsEachKnownStatus() {
        assertEquals(Severity.GOOD, CustodyProviderFormat.statusBadge(ProviderStatus.HEALTHY).severity)
        assertEquals(Severity.WARN, CustodyProviderFormat.statusBadge(ProviderStatus.DEGRADED).severity)
        assertEquals(Severity.BAD, CustodyProviderFormat.statusBadge(ProviderStatus.DOWN).severity)
        assertEquals(Severity.NEUTRAL, CustodyProviderFormat.statusBadge(ProviderStatus.NOT_CONNECTED).severity)
        assertEquals("Healthy", CustodyProviderFormat.statusBadge(ProviderStatus.HEALTHY).label)
    }

    @Test
    fun statusFrom_isCaseInsensitive_andFallsBackToUnknown() {
        assertEquals(ProviderStatus.HEALTHY, ProviderStatus.from("HEALTHY"))
        assertEquals(ProviderStatus.DEGRADED, ProviderStatus.from(" degraded "))
        assertEquals(ProviderStatus.UNKNOWN, ProviderStatus.from("gibberish"))
        assertEquals(ProviderStatus.UNKNOWN, ProviderStatus.from(null))
    }

    @Test
    fun statusBadge_fromWireString_resolvesAndDefaults() {
        assertEquals("Down", CustodyProviderFormat.statusBadge("down").label)
        assertEquals(Severity.NEUTRAL, CustodyProviderFormat.statusBadge("???").severity)
    }

    // ---- kind ----

    @Test
    fun kindLabel_mapsKnownKinds() {
        assertEquals("Internal gateway", CustodyProviderFormat.kindLabel(ProviderKind.INTERNAL))
        assertEquals("Fireblocks", CustodyProviderFormat.kindLabel(ProviderKind.FIREBLOCKS))
        assertEquals("BitGo", CustodyProviderFormat.kindLabel(ProviderKind.BITGO))
        assertEquals("External custodian", CustodyProviderFormat.kindLabel(ProviderKind.UNKNOWN))
    }

    @Test
    fun kindFrom_andIsExternal() {
        assertEquals(ProviderKind.FIREBLOCKS, ProviderKind.from("Fireblocks"))
        assertTrue(CustodyProviderFormat.isExternal(ProviderKind.FIREBLOCKS))
        assertTrue(CustodyProviderFormat.isExternal(ProviderKind.BITGO))
        assertFalse(CustodyProviderFormat.isExternal(ProviderKind.INTERNAL))
        assertFalse(CustodyProviderFormat.isExternal(ProviderKind.UNKNOWN))
    }

    // ---- attestation ----

    @Test
    fun attestationLabel_andSeverity() {
        assertEquals("Balances attested", CustodyProviderFormat.attestationLabel(true))
        assertEquals("Not attested", CustodyProviderFormat.attestationLabel(false))
        assertEquals("Attestation unknown", CustodyProviderFormat.attestationLabel(null))
        assertEquals(Severity.GOOD, CustodyProviderFormat.attestationSeverity(true))
        assertEquals(Severity.WARN, CustodyProviderFormat.attestationSeverity(false))
        assertEquals(Severity.NEUTRAL, CustodyProviderFormat.attestationSeverity(null))
    }

    // ---- approval stepper ----

    @Test
    fun approvalFrom_isCaseInsensitive_andDefaults() {
        assertEquals(ApprovalStatus.SIGNED, ApprovalStatus.from("SIGNED"))
        assertEquals(ApprovalStatus.PENDING_APPROVAL, ApprovalStatus.from("pending_approval"))
        assertEquals(ApprovalStatus.UNKNOWN, ApprovalStatus.from("nope"))
    }

    @Test
    fun stepper_pendingApproval_firstIsCurrent_restUpcoming() {
        val steps = CustodyProviderFormat.stepper(ApprovalStatus.PENDING_APPROVAL)
        assertEquals(4, steps.size)
        assertEquals(StepState.CURRENT, steps[0].state)
        assertEquals(StepState.UPCOMING, steps[1].state)
        assertEquals(StepState.UPCOMING, steps[3].state)
        assertEquals(ApprovalStatus.PENDING_APPROVAL, steps[0].status)
        assertEquals("Broadcast", steps[3].label)
    }

    @Test
    fun stepper_signed_marksEarlierDone_currentSigned_broadcastUpcoming() {
        val steps = CustodyProviderFormat.stepper(ApprovalStatus.SIGNED)
        assertEquals(StepState.DONE, steps[0].state)
        assertEquals(StepState.DONE, steps[1].state)
        assertEquals(StepState.CURRENT, steps[2].state)
        assertEquals(StepState.UPCOMING, steps[3].state)
    }

    @Test
    fun stepper_broadcast_allDone() {
        val steps = CustodyProviderFormat.stepper(ApprovalStatus.BROADCAST)
        assertTrue(steps.dropLast(1).all { it.state == StepState.DONE })
        assertEquals(StepState.CURRENT, steps.last().state)
    }

    @Test
    fun stepper_rejected_marksAllRejected() {
        val steps = CustodyProviderFormat.stepper(ApprovalStatus.REJECTED)
        assertEquals(4, steps.size)
        assertTrue(steps.all { it.state == StepState.REJECTED })
    }

    @Test
    fun stepper_unknown_allUpcoming() {
        val steps = CustodyProviderFormat.stepper(ApprovalStatus.UNKNOWN)
        assertTrue(steps.all { it.state == StepState.UPCOMING })
    }

    @Test
    fun stepper_fromWireString_resolves() {
        val steps = CustodyProviderFormat.stepper("approved")
        assertEquals(StepState.DONE, steps[0].state)
        assertEquals(StepState.CURRENT, steps[1].state)
    }

    @Test
    fun isTerminal_onlyBroadcastAndRejected() {
        assertTrue(CustodyProviderFormat.isTerminal(ApprovalStatus.BROADCAST))
        assertTrue(CustodyProviderFormat.isTerminal(ApprovalStatus.REJECTED))
        assertFalse(CustodyProviderFormat.isTerminal(ApprovalStatus.PENDING_APPROVAL))
        assertFalse(CustodyProviderFormat.isTerminal(ApprovalStatus.SIGNED))
    }

    @Test
    fun quorumLabel_formatsAndClampsNegatives() {
        assertEquals("2 of 3", CustodyProviderFormat.quorumLabel(2, 3))
        assertEquals("0 of 0", CustodyProviderFormat.quorumLabel(-1, -5))
        assertEquals("0 of 2", CustodyProviderFormat.quorumLabel(0, 2))
    }
}
