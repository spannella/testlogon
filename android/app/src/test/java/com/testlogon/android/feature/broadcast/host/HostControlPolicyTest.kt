package com.testlogon.android.feature.broadcast.host

import com.testlogon.android.data.broadcast.BroadcastSessionStatus
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * AND-309 — exhaustive table test for [HostControlPolicy] over EVERY [BroadcastSessionStatus] × every
 * action (start / stop / resume(resumable true & false) / reschedule). Locks the allowed matrix and gives
 * 100% branch coverage of the policy.
 */
class HostControlPolicyTest {

    /** start / reschedule are allowed exactly for SCHEDULED and READY. */
    private val startRescheduleAllowed = setOf(
        BroadcastSessionStatus.SCHEDULED,
        BroadcastSessionStatus.READY,
    )

    /** stop is allowed exactly for LIVE. */
    private val stopAllowed = setOf(BroadcastSessionStatus.LIVE)

    /** resume (when resumable) is allowed for the non-terminal post-provision states. */
    private val resumeResumableAllowed = setOf(
        BroadcastSessionStatus.LIVE,
        BroadcastSessionStatus.STOPPING,
        BroadcastSessionStatus.READY,
        BroadcastSessionStatus.PROVISIONING,
    )

    @Test
    fun canStart_matrix() {
        for (status in BroadcastSessionStatus.entries) {
            assertEquals(
                "canStart($status)",
                status in startRescheduleAllowed,
                HostControlPolicy.canStart(status),
            )
        }
    }

    @Test
    fun canReschedule_matrix() {
        for (status in BroadcastSessionStatus.entries) {
            assertEquals(
                "canReschedule($status)",
                status in startRescheduleAllowed,
                HostControlPolicy.canReschedule(status),
            )
        }
    }

    @Test
    fun canStop_matrix() {
        for (status in BroadcastSessionStatus.entries) {
            assertEquals(
                "canStop($status)",
                status in stopAllowed,
                HostControlPolicy.canStop(status),
            )
        }
    }

    @Test
    fun canResume_resumableTrue_matrix() {
        for (status in BroadcastSessionStatus.entries) {
            assertEquals(
                "canResume($status, resumable=true)",
                status in resumeResumableAllowed,
                HostControlPolicy.canResume(status, resumable = true),
            )
        }
    }

    @Test
    fun canResume_resumableFalse_neverAllowed() {
        for (status in BroadcastSessionStatus.entries) {
            assertEquals(
                "canResume($status, resumable=false)",
                false,
                HostControlPolicy.canResume(status, resumable = false),
            )
        }
    }
}
