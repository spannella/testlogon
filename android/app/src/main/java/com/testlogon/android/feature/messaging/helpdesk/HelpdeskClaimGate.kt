package com.testlogon.android.feature.messaging.helpdesk

import com.testlogon.android.core.model.helpdesk.Availability
import com.testlogon.android.data.messaging.helpdesk.availability.AvailabilityRepository
import javax.inject.Inject

/**
 * AND-379 — result of the on-device claim-eligibility check.
 *
 * The gate is a UX/affordance control only — the backend remains authoritative on who may claim
 * (§8). It prevents a claim attempt that raced the toggle from hitting the network while the agent is
 * Away.
 */
sealed interface ClaimGateResult {
    /** Agent is ONLINE; the claim may proceed. */
    data object Allowed : ClaimGateResult

    /** Agent is AWAY; the claim is short-circuited with a "go Online" message and no network call. */
    data object BlockedAway : ClaimGateResult
}

/**
 * AND-379 — gates the helpdesk claim flow on the agent's current availability. Reads the same
 * [AvailabilityRepository] single source of truth as the toggle UI and the heartbeat (AC-4), so an
 * Away agent can never reach the claim network call (AC-1).
 */
class HelpdeskClaimGate @Inject constructor(
    private val availabilityRepository: AvailabilityRepository,
) {
    suspend fun check(): ClaimGateResult =
        if (availabilityRepository.current() == Availability.ONLINE) {
            ClaimGateResult.Allowed
        } else {
            ClaimGateResult.BlockedAway
        }
}
