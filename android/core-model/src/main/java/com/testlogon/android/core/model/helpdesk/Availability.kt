package com.testlogon.android.core.model.helpdesk

/**
 * AND-379 — agent availability ("online state") domain model.
 *
 * An agent is either [ONLINE] (a.k.a. Available, eligible to claim helpdesk work) or [AWAY]
 * (ineligible). This is a device-local agent preference, NOT cached server data; the value is carried
 * to the backend via the presence heartbeat `status` field (AND-145) and gates the on-device claim
 * flow. Pure (no android.* / network types) so it lives in core-model and is JVM-unit-testable.
 */
enum class Availability { ONLINE, AWAY }

/**
 * AND-379 — the wire `status` token sent on the presence heartbeat (`PresenceHeartbeatIn.status`).
 * Vocabulary committed by AND-379: ONLINE -> "available", AWAY -> "away" (exact lowercase strings).
 */
fun Availability.heartbeatStatus(): String = when (this) {
    Availability.ONLINE -> "available"
    Availability.AWAY -> "away"
}

/**
 * AND-379 — diagnostic snapshot of availability state. Persisted value is the [availability] enum only;
 * [lastChangedAt] (epoch millis) and [pushPending] are in-memory telemetry/diagnostics aids.
 */
data class AgentAvailabilityState(
    val availability: Availability = Availability.AWAY,
    val lastChangedAt: Long = 0L,
    val pushPending: Boolean = false,
)
