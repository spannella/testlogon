package com.testlogon.android.core.data.telemetry

/** A redacted, structured telemetry record held in the ring buffer / emitted to Logcat. */
data class TelemetryRecord(
    val tMillis: Long,
    val stage: AuthStage,
    val outcome: AuthOutcome,
    val reason: AuthFailureReason?,
    val line: String, // fully redacted, structured "k=v" line
)

/**
 * AND-052 — single entry point for emitting auth telemetry.
 *
 * Implementations MUST be non-blocking and MUST NEVER throw into the caller; a failure inside the
 * telemetry layer is swallowed. No secrets ever reach a sink (enforced by [Redactor]).
 */
interface AuthTelemetry {
    fun log(event: AuthEvent)

    /** Newest-last immutable copy of the in-memory ring buffer (debug triage / tests). */
    fun snapshot(): List<TelemetryRecord>
}

/** No-op telemetry — the safe default for tests and for ViewModel constructor defaults. */
object NoopAuthTelemetry : AuthTelemetry {
    override fun log(event: AuthEvent) = Unit
    override fun snapshot(): List<TelemetryRecord> = emptyList()
}
