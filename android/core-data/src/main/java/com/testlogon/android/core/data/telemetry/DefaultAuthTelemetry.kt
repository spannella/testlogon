package com.testlogon.android.core.data.telemetry

import android.util.Log

/** Sink for the redacted Logcat line. Injectable so JVM unit tests avoid the Android `Log` class. */
fun interface TelemetryLogSink {
    fun println(priority: Int, tag: String, message: String)
}

/**
 * AND-052 — default [AuthTelemetry]: redacts each event into a structured line, appends it to a
 * bounded in-memory ring buffer, and (in debug builds only) writes it to Logcat.
 *
 * Self-isolating: [log] wraps everything in `runCatching`, so a telemetry failure can never
 * propagate into or alter the auth flow.
 *
 * @param debug whether Logcat output is enabled (wired to `BuildConfig.DEBUG` by the Hilt module).
 * @param clock monotonic time source.
 * @param logSink seam for the Logcat write (default = [Log.println]); overridden in unit tests.
 */
class DefaultAuthTelemetry(
    private val redactor: Redactor,
    private val debug: Boolean,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val logSink: TelemetryLogSink = TelemetryLogSink(Log::println),
) : AuthTelemetry {

    private val ring = ArrayDeque<TelemetryRecord>(RING_CAPACITY)
    private val lock = Any()

    override fun log(event: AuthEvent) {
        runCatching {
            val record = event.toRecord(clock(), redactor)
            synchronized(lock) {
                if (ring.size >= RING_CAPACITY) ring.removeFirst()
                ring.addLast(record)
            }
            if (debug) logSink.println(record.priority(), TAG, record.line)
            // Remote sink seam: no-op in M1 (see RemoteTelemetrySink).
        }.onFailure {
            if (debug) runCatching { logSink.println(Log.DEBUG, TAG, "telemetry self-error") }
        }
    }

    override fun snapshot(): List<TelemetryRecord> = synchronized(lock) { ring.toList() }

    companion object {
        const val RING_CAPACITY = 200
        const val TAG = "AuthTelemetry"
    }
}

/** Logcat priority for a record: ATTEMPT/SUCCESS=INFO, FAILURE=WARN, server/parse errors=ERROR. */
private fun TelemetryRecord.priority(): Int = when {
    reason == AuthFailureReason.SERVER_5XX || reason == AuthFailureReason.MALFORMED_RESPONSE -> Log.ERROR
    outcome == AuthOutcome.FAILURE -> Log.WARN
    else -> Log.INFO
}

/** Build a fully-redacted [TelemetryRecord] from a coarse [AuthEvent]. */
internal fun AuthEvent.toRecord(now: Long, redactor: Redactor): TelemetryRecord {
    val reason: AuthFailureReason? = when (this) {
        is AuthEvent.LoginFailure -> reason
        is AuthEvent.MfaFailure -> reason
        is AuthEvent.FinalizeResult -> reason
        else -> null
    }
    val attrs: List<Pair<String, String?>> = buildList {
        add("stage" to stage.name)
        add("outcome" to outcome.name)
        when (val e = this@toRecord) {
            is AuthEvent.LoginAttempt -> add("userPresent" to e.userPresent.toString())
            is AuthEvent.LoginSuccess ->
                add("factors" to e.requiredFactors.joinToString(",") { it.name })
            is AuthEvent.LoginFailure -> {
                add("reason" to e.reason.name)
                add("http" to e.httpStatus?.toString())
            }
            is AuthEvent.MfaBegin -> {
                add("factor" to e.factor.name)
                add("cref" to redactor.shortHash(e.challengeId))
            }
            is AuthEvent.MfaVerifyAttempt -> {
                add("factor" to e.factor.name)
                add("cref" to redactor.shortHash(e.challengeId))
            }
            is AuthEvent.MfaSuccess -> {
                add("factor" to e.factor.name)
                add("cref" to redactor.shortHash(e.challengeId))
            }
            is AuthEvent.MfaFailure -> {
                add("factor" to e.factor.name)
                add("reason" to e.reason.name)
                add("remaining" to e.remainingFactors.toString())
                add("http" to e.httpStatus?.toString())
            }
            is AuthEvent.FinalizeResult -> add("reason" to e.reason?.name)
            is AuthEvent.RefreshResult -> Unit
            is AuthEvent.LogoutResult -> Unit
        }
        elapsedMs?.let { add("t" to "${it}ms") }
    }
    return TelemetryRecord(
        tMillis = now,
        stage = stage,
        outcome = outcome,
        reason = reason,
        line = redactor.line(attrs),
    )
}
