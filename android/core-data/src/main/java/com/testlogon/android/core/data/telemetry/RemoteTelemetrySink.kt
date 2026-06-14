package com.testlogon.android.core.data.telemetry

/**
 * AND-052 — seam for shipping telemetry to a remote sink. Inert in M1; a real implementation can be
 * swapped in later with no call-site changes. [DefaultAuthTelemetry] is the only caller.
 */
fun interface RemoteTelemetrySink {
    fun send(record: TelemetryRecord)
}

/** Default no-op remote sink (M1). */
object NoopRemoteTelemetrySink : RemoteTelemetrySink {
    override fun send(record: TelemetryRecord) = Unit
}
