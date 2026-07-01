package com.testlogon.android.feature.vnc

import java.net.URI

/**
 * Decides whether the session's ws_url is even worth attempting from a mobile device, so the UI can
 * show the live WebView viewer vs the honest connection-details fallback.
 *
 * The broker (app/services/vnc_sessions.py) returns, for its registered targets, host-local or
 * private endpoints (e.g. ws://localhost:6080/websockify for `demo`, wss://ops-admin.example.internal/
 * websockify for `ops-admin`) unless VNC_*_WS_URL env overrides point at a PUBLIC websockify gateway.
 * A loopback / *.local / *.internal / link-local host can never be reached from the phone, so we don't
 * pretend — we skip the viewer and explain what infra is needed. Anything else is attempted for real
 * (the RFB lifecycle then reports the true outcome).
 */
object VncReachability {

    private val UNREACHABLE_HOSTS = setOf("localhost", "127.0.0.1", "::1", "0.0.0.0")

    data class Verdict(val reachable: Boolean, val reason: String?)

    fun assess(wsUrl: String): Verdict {
        val host = hostOf(wsUrl)?.lowercase()
            ?: return Verdict(false, "The bridge URL is malformed.")

        if (host in UNREACHABLE_HOSTS) {
            return Verdict(
                false,
                "The bridge listens on $host (the server's own loopback), which is not reachable " +
                    "from this device. A public websockify/VNC gateway must be deployed.",
            )
        }
        if (host.endsWith(".internal") || host.endsWith(".local") || host.endsWith(".localdomain")) {
            return Verdict(
                false,
                "The bridge host \"$host\" is a private/internal name that does not resolve from this " +
                    "device. A publicly reachable websockify gateway (DNS + open port) is required.",
            )
        }
        if (isPrivateIpv4(host)) {
            return Verdict(
                false,
                "The bridge host $host is a private LAN address, unreachable unless this device is on " +
                    "the same network.",
            )
        }
        return Verdict(true, null)
    }

    fun hostOf(wsUrl: String): String? = try {
        val u = URI(wsUrl.trim())
        u.host ?: httpFallbackHost(wsUrl)
    } catch (e: Exception) {
        httpFallbackHost(wsUrl)
    }

    private fun httpFallbackHost(wsUrl: String): String? {
        // ws://host:port/path  ->  host
        val noScheme = wsUrl.substringAfter("://", "")
        if (noScheme.isEmpty()) return null
        return noScheme.substringBefore("/").substringBefore(":").ifBlank { null }
    }

    private fun isPrivateIpv4(host: String): Boolean {
        val parts = host.split(".")
        if (parts.size != 4 || parts.any { it.toIntOrNull() == null }) return false
        val a = parts[0].toInt(); val b = parts[1].toInt()
        return a == 10 ||
            (a == 172 && b in 16..31) ||
            (a == 192 && b == 168) ||
            (a == 169 && b == 254)
    }
}
