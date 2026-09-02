package com.testlogon.android.feature.rdp

import com.testlogon.android.data.rdp.RdpFallbackDto

/**
 * PURE (no Android / Moshi / coroutine types) derivation of the RDP fallback connection-info VIEW, so
 * the UI + JVM tests can share one source of truth. RDP on mobile is a connection-info surface only:
 * there is NO interactive rendering (Phase-1 native RDP is deferred behind a server gate). This decides
 * how to display the copy-ready address and native-client hint.
 */
object RdpFallbackMath {

    /** A normalized, copy-ready `host:port` string. Prefers the server `address`; else composes it. */
    fun connectionAddress(f: RdpFallbackDto): String {
        val fromServer = f.address.trim()
        if (fromServer.isNotEmpty()) return fromServer
        val host = f.hostname.trim()
        if (host.isEmpty()) return ""
        val port = if (f.port in 1..65535) f.port else 3389
        return "$host:$port"
    }

    /** A stable human title for the card. */
    fun displayLabel(f: RdpFallbackDto): String =
        f.label.trim().ifEmpty { f.hostname.trim().ifEmpty { f.hostId.trim().ifEmpty { "RDP host" } } }

    /** Only offer the details when the server says the host is available AND we have somewhere to point. */
    fun isConnectable(f: RdpFallbackDto): Boolean =
        f.available && connectionAddress(f).isNotEmpty()

    /** Native-client hint line; falls back to a sensible default when the server sends none. */
    fun nativeClientsHint(f: RdpFallbackDto): String {
        val clients = f.nativeClients.map { it.trim() }.filter { it.isNotEmpty() }
        return if (clients.isEmpty()) {
            "Use a native RDP client (e.g. Microsoft Remote Desktop)."
        } else {
            "Open in: " + clients.joinToString(", ")
        }
    }
}
