package com.testlogon.android.feature.rdp

import com.testlogon.android.data.rdp.RdpFallbackDto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM unit tests for the PURE [RdpFallbackMath] connection-info derivation (no Android/Moshi behavior).
 * Covers server-address preference, host:port composition + port clamping, label fallbacks, the
 * connectable gate (must be available AND have an address), and the native-client hint.
 */
class RdpFallbackMathTest {

    private fun dto(
        available: Boolean = true,
        hostId: String = "host-1",
        label: String = "",
        hostname: String = "",
        port: Int = 3389,
        address: String = "",
        clients: List<String> = emptyList(),
    ) = RdpFallbackDto(
        available = available,
        hostId = hostId,
        label = label,
        hostname = hostname,
        port = port,
        username = "admin",
        address = address,
        instructions = "",
        nativeClients = clients,
    )

    @Test
    fun connectionAddress_prefersServerAddress() {
        assertEquals("win.example.com:3389", RdpFallbackMath.connectionAddress(dto(address = " win.example.com:3389 ")))
    }

    @Test
    fun connectionAddress_composesFromHostAndPort() {
        assertEquals("10.0.0.5:3389", RdpFallbackMath.connectionAddress(dto(hostname = "10.0.0.5", port = 3389)))
        assertEquals("win.local:3390", RdpFallbackMath.connectionAddress(dto(hostname = "win.local", port = 3390)))
    }

    @Test
    fun connectionAddress_clampsInvalidPortTo3389() {
        assertEquals("host:3389", RdpFallbackMath.connectionAddress(dto(hostname = "host", port = 0)))
        assertEquals("host:3389", RdpFallbackMath.connectionAddress(dto(hostname = "host", port = 99999)))
    }

    @Test
    fun connectionAddress_emptyWhenNoHost() {
        assertEquals("", RdpFallbackMath.connectionAddress(dto(hostname = "", address = "")))
    }

    @Test
    fun displayLabel_fallsBackThroughHostnameThenHostId() {
        assertEquals("Prod DC", RdpFallbackMath.displayLabel(dto(label = "Prod DC")))
        assertEquals("win.example.com", RdpFallbackMath.displayLabel(dto(label = "", hostname = "win.example.com")))
        assertEquals("host-1", RdpFallbackMath.displayLabel(dto(label = "", hostname = "", hostId = "host-1")))
        assertEquals("RDP host", RdpFallbackMath.displayLabel(dto(label = "", hostname = "", hostId = "")))
    }

    @Test
    fun isConnectable_requiresAvailableAndAddress() {
        assertTrue(RdpFallbackMath.isConnectable(dto(available = true, hostname = "h")))
        assertFalse(RdpFallbackMath.isConnectable(dto(available = false, hostname = "h")))
        assertFalse(RdpFallbackMath.isConnectable(dto(available = true, hostname = "", address = "")))
    }

    @Test
    fun nativeClientsHint_joinsOrDefaults() {
        assertEquals(
            "Open in: Microsoft Remote Desktop, FreeRDP",
            RdpFallbackMath.nativeClientsHint(dto(clients = listOf("Microsoft Remote Desktop", " FreeRDP "))),
        )
        assertTrue(RdpFallbackMath.nativeClientsHint(dto(clients = emptyList())).startsWith("Use a native RDP client"))
    }
}
