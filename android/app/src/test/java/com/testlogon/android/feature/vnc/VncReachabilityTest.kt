package com.testlogon.android.feature.vnc

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM unit tests for the PURE [VncReachability] logic that decides whether a brokered ws_url is worth
 * attempting a live viewer against (vs an honest connection-details fallback). Covers host extraction
 * (URI + scheme-fallback), loopback / internal / private-LAN unreachability, and public-host reachability.
 */
class VncReachabilityTest {

    @Test
    fun loopbackHosts_areUnreachableWithReason() {
        for (h in listOf("localhost", "127.0.0.1", "0.0.0.0")) {
            val v = VncReachability.assess("ws://$h:6080/websockify")
            assertFalse("expected $h unreachable", v.reachable)
            assertNotNull(v.reason)
        }
    }

    @Test
    fun internalAndLocalNames_areUnreachable() {
        assertFalse(VncReachability.assess("wss://ops-admin.example.internal/websockify").reachable)
        assertFalse(VncReachability.assess("ws://box.local:6080/ws").reachable)
        assertFalse(VncReachability.assess("ws://box.localdomain/ws").reachable)
    }

    @Test
    fun privateLanIpv4_isUnreachable() {
        assertFalse(VncReachability.assess("ws://10.0.0.5:6080/ws").reachable)
        assertFalse(VncReachability.assess("ws://172.16.4.9:6080/ws").reachable)
        assertFalse(VncReachability.assess("ws://192.168.1.20:6080/ws").reachable)
        assertFalse(VncReachability.assess("ws://169.254.1.1:6080/ws").reachable)
    }

    @Test
    fun publicIpv4_andPublicHost_areReachable() {
        val ipv4 = VncReachability.assess("wss://8.8.8.8:443/websockify")
        assertTrue(ipv4.reachable)
        assertNull(ipv4.reason)
        assertTrue(VncReachability.assess("wss://vnc.gateway.example.com/websockify").reachable)
    }

    @Test
    fun nonPrivate172Range_isReachable() {
        // 172.15 and 172.32 are OUTSIDE the private 172.16-172.31 block.
        assertTrue(VncReachability.assess("ws://172.15.0.1:6080/ws").reachable)
        assertTrue(VncReachability.assess("ws://172.32.0.1:6080/ws").reachable)
    }

    @Test
    fun malformedUrl_isUnreachable() {
        val v = VncReachability.assess("not a url")
        assertFalse(v.reachable)
        assertNotNull(v.reason)
    }

    @Test
    fun hostOf_extractsHostViaUriAndFallback() {
        assertEquals("example.com", VncReachability.hostOf("wss://example.com:443/websockify"))
        assertEquals("10.0.0.5", VncReachability.hostOf("ws://10.0.0.5:6080/ws"))
    }
}
