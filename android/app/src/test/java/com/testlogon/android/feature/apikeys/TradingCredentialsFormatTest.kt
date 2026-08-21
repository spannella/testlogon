package com.testlogon.android.feature.apikeys

import com.testlogon.android.feature.apikeys.data.Protocol
import com.testlogon.android.feature.apikeys.data.TradingCredentialsFormat
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM unit tests for [TradingCredentialsFormat] — the PURE multi-protocol trading/custody credential helpers
 * (mirrored from the web `tradingCredentials.test.ts`). Covers protocol/scope requirements + validation,
 * the QuickFIX .cfg builder, filename sanitisation, WS subscribe payloads/channels, and wire parsing.
 */
class TradingCredentialsFormatTest {

    @Test
    fun `rest requires no scopes`() {
        assertTrue(TradingCredentialsFormat.protocolRequiresScopes(Protocol.REST).isEmpty())
    }

    @Test
    fun `fix and binary require trading-or-custody scopes`() {
        val fix = TradingCredentialsFormat.protocolRequiresScopes(Protocol.FIX)
        val binary = TradingCredentialsFormat.protocolRequiresScopes(Protocol.BINARY)
        assertTrue(fix.contains("trading:orders"))
        assertTrue(fix.contains("custody:withdraw"))
        assertFalse(fix.contains("marketdata:read"))
        assertEquals(fix, binary)
    }

    @Test
    fun `ws requires trading custody or marketdata scopes`() {
        val ws = TradingCredentialsFormat.protocolRequiresScopes(Protocol.WS)
        assertTrue(ws.contains("marketdata:stream"))
        assertTrue(ws.contains("trading:read"))
        assertTrue(ws.contains("custody:read"))
    }

    @Test
    fun `validate flags fix and binary when no trading-or-custody scope selected`() {
        val errors = TradingCredentialsFormat.validateProtocolScopes(
            protocols = listOf(Protocol.FIX, Protocol.BINARY),
            scopes = listOf("marketdata:read"),
        )
        assertEquals(2, errors.size)
        assertEquals(setOf(Protocol.FIX, Protocol.BINARY), errors.map { it.protocol }.toSet())
    }

    @Test
    fun `validate passes fix when a custody scope is present`() {
        val errors = TradingCredentialsFormat.validateProtocolScopes(
            protocols = listOf(Protocol.FIX),
            scopes = listOf("custody:transfer"),
        )
        assertTrue(errors.isEmpty())
    }

    @Test
    fun `validate flags ws only when no trading custody or marketdata scope`() {
        val bad = TradingCredentialsFormat.validateProtocolScopes(
            protocols = listOf(Protocol.WS),
            scopes = listOf("newsfeed:read"),
        )
        assertEquals(1, bad.size)
        assertEquals(Protocol.WS, bad.first().protocol)

        val good = TradingCredentialsFormat.validateProtocolScopes(
            protocols = listOf(Protocol.WS),
            scopes = listOf("marketdata:stream"),
        )
        assertTrue(good.isEmpty())
    }

    @Test
    fun `validate never flags rest`() {
        val errors = TradingCredentialsFormat.validateProtocolScopes(
            protocols = listOf(Protocol.REST),
            scopes = emptyList(),
        )
        assertTrue(errors.isEmpty())
    }

    @Test
    fun `buildFixSessionConfig emits session block with supplied params`() {
        val cfg = TradingCredentialsFormat.buildFixSessionConfig(
            TradingCredentialsFormat.FixSessionParams(
                senderCompId = "CLIENT1",
                targetCompId = "EXCH",
                host = "fix.example.com",
                port = "9880",
                username = "u1",
                password = "p1",
                msgTypes = listOf("D", "F", "CU"),
            ),
        )
        assertTrue(cfg.contains("ConnectionType=initiator"))
        assertTrue(cfg.contains("BeginString=FIX.4.4"))
        assertTrue(cfg.contains("SenderCompID=CLIENT1"))
        assertTrue(cfg.contains("TargetCompID=EXCH"))
        assertTrue(cfg.contains("SocketConnectHost=fix.example.com"))
        assertTrue(cfg.contains("SocketConnectPort=9880"))
        assertTrue(cfg.contains("Username=u1"))
        assertTrue(cfg.contains("Password=p1"))
        assertTrue(cfg.contains("# Permitted MsgTypes: D, F, CU"))
    }

    @Test
    fun `buildFixSessionConfig omits password and msgtypes when absent`() {
        val cfg = TradingCredentialsFormat.buildFixSessionConfig(
            TradingCredentialsFormat.FixSessionParams(
                senderCompId = "S",
                targetCompId = "T",
                host = "h",
                port = "1",
            ),
        )
        assertFalse(cfg.contains("Password="))
        assertFalse(cfg.contains("Username="))
        assertFalse(cfg.contains("Permitted MsgTypes"))
    }

    @Test
    fun `fixConfigFilename sanitises and defaults`() {
        assertEquals("fix-CLIENT_1.cfg", TradingCredentialsFormat.fixConfigFilename("CLIENT 1"))
        assertEquals("fix-session.cfg", TradingCredentialsFormat.fixConfigFilename(""))
    }

    @Test
    fun `wsSubscribePayload builds compact json`() {
        assertEquals("{\"sub\":\"events\"}", TradingCredentialsFormat.wsSubscribePayload("events"))
        assertEquals("{\"sub\":\"custody\"}", TradingCredentialsFormat.wsSubscribePayload("custody"))
    }

    @Test
    fun `wsSubscribeChannels defaults to events and custody`() {
        assertEquals(listOf("events", "custody"), TradingCredentialsFormat.wsSubscribeChannels(null))
        assertEquals(listOf("events", "custody"), TradingCredentialsFormat.wsSubscribeChannels(emptyList()))
        assertEquals(listOf("orders"), TradingCredentialsFormat.wsSubscribeChannels(listOf("orders")))
    }

    @Test
    fun `protocol fromWire parses case-insensitively and rejects unknown`() {
        assertEquals(Protocol.FIX, Protocol.fromWire("fix"))
        assertEquals(Protocol.BINARY, Protocol.fromWire("BINARY"))
        assertNull(Protocol.fromWire("carrier-pigeon"))
        assertNull(Protocol.fromWire(null))
    }

    @Test
    fun `protocolLabel maps ws to WebSocket`() {
        assertEquals("WebSocket", TradingCredentialsFormat.protocolLabel(Protocol.WS))
        assertEquals("REST", TradingCredentialsFormat.protocolLabel(Protocol.REST))
    }
}
