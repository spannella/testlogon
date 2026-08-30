package com.testlogon.android.feature.call.domain

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** FE-143 — pure unit tests for the connection-state / ICE-restart / TURN-refresh math. */
class CallConnectionMathTest {

    // ── mapConnectionStatus ──────────────────────────────────────────────────────────────────────
    @Test fun `new maps to connecting`() =
        assertEquals(CallConnectionStatus.CONNECTING, CallConnectionMath.mapConnectionStatus("NEW"))

    @Test fun `checking maps to connecting`() =
        assertEquals(CallConnectionStatus.CONNECTING, CallConnectionMath.mapConnectionStatus("CHECKING"))

    @Test fun `connected maps to connected`() =
        assertEquals(CallConnectionStatus.CONNECTED, CallConnectionMath.mapConnectionStatus("CONNECTED"))

    @Test fun `completed maps to connected`() =
        assertEquals(CallConnectionStatus.CONNECTED, CallConnectionMath.mapConnectionStatus("COMPLETED"))

    @Test fun `disconnected maps to reconnecting`() =
        assertEquals(CallConnectionStatus.RECONNECTING, CallConnectionMath.mapConnectionStatus("DISCONNECTED"))

    @Test fun `failed maps to failed`() =
        assertEquals(CallConnectionStatus.FAILED, CallConnectionMath.mapConnectionStatus("FAILED"))

    @Test fun `closed maps to closed`() =
        assertEquals(CallConnectionStatus.CLOSED, CallConnectionMath.mapConnectionStatus("CLOSED"))

    @Test fun `lowercase and whitespace are normalised`() =
        assertEquals(CallConnectionStatus.CONNECTED, CallConnectionMath.mapConnectionStatus("  connected "))

    @Test fun `unknown or null falls back to connecting`() {
        assertEquals(CallConnectionStatus.CONNECTING, CallConnectionMath.mapConnectionStatus(null))
        assertEquals(CallConnectionStatus.CONNECTING, CallConnectionMath.mapConnectionStatus("WAT"))
    }

    // ── shouldIceRestart ─────────────────────────────────────────────────────────────────────────
    @Test fun `failed always restarts`() =
        assertTrue(CallConnectionMath.shouldIceRestart("FAILED", disconnectedForSec = 0))

    @Test fun `disconnected within grace does not restart`() =
        assertFalse(CallConnectionMath.shouldIceRestart("DISCONNECTED", disconnectedForSec = 1))

    @Test fun `disconnected past grace restarts`() =
        assertTrue(
            CallConnectionMath.shouldIceRestart(
                "DISCONNECTED",
                disconnectedForSec = CallConnectionMath.ICE_DISCONNECT_GRACE_SEC,
            ),
        )

    @Test fun `connected never restarts`() =
        assertFalse(CallConnectionMath.shouldIceRestart("CONNECTED", disconnectedForSec = 999))

    @Test fun `null never restarts`() =
        assertFalse(CallConnectionMath.shouldIceRestart(null))

    // ── isTurnExpired ────────────────────────────────────────────────────────────────────────────
    @Test fun `turn not expired before expiry`() =
        assertFalse(CallConnectionMath.isTurnExpired(expiresAtSec = 1000, nowSec = 999))

    @Test fun `turn expired at and after expiry`() {
        assertTrue(CallConnectionMath.isTurnExpired(expiresAtSec = 1000, nowSec = 1000))
        assertTrue(CallConnectionMath.isTurnExpired(expiresAtSec = 1000, nowSec = 1001))
    }

    // ── shouldRefreshTurn ────────────────────────────────────────────────────────────────────────
    @Test fun `refresh not due well before lead window`() =
        assertFalse(
            CallConnectionMath.shouldRefreshTurn(expiresAtSec = 1000, nowSec = 800, leadSec = 60),
        )

    @Test fun `refresh due once inside lead window`() =
        assertTrue(
            CallConnectionMath.shouldRefreshTurn(expiresAtSec = 1000, nowSec = 940, leadSec = 60),
        )

    @Test fun `refresh due when already expired`() =
        assertTrue(
            CallConnectionMath.shouldRefreshTurn(expiresAtSec = 1000, nowSec = 5000, leadSec = 60),
        )

    @Test fun `no expiry means never refresh`() {
        assertFalse(CallConnectionMath.shouldRefreshTurn(expiresAtSec = 0, nowSec = 5000))
        assertFalse(CallConnectionMath.shouldRefreshTurn(expiresAtSec = -1, nowSec = 5000))
    }

    @Test fun `default lead constant is used`() =
        assertTrue(
            CallConnectionMath.shouldRefreshTurn(
                expiresAtSec = 1000,
                nowSec = 1000 - CallConnectionMath.TURN_REFRESH_LEAD_SEC,
            ),
        )
}
