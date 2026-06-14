package com.testlogon.android.feature.player

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-170 / AND-172 — pure JVM tests for the watermark policy truth table, spec builder identity
 * precedence + timestamp token, and the anti-static-crop motion scheduler. No Compose / Android.
 */
class WatermarkLogicTest {

    private val now = 0L // epoch -> 00:00 UTC
    private val identity = UserIdentity(userSub = "usr_42")

    // TC-AND-170-01 — policy truth table.
    @Test
    fun evaluate_truthTable() {
        // Null item -> NotRequired.
        assertEquals(WatermarkUiState.NotRequired, WatermarkPolicy.evaluate(null, identity, now))
        // Not protected -> NotRequired.
        assertEquals(
            WatermarkUiState.NotRequired,
            WatermarkPolicy.evaluate(PlayableItem("m", requiresWatermark = false), identity, now),
        )
        // Protected + no identity -> PendingIdentity (gate).
        assertEquals(
            WatermarkUiState.PendingIdentity,
            WatermarkPolicy.evaluate(PlayableItem("m", requiresWatermark = true), null, now),
        )
        // Protected + identity -> Required.
        val result = WatermarkPolicy.evaluate(PlayableItem("m", requiresWatermark = true), identity, now)
        assertTrue(result is WatermarkUiState.Required)
    }

    // TC-AND-170-02 — buildSpec identity precedence (email -> username -> displayName -> userSub).
    @Test
    fun buildSpec_identityPrecedence() {
        assertEquals(
            "a@b.com",
            WatermarkPolicy.buildSpec(UserIdentity("usr_1", email = "a@b.com", username = "u"), now).primaryLine,
        )
        assertEquals(
            "uname",
            WatermarkPolicy.buildSpec(UserIdentity("usr_1", username = "uname", displayName = "Disp"), now).primaryLine,
        )
        assertEquals(
            "Disp",
            WatermarkPolicy.buildSpec(UserIdentity("usr_1", displayName = "Disp"), now).primaryLine,
        )
        assertEquals(
            "usr_1",
            WatermarkPolicy.buildSpec(UserIdentity("usr_1"), now).primaryLine,
        )
    }

    @Test
    fun buildSpec_secondaryCarriesUserSubAndHhMm() {
        val spec = WatermarkPolicy.buildSpec(identity, now)
        assertTrue(spec.secondaryLine.contains("id:usr_42"))
        assertTrue(spec.secondaryLine.contains("00:00"))
    }

    @Test
    fun formatHhMm_pure() {
        assertEquals("00:00", WatermarkPolicy.formatHhMm(0L, 0))
        assertEquals("01:30", WatermarkPolicy.formatHhMm(90L * 60_000L, 0))
        // Zone offset +60 min.
        assertEquals("01:00", WatermarkPolicy.formatHhMm(0L, 60))
        // Wrap across midnight with negative offset.
        assertEquals("23:00", WatermarkPolicy.formatHhMm(0L, -60))
        // Negative epoch clamps to 0.
        assertEquals("00:00", WatermarkPolicy.formatHhMm(-5_000L, 0))
    }

    // TC-AND-170-08 — motion across >= 3x3 grid; covers distinct cells over time.
    @Test
    fun motion_cyclesAcrossGrid() {
        val spec = WatermarkSpec(primaryLine = "p", secondaryLine = "s") // 3x3, 7s dwell
        val cells = mutableSetOf<Int>()
        for (i in 0 until 9) {
            cells += WatermarkMotion.cellIndex(spec, i * spec.cycleMillis)
        }
        // 9 distinct cells over 9 dwells.
        assertEquals(9, cells.size)
        // Wraps after the full grid.
        assertEquals(
            WatermarkMotion.cellIndex(spec, 0L),
            WatermarkMotion.cellIndex(spec, 9 * spec.cycleMillis),
        )
    }

    @Test
    fun motion_anchorFractionWithinGrid() {
        val spec = WatermarkSpec(primaryLine = "p", secondaryLine = "s")
        // index 0 -> top-left cell center (1/6, 1/6).
        val (x0, y0) = WatermarkMotion.anchorFraction(spec, 0)
        assertEquals(1f / 6f, x0, 1e-4f)
        assertEquals(1f / 6f, y0, 1e-4f)
        // index 4 -> center cell (3/6, 3/6).
        val (x4, y4) = WatermarkMotion.anchorFraction(spec, 4)
        assertEquals(0.5f, x4, 1e-4f)
        assertEquals(0.5f, y4, 1e-4f)
        // Successive indices differ.
        assertNotEquals(x0, x4)
    }
}
