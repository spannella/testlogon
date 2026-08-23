package com.testlogon.android.data.exchange.alerts

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit coverage for the pure [PriceAlertEval.evaluate] edge-trigger logic: arm/fire, one-shot latch,
 * re-arm, both directions, first-observation (no prior price never fires), and the disarmed/triggered
 * short-circuits.
 */
class PriceAlertEvalTest {

    private val NOW = 5_000L

    private fun alert(
        dir: PriceAlertDirection = PriceAlertDirection.ABOVE,
        ticks: Long = 100,
        armed: Boolean = true,
        triggeredTs: Long? = null,
    ) = PriceAlert(
        id = "a1",
        symbolId = 1,
        direction = dir,
        priceTicks = ticks,
        note = null,
        createdTs = 0L,
        triggeredTs = triggeredTs,
        armed = armed,
    )

    // ---- first observation never fires (no edge) ----

    @Test
    fun firstObservation_neverFires_evenWhenAlreadyPastThreshold() {
        val r = PriceAlertEval.evaluate(alert(ticks = 100), prevTicks = null, lastTicks = 150, nowMs = NOW)
        assertFalse(r.fired)
        assertTrue(r.alert.armed)
        assertNull(r.alert.triggeredTs)
    }

    // ---- ABOVE ----

    @Test
    fun above_firesOnUpwardCross_andIsOneShot() {
        val r = PriceAlertEval.evaluate(alert(PriceAlertDirection.ABOVE, 100), prevTicks = 90, lastTicks = 110, nowMs = NOW)
        assertTrue(r.fired)
        assertFalse("must disarm on fire", r.alert.armed)
        assertEquals(NOW, r.alert.triggeredTs)

        // One-shot: re-evaluating the now-disarmed alert never fires again.
        val again = PriceAlertEval.evaluate(r.alert, prevTicks = 110, lastTicks = 130, nowMs = NOW + 1)
        assertFalse(again.fired)
    }

    @Test
    fun above_firesWhenPrevSitsExactlyOnThreshold() {
        // prev == threshold, last strictly above => crossing.
        val r = PriceAlertEval.evaluate(alert(PriceAlertDirection.ABOVE, 100), prevTicks = 100, lastTicks = 101, nowMs = NOW)
        assertTrue(r.fired)
    }

    @Test
    fun above_doesNotFireWhileStayingBelow() {
        val r = PriceAlertEval.evaluate(alert(PriceAlertDirection.ABOVE, 100), prevTicks = 80, lastTicks = 95, nowMs = NOW)
        assertFalse(r.fired)
        assertTrue(r.alert.armed)
    }

    @Test
    fun above_doesNotFireWhenAlreadyAboveAndStaysAbove() {
        // No crossing: both prev and last above threshold.
        val r = PriceAlertEval.evaluate(alert(PriceAlertDirection.ABOVE, 100), prevTicks = 120, lastTicks = 140, nowMs = NOW)
        assertFalse(r.fired)
    }

    // ---- BELOW ----

    @Test
    fun below_firesOnDownwardCross() {
        val r = PriceAlertEval.evaluate(alert(PriceAlertDirection.BELOW, 100), prevTicks = 110, lastTicks = 90, nowMs = NOW)
        assertTrue(r.fired)
        assertFalse(r.alert.armed)
        assertEquals(NOW, r.alert.triggeredTs)
    }

    @Test
    fun below_doesNotFireOnUpwardMove() {
        val r = PriceAlertEval.evaluate(alert(PriceAlertDirection.BELOW, 100), prevTicks = 90, lastTicks = 110, nowMs = NOW)
        assertFalse(r.fired)
    }

    // ---- disarmed / already triggered short-circuit ----

    @Test
    fun disarmedAlert_neverFires() {
        val r = PriceAlertEval.evaluate(alert(armed = false), prevTicks = 90, lastTicks = 110, nowMs = NOW)
        assertFalse(r.fired)
    }

    @Test
    fun alreadyTriggeredAlert_neverFires() {
        val r = PriceAlertEval.evaluate(alert(triggeredTs = 1L), prevTicks = 90, lastTicks = 110, nowMs = NOW)
        assertFalse(r.fired)
    }

    // ---- re-arm makes it eligible again ----

    @Test
    fun reArmedAlert_firesAgainOnNextCross() {
        val fired = PriceAlertEval.evaluate(alert(PriceAlertDirection.ABOVE, 100), prevTicks = 90, lastTicks = 110, nowMs = NOW)
        assertTrue(fired.fired)
        // Simulate the store re-arm: armed=true, triggeredTs=null.
        val rearmed = fired.alert.copy(armed = true, triggeredTs = null)
        val r2 = PriceAlertEval.evaluate(rearmed, prevTicks = 90, lastTicks = 110, nowMs = NOW + 100)
        assertTrue(r2.fired)
        assertEquals(NOW + 100, r2.alert.triggeredTs)
    }
}

/**
 * EXTENDED coverage for the generalized SYMBOL|TOKEN|STRATEGY alerts: the pure [alertCrossed] predicate
 * (both directions, edge cases), [alertLabel] rendering per kind, and the evaluator over token/strategy
 * subjects (default kind, subjectId defaulting from symbolId).
 */
class PriceAlertGeneralizedTest {

    private val NOW = 9_000L

    private fun tokenAlert(dir: PriceAlertDirection = PriceAlertDirection.ABOVE, cents: Long = 25000) =
        PriceAlert(
            id = "t1", symbolId = -1, direction = dir, priceTicks = cents, note = null,
            createdTs = 0L, subject = PriceAlertSubject.TOKEN, subjectId = "tok-abc", subjectLabel = "ACME",
        )

    // ---- alertCrossed pure predicate ----

    @Test
    fun crossed_above_true_onUpwardCross() {
        assertTrue(alertCrossed(90, 110, PriceAlertDirection.ABOVE, 100))
    }

    @Test
    fun crossed_above_true_whenPrevOnThreshold() {
        assertTrue(alertCrossed(100, 101, PriceAlertDirection.ABOVE, 100))
    }

    @Test
    fun crossed_above_false_whenStaysBelow() {
        assertFalse(alertCrossed(80, 95, PriceAlertDirection.ABOVE, 100))
    }

    @Test
    fun crossed_above_false_whenAlreadyAbove() {
        assertFalse(alertCrossed(120, 140, PriceAlertDirection.ABOVE, 100))
    }

    @Test
    fun crossed_below_true_onDownwardCross() {
        assertTrue(alertCrossed(110, 90, PriceAlertDirection.BELOW, 100))
    }

    @Test
    fun crossed_below_true_whenPrevOnThreshold() {
        assertTrue(alertCrossed(100, 99, PriceAlertDirection.BELOW, 100))
    }

    @Test
    fun crossed_below_false_onUpwardMove() {
        assertFalse(alertCrossed(90, 110, PriceAlertDirection.BELOW, 100))
    }

    @Test
    fun crossed_below_false_whenAlreadyBelow() {
        assertFalse(alertCrossed(80, 60, PriceAlertDirection.BELOW, 100))
    }

    // ---- default subject / migration defaults ----

    @Test
    fun defaultAlert_isSymbolKind_withSubjectIdFromSymbolId() {
        val a = PriceAlert(id = "a", symbolId = 42, direction = PriceAlertDirection.ABOVE, priceTicks = 1, createdTs = 0L)
        assertEquals(PriceAlertSubject.SYMBOL, a.subject)
        assertEquals("42", a.subjectId)
    }

    // ---- alertLabel per kind ----

    @Test
    fun label_symbol_hasNoKindTag() {
        val a = PriceAlert(id = "a", symbolId = 1, direction = PriceAlertDirection.ABOVE, priceTicks = 65000, createdTs = 0L, subjectLabel = "BTC")
        assertEquals("BTC above 65000", alertLabel(a))
    }

    @Test
    fun label_token_hasTokenTag_andUsesResolvedName() {
        val a = tokenAlert(PriceAlertDirection.BELOW, 25000)
        assertEquals("ACME token below 250", alertLabel(a, subjectName = "ACME", formatTarget = { (it / 100).toString() }))
    }

    @Test
    fun label_strategy_hasNavTag() {
        val a = PriceAlert(
            id = "s", symbolId = -1, direction = PriceAlertDirection.ABOVE, priceTicks = 10000, createdTs = 0L,
            subject = PriceAlertSubject.STRATEGY, subjectId = "str-1", subjectLabel = "Momentum",
        )
        assertEquals("Momentum NAV above 10000", alertLabel(a))
    }

    @Test
    fun label_fallsBackToHashId_whenNoName() {
        val a = PriceAlert(
            id = "s", symbolId = -1, direction = PriceAlertDirection.ABOVE, priceTicks = 1, createdTs = 0L,
            subject = PriceAlertSubject.TOKEN, subjectId = "xyz",
        )
        assertEquals("#xyz token above 1", alertLabel(a))
    }

    // ---- token subject evaluated by the same pure eval ----

    @Test
    fun tokenAlert_firesOnUpwardCrossViaEvaluate() {
        val r = PriceAlertEval.evaluate(tokenAlert(PriceAlertDirection.ABOVE, 25000), prevTicks = 24000, lastTicks = 26000, nowMs = NOW)
        assertTrue(r.fired)
        assertFalse(r.alert.armed)
        assertEquals(NOW, r.alert.triggeredTs)
        assertEquals(PriceAlertSubject.TOKEN, r.alert.subject)
    }
}
