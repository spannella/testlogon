package com.testlogon.android.feature.call.billing

import org.junit.Assert.assertEquals
import org.junit.Test

/** AND-301 — pure JVM tests for [BillingCalculator] (ceil-per-minute estimate + locale-agnostic USD). */
class BillingCalculatorTest {

    @Test
    fun estimate_0s_isZero() {
        assertEquals(0, BillingCalculator.estimateCents(0L, 5))
    }

    @Test
    fun estimate_1s_chargesFirstMinute() {
        assertEquals(5, BillingCalculator.estimateCents(1L, 5))
    }

    @Test
    fun estimate_59s_chargesFirstMinute() {
        assertEquals(5, BillingCalculator.estimateCents(59L, 5))
    }

    @Test
    fun estimate_60s_chargesFirstMinute() {
        assertEquals(5, BillingCalculator.estimateCents(60L, 5))
    }

    @Test
    fun estimate_61s_chargesSecondMinute() {
        assertEquals(10, BillingCalculator.estimateCents(61L, 5))
    }

    @Test
    fun estimate_120s_chargesTwoMinutes() {
        assertEquals(10, BillingCalculator.estimateCents(120L, 5))
    }

    @Test
    fun estimate_freeCall_rateZero_isZero() {
        assertEquals(0, BillingCalculator.estimateCents(120L, 0))
    }

    @Test
    fun estimate_negativeRate_isZero() {
        assertEquals(0, BillingCalculator.estimateCents(120L, -5))
    }

    @Test
    fun format_5cents() {
        assertEquals("\$0.05", BillingCalculator.formatCents(5))
    }

    @Test
    fun format_120cents() {
        assertEquals("\$1.20", BillingCalculator.formatCents(120))
    }

    @Test
    fun format_0cents() {
        assertEquals("\$0.00", BillingCalculator.formatCents(0))
    }

    @Test
    fun format_negative_clampsToZero() {
        assertEquals("\$0.00", BillingCalculator.formatCents(-5))
    }
}
